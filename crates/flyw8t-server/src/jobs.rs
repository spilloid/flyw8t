//! Job orchestration: creation, dispatch, device reports, cancellation and deadlines.
//!
//! Every state change goes through [`transition`], which locks the job row, checks the
//! domain transition table, writes the new state and appends a `job_events` row in the same
//! transaction. Nothing else writes `jobs.state`.

use crate::audit::Audit;
use crate::auth::Principal;
use crate::error::{AppError, AppResult};
use crate::Shared;
use flyw8t_domain::evidence;
use flyw8t_domain::job::{state_for_outcome, ExecState, Verification};
use flyw8t_domain::Permission;
use flyw8t_protocol::messages::{ExecOutcome, Finished, JobPhase, JobReport, NotAccepted};
use flyw8t_protocol::{Action, ServerMsg};
use serde_json::{json, Value};
use sqlx::{PgConnection, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

/// A job row as the orchestrator needs it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct JobCore {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub device_id: Uuid,
    pub request: Value,
    pub timeout_secs: i32,
    pub state: String,
    pub cancel_requested_at: Option<OffsetDateTime>,
}

impl JobCore {
    pub fn state(&self) -> ExecState {
        ExecState::parse(&self.state).unwrap_or(ExecState::OutcomeUnknown)
    }

    pub fn action(&self) -> anyhow::Result<Action> {
        Ok(serde_json::from_value(self.request.clone())?)
    }
}

const CORE: &str =
    "id, organization_id, device_id, request, timeout_secs, state, cancel_requested_at";

async fn lock(tx: &mut PgConnection, job_id: Uuid) -> sqlx::Result<Option<JobCore>> {
    sqlx::query_as(&format!("SELECT {CORE} FROM jobs WHERE id = $1 FOR UPDATE"))
        .bind(job_id)
        .fetch_optional(tx)
        .await
}

/// Columns a transition may set besides `state`.
#[derive(Default)]
struct Sets {
    verification: Option<Verification>,
    verification_note: Option<String>,
    state_note: Option<String>,
    finished: Option<Finished>,
    acknowledged: bool,
    started_at: Option<OffsetDateTime>,
}

/// Apply one legal transition to a locked row. Illegal transitions are bugs and refused.
async fn transition(
    tx: &mut PgConnection,
    job: &JobCore,
    to: ExecState,
    actor: &str,
    kind: &str,
    detail: Value,
    sets: Sets,
) -> anyhow::Result<()> {
    let from = job.state();
    anyhow::ensure!(
        from.can_transition_to(to),
        "illegal job transition {from:?} -> {to:?}"
    );
    let verification = sets.verification.or_else(|| {
        (to.is_terminal() && to != ExecState::Completed).then_some(Verification::NotApplicable)
    });
    let f = sets.finished.as_ref();
    let (exit_code, error) = match f.map(|f| &f.outcome) {
        Some(ExecOutcome::Exited { code }) => (Some(*code), None),
        Some(ExecOutcome::Failed { error }) => (None, Some(error.clone())),
        Some(ExecOutcome::NotStarted { reason }) => (None, Some(format!("Not executed: {reason}"))),
        Some(ExecOutcome::Interrupted { reason }) => (None, Some(reason.clone())),
        _ => (None, None),
    };
    sqlx::query(
        "UPDATE jobs SET
            state = $2,
            verification = coalesce($3, verification),
            verification_note = coalesce($4, verification_note),
            state_note = coalesce($5, state_note),
            queued_at = CASE WHEN $2 = 'queued' AND queued_at IS NULL THEN now() ELSE queued_at END,
            first_dispatched_at = CASE WHEN $2 = 'dispatched' THEN coalesce(first_dispatched_at, now()) ELSE first_dispatched_at END,
            dispatch_count = dispatch_count + CASE WHEN $2 = 'dispatched' THEN 1 ELSE 0 END,
            acknowledged_at = CASE WHEN $6 THEN coalesce(acknowledged_at, now()) ELSE acknowledged_at END,
            started_at = coalesce($7, started_at),
            finished_at = coalesce($8, finished_at),
            terminal_at = CASE WHEN $2 IN ('completed','failed','timed_out','cancelled','expired') THEN now() ELSE terminal_at END,
            exit_code = coalesce($9, exit_code),
            stdout = coalesce($10, stdout),
            stdout_truncated = coalesce($11, stdout_truncated),
            stderr = coalesce($12, stderr),
            stderr_truncated = coalesce($13, stderr_truncated),
            result = coalesce($14, result),
            error = coalesce($15, error)
         WHERE id = $1 AND state = $16",
    )
    .bind(job.id)
    .bind(to.as_str())
    .bind(verification.map(Verification::as_str))
    .bind(sets.verification_note)
    .bind(sets.state_note)
    .bind(sets.acknowledged)
    .bind(sets.started_at.or(f.and_then(|f| f.started_at)))
    .bind(f.map(|f| f.finished_at))
    .bind(exit_code)
    .bind(f.and_then(|f| f.stdout.as_ref()).map(|s| strip_nul(&s.data)))
    .bind(f.and_then(|f| f.stdout.as_ref()).map(|s| s.truncated))
    .bind(f.and_then(|f| f.stderr.as_ref()).map(|s| strip_nul(&s.data)))
    .bind(f.and_then(|f| f.stderr.as_ref()).map(|s| s.truncated))
    .bind(f.and_then(|f| f.structured.clone()))
    .bind(error)
    .bind(from.as_str())
    .execute(&mut *tx)
    .await?;
    event(tx, job.id, kind, Some(from), Some(to), actor, detail).await?;
    Ok(())
}

/// Postgres text cannot hold NUL; device output can.
fn strip_nul(s: &str) -> String {
    s.replace('\0', "\u{FFFD}")
}

async fn event(
    tx: &mut PgConnection,
    job_id: Uuid,
    kind: &str,
    from: Option<ExecState>,
    to: Option<ExecState>,
    actor: &str,
    detail: Value,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO job_events (job_id, kind, from_state, to_state, actor, detail) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(job_id)
        .bind(kind)
        .bind(from.map(ExecState::as_str))
        .bind(to.map(ExecState::as_str))
        .bind(actor)
        .bind(detail)
        .execute(tx)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Creation

pub struct NewJob {
    pub device_id: Uuid,
    pub action: Action,
    pub timeout_secs: Option<u32>,
    pub idempotency_key: Option<String>,
}

/// Authorize, record and queue a job, then dispatch it if the device is connected.
pub async fn create(state: &Shared, p: &Principal, req: NewJob) -> AppResult<Uuid> {
    // Scope first: a device outside the caller's organizations does not exist for them.
    let (all, orgs) = p.scope();
    let device: Option<(Uuid, Option<OffsetDateTime>, bool)> = sqlx::query_as(
        "SELECT d.organization_id, d.retired_at,
                EXISTS (SELECT 1 FROM device_credentials c WHERE c.device_id = d.id AND c.revoked_at IS NULL)
           FROM devices d WHERE d.id = $1 AND ($2 OR d.organization_id = ANY($3))",
    )
    .bind(req.device_id)
    .bind(all)
    .bind(&orgs)
    .fetch_optional(&state.db)
    .await?;
    let Some((org_id, retired_at, has_credential)) = device else {
        return Err(AppError::NotFound);
    };
    if !p.can(Permission::RunDiagnostics) {
        Audit::user(p, "job.create")
            .org(org_id)
            .target("device", req.device_id)
            .denied()
            .detail(json!({ "action": req.action.name(), "reason": "permission" }))
            .record(&state.db)
            .await?;
        return Err(AppError::Forbidden);
    }
    req.action
        .validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    if retired_at.is_some() || !has_credential {
        return Err(AppError::Conflict(
            "this device is retired or its credential is revoked".into(),
        ));
    }
    let info = req.action.info();
    let timeout = req.timeout_secs.unwrap_or(info.default_timeout_secs);
    if timeout == 0 || timeout > info.max_timeout_secs {
        return Err(AppError::BadRequest(format!(
            "timeout must be between 1 and {} seconds for {}",
            info.max_timeout_secs, info.name
        )));
    }

    if let Some(key) = &req.idempotency_key {
        if key.is_empty() || key.len() > 200 {
            return Err(AppError::BadRequest(
                "Idempotency-Key must be 1-200 characters".into(),
            ));
        }
        let existing: Option<(Uuid, Uuid, Value)> =
            sqlx::query_as("SELECT id, device_id, request FROM jobs WHERE requested_by = $1 AND idempotency_key = $2")
                .bind(p.user_id)
                .bind(key)
                .fetch_optional(&state.db)
                .await?;
        if let Some((id, device, request)) = existing {
            return if device == req.device_id
                && request == serde_json::to_value(&req.action).map_err(anyhow::Error::from)?
            {
                Ok(id)
            } else {
                Err(AppError::Conflict(
                    "Idempotency-Key was already used for a different request".into(),
                ))
            };
        }
    }

    let actor = format!("user:{}", p.email);
    let mut tx = state.db.begin().await?;
    let job: JobCore = sqlx::query_as(&format!(
        "INSERT INTO jobs (organization_id, device_id, action, request, timeout_secs, requested_by, request_channel,
                           idempotency_key, state, deliver_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'created', now() + make_interval(secs => $9))
         RETURNING {CORE}"
    ))
    .bind(org_id)
    .bind(req.device_id)
    .bind(req.action.name())
    .bind(serde_json::to_value(&req.action).map_err(anyhow::Error::from)?)
    .bind(timeout as i32)
    .bind(p.user_id)
    .bind(p.channel.as_str())
    .bind(&req.idempotency_key)
    .bind(state.config.delivery_window.as_secs_f64())
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict("duplicate Idempotency-Key".into()),
        _ => e.into(),
    })?;
    event(
        &mut tx,
        job.id,
        "created",
        None,
        Some(ExecState::Created),
        &actor,
        json!({ "request": job.request }),
    )
    .await?;
    let mut job = job;
    transition(
        &mut tx,
        &job,
        ExecState::Authorized,
        "system",
        "authorized",
        json!({ "role": p.role.as_str(), "credential": p.credential, "permission": "run_diagnostics" }),
        Sets::default(),
    )
    .await?;
    job.state = ExecState::Authorized.as_str().into();
    transition(
        &mut tx,
        &job,
        ExecState::Queued,
        "system",
        "queued",
        json!({}),
        Sets::default(),
    )
    .await?;
    Audit::user(p, "job.create")
        .org(org_id)
        .target("job", job.id)
        .detail(json!({ "device_id": req.device_id, "action": req.action.name(), "timeout_secs": timeout }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;

    dispatch_pending(state, req.device_id, Pass::NewWork).await?;
    Ok(job.id)
}

// ---------------------------------------------------------------------------------------
// Dispatch

/// Why a dispatch pass is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// A device just connected: also re-offer unacknowledged jobs and re-send pending
    /// cancels, since the previous connection may have lost them.
    NewConnection,
    /// New or retryable work on an existing connection. Messages already written to a live
    /// connection are not repeated: one WebSocket is ordered and reliable.
    NewWork,
}

/// Offer deliverable jobs to the device's live connection. Safe to call at any time and
/// concurrently: transitions are row-locked, and the agent deduplicates offers.
pub async fn dispatch_pending(state: &Shared, device_id: Uuid, pass: Pass) -> anyhow::Result<()> {
    let Some(conn) = state.registry.current_conn(device_id) else {
        return Ok(());
    };
    let ids: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM jobs
          WHERE device_id = $1 AND deliver_by > now()
            AND (state = 'queued'
                 OR ($2 AND state = 'dispatched' AND cancel_requested_at IS NULL
                     AND last_dispatch_conn IS DISTINCT FROM $3))
          ORDER BY created_at",
    )
    .bind(device_id)
    .bind(pass == Pass::NewConnection)
    .bind(conn)
    .fetch_all(&state.db)
    .await?;
    for (id,) in ids {
        dispatch_one(state, id, conn).await?;
    }
    if pass == Pass::NewWork {
        return Ok(());
    }
    let cancels: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM jobs WHERE device_id = $1 AND cancel_requested_at IS NOT NULL
            AND state IN ('dispatched', 'acknowledged', 'running', 'outcome_unknown')",
    )
    .bind(device_id)
    .fetch_all(&state.db)
    .await?;
    for (job_id,) in cancels {
        state
            .registry
            .send(device_id, ServerMsg::JobCancel { job_id });
    }
    Ok(())
}

/// Offer one job on connection `conn`. The row lock serializes concurrent passes; the
/// recorded `last_dispatch_conn` makes a second pass on the same connection a no-op.
async fn dispatch_one(state: &Shared, job_id: Uuid, conn: Uuid) -> anyhow::Result<()> {
    let mut tx = state.db.begin().await?;
    let Some(job) = lock(&mut tx, job_id).await? else {
        return Ok(());
    };
    let (last_conn,): (Option<Uuid>,) =
        sqlx::query_as("SELECT last_dispatch_conn FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&mut *tx)
            .await?;
    async fn record_conn(tx: &mut PgConnection, job_id: Uuid, conn: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE jobs SET last_dispatch_conn = $2 WHERE id = $1")
            .bind(job_id)
            .bind(conn)
            .execute(tx)
            .await
            .map(|_| ())
    }
    let action = job.action()?;
    let offer = ServerMsg::JobOffer {
        job_id,
        action,
        timeout_secs: job.timeout_secs as u32,
    };
    match job.state() {
        ExecState::Queued if job.cancel_requested_at.is_none() => {
            // Durably record the dispatch *before* the offer leaves, so the database can never
            // say "queued" (and later "expired, did not run") about a job a device holds. A
            // cancel that lands between commit and send sees `dispatched` and sends JobCancel.
            // Either order is safe at the agent: offer-then-cancel stops the job; cancel-then-
            // offer tombstones the id first, so the offer is reported cancelled and never run.
            transition(
                &mut tx,
                &job,
                ExecState::Dispatched,
                "system",
                "dispatched",
                json!({}),
                Sets::default(),
            )
            .await?;
            record_conn(&mut tx, job_id, conn).await?;
            tx.commit().await?;
            if !state.registry.send_on(job.device_id, conn, offer) {
                // Never left this server: provably not delivered, so back to the queue.
                let mut tx = state.db.begin().await?;
                if let Some(job) = lock(&mut tx, job_id).await? {
                    if job.state() == ExecState::Dispatched {
                        transition(
                            &mut tx,
                            &job,
                            ExecState::Queued,
                            "system",
                            "delivery_failed",
                            json!({ "reason": "connection closed before the offer was sent" }),
                            Sets::default(),
                        )
                        .await?;
                    }
                }
                tx.commit().await?;
            }
        }
        ExecState::Dispatched
            if last_conn != Some(conn)
                && job.cancel_requested_at.is_none()
                && state.registry.send_on(job.device_id, conn, offer) =>
        {
            sqlx::query("UPDATE jobs SET dispatch_count = dispatch_count + 1 WHERE id = $1")
                .bind(job_id)
                .execute(&mut *tx)
                .await?;
            record_conn(&mut tx, job_id, conn).await?;
            event(
                &mut tx,
                job_id,
                "redelivered",
                None,
                None,
                "system",
                json!({ "reason": "no acknowledgement on a previous connection" }),
            )
            .await?;
            tx.commit().await?;
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Device reports

/// What the gateway should do after a report is stored.
pub enum ReportResult {
    /// Send `ReportAck`: the final result is durably stored.
    AckFinal,
    Stored,
    /// The device reported on a job it does not own. Recorded; nothing changed.
    Foreign,
}

pub async fn apply_report(
    state: &Shared,
    device_id: Uuid,
    hostname: &str,
    report: JobReport,
) -> anyhow::Result<ReportResult> {
    let mut tx: Transaction<'_, Postgres> = state.db.begin().await?;
    let job = match lock(&mut tx, report.job_id).await? {
        Some(j) if j.device_id == device_id => j,
        found => {
            tx.rollback().await?;
            Audit::device(device_id, hostname, "device.job_report")
                .denied()
                .target("job", report.job_id)
                .detail(json!({ "reason": if found.is_some() { "job belongs to another device" } else { "unknown job" } }))
                .record(&state.db)
                .await?;
            return Ok(ReportResult::Foreign);
        }
    };
    let actor = format!("device:{device_id}");
    let current = job.state();
    let mut result = ReportResult::Stored;

    match report.phase {
        JobPhase::Accepted => match current {
            ExecState::Dispatched => {
                transition(
                    &mut tx,
                    &job,
                    ExecState::Acknowledged,
                    &actor,
                    "acknowledged",
                    json!({}),
                    Sets {
                        acknowledged: true,
                        ..Default::default()
                    },
                )
                .await?
            }
            _ => {
                event(
                    &mut tx,
                    job.id,
                    "acknowledged_again",
                    None,
                    None,
                    &actor,
                    json!({ "state": current.as_str() }),
                )
                .await?
            }
        },
        JobPhase::NotAccepted { reason } => {
            let detail = json!({ "reason": reason });
            match (current, reason) {
                (ExecState::Dispatched, NotAccepted::Busy) => {
                    // Provably not run; the sweeper will offer it again.
                    transition(
                        &mut tx,
                        &job,
                        ExecState::Queued,
                        &actor,
                        "declined_busy",
                        detail,
                        Sets::default(),
                    )
                    .await?
                }
                (ExecState::Dispatched | ExecState::OutcomeUnknown, _) => {
                    let note = format!("The device declined the job ({reason:?}); it did not run.");
                    transition(
                        &mut tx,
                        &job,
                        ExecState::Failed,
                        &actor,
                        "declined",
                        detail,
                        Sets {
                            state_note: Some(note),
                            ..Default::default()
                        },
                    )
                    .await?
                }
                _ => event(&mut tx, job.id, "declined_late", None, None, &actor, detail).await?,
            }
        }
        JobPhase::Started { at } => match current {
            ExecState::Dispatched | ExecState::Acknowledged => {
                transition(
                    &mut tx,
                    &job,
                    ExecState::Running,
                    &actor,
                    "started",
                    json!({}),
                    Sets {
                        started_at: Some(at),
                        acknowledged: true,
                        ..Default::default()
                    },
                )
                .await?
            }
            _ => {
                event(
                    &mut tx,
                    job.id,
                    "started_report",
                    None,
                    None,
                    &actor,
                    json!({ "state": current.as_str() }),
                )
                .await?
            }
        },
        JobPhase::Finished(finished) => {
            result = ReportResult::AckFinal;
            let target = state_for_outcome(&finished.outcome);
            let outcome = serde_json::to_value(&finished.outcome)?;
            if current.is_terminal()
                || (current == ExecState::OutcomeUnknown && target == ExecState::OutcomeUnknown)
            {
                event(
                    &mut tx,
                    job.id,
                    "final_report_again",
                    None,
                    None,
                    &actor,
                    json!({ "outcome": outcome }),
                )
                .await?;
            } else if target == ExecState::OutcomeUnknown {
                let note = match &finished.outcome {
                    ExecOutcome::Interrupted { reason } => reason.clone(),
                    _ => "outcome unknown".into(),
                };
                transition(
                    &mut tx,
                    &job,
                    ExecState::OutcomeUnknown,
                    &actor,
                    "interrupted",
                    json!({ "outcome": outcome }),
                    Sets {
                        state_note: Some(note),
                        finished: Some(*finished),
                        ..Default::default()
                    },
                )
                .await?;
            } else {
                let mut sets = Sets {
                    finished: Some((*finished).clone()),
                    acknowledged: true,
                    ..Default::default()
                };
                let late = current == ExecState::OutcomeUnknown;
                if target == ExecState::Completed {
                    let verdict = evidence::evaluate(&job.action()?, &finished);
                    sets.verification = Some(verdict.verification);
                    sets.verification_note = Some(verdict.explanation);
                    if verdict.verification == Verification::Verified {
                        record_job_inventory(&mut tx, &job, &finished).await?;
                    }
                }
                if late {
                    sets.state_note = Some("Resolved by a result the device reported after the outcome was marked unknown.".into());
                }
                if let ExecOutcome::Cancelled { started } = finished.outcome {
                    sets.state_note = Some(if started {
                        "Cancelled while running; output is partial.".into()
                    } else {
                        "Cancelled before it started; it did not run.".into()
                    });
                }
                let kind = if late { "resolved_late" } else { "finished" };
                transition(
                    &mut tx,
                    &job,
                    target,
                    &actor,
                    kind,
                    json!({ "outcome": outcome }),
                    sets,
                )
                .await?;
            }
        }
    }
    tx.commit().await?;
    Ok(result)
}

async fn record_job_inventory(
    tx: &mut PgConnection,
    job: &JobCore,
    f: &Finished,
) -> sqlx::Result<()> {
    if job.request.get("action").and_then(Value::as_str) != Some("system.info") {
        return Ok(());
    }
    let Some(data) = &f.structured else {
        return Ok(());
    };
    let collected = data
        .get("collected_at")
        .and_then(Value::as_str)
        .and_then(|s| OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok())
        .unwrap_or(f.finished_at);
    sqlx::query("INSERT INTO inventory_snapshots (device_id, collected_at, source, data) VALUES ($1, $2, 'job', $3)")
        .bind(job.device_id)
        .bind(collected)
        .bind(data)
        .execute(tx)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Cancellation

pub async fn cancel(state: &Shared, p: &Principal, job_id: Uuid) -> AppResult<()> {
    let (all, orgs) = p.scope();
    let mut tx = state.db.begin().await?;
    let job: Option<JobCore> = sqlx::query_as(&format!(
        "SELECT {CORE} FROM jobs WHERE id = $1 AND ($2 OR organization_id = ANY($3)) FOR UPDATE"
    ))
    .bind(job_id)
    .bind(all)
    .bind(&orgs)
    .fetch_optional(&mut *tx)
    .await?;
    let job = job.ok_or(AppError::NotFound)?;
    p.require(Permission::CancelJobs)?;
    let actor = format!("user:{}", p.email);
    let current = job.state();
    let audit = Audit::user(p, "job.cancel")
        .org(job.organization_id)
        .target("job", job_id);
    if current.is_pre_dispatch() {
        transition(
            &mut tx,
            &job,
            ExecState::Cancelled,
            &actor,
            "cancelled",
            json!({ "before_dispatch": true }),
            Sets {
                state_note: Some("Cancelled before it was sent; it did not run.".into()),
                ..Default::default()
            },
        )
        .await?;
        audit
            .detail(json!({ "effect": "cancelled before dispatch" }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(());
    }
    if current.is_terminal() || job.cancel_requested_at.is_some() {
        return Err(AppError::Conflict(format!(
            "job is already {}",
            current.as_str().replace('_', " ")
        )));
    }
    sqlx::query(
        "UPDATE jobs SET cancel_requested_at = now(), cancel_requested_by = $2 WHERE id = $1",
    )
    .bind(job_id)
    .bind(p.user_id)
    .execute(&mut *tx)
    .await?;
    event(
        &mut tx,
        job_id,
        "cancel_requested",
        None,
        None,
        &actor,
        json!({ "state": current.as_str() }),
    )
    .await?;
    audit
        .detail(json!({ "effect": "cancel requested from device" }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    state
        .registry
        .send(job.device_id, ServerMsg::JobCancel { job_id });
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Deadlines

/// Resolve deadlines and retry queued work. Runs periodically; every rule is idempotent.
pub async fn sweep(state: &Shared) -> anyhow::Result<()> {
    let grace = state.config.silence_grace.as_secs_f64();
    let rules: [(&str, ExecState, &str, &str); 3] = [
        (
            "SELECT id FROM jobs WHERE state = 'queued' AND deliver_by <= now()",
            ExecState::Expired,
            "expired",
            "The device did not connect before the delivery deadline. The job was never sent and did not run.",
        ),
        (
            "SELECT id FROM jobs WHERE state = 'dispatched' AND deliver_by <= now()",
            ExecState::OutcomeUnknown,
            "unconfirmed_delivery",
            "Sent, but the device never confirmed receiving it before the delivery deadline. It may or may not have run.",
        ),
        (
            "SELECT id FROM jobs WHERE state IN ('acknowledged', 'running')
                AND coalesce(acknowledged_at, first_dispatched_at) + make_interval(secs => timeout_secs + $1) <= now()",
            ExecState::OutcomeUnknown,
            "silent",
            "The device accepted the job but reported no result within its time limit plus grace. It may still report one.",
        ),
    ];
    for (select, to, kind, note) in rules {
        let ids: Vec<(Uuid,)> = sqlx::query_as(select)
            .bind(grace)
            .fetch_all(&state.db)
            .await?;
        for (id,) in ids {
            let mut tx = state.db.begin().await?;
            if let Some(job) = lock(&mut tx, id).await? {
                // Re-check under the lock: the row may have moved since the scan.
                let still_due = match to {
                    ExecState::Expired => job.state() == ExecState::Queued,
                    _ => job.state().is_in_flight(),
                };
                if still_due && job.state().can_transition_to(to) {
                    let due: (bool,) = sqlx::query_as(
                        "SELECT CASE WHEN state IN ('queued','dispatched') THEN deliver_by <= now()
                                ELSE coalesce(acknowledged_at, first_dispatched_at) + make_interval(secs => timeout_secs + $2) <= now() END
                           FROM jobs WHERE id = $1",
                    )
                    .bind(id)
                    .bind(grace)
                    .fetch_one(&mut *tx)
                    .await?;
                    if due.0 {
                        transition(
                            &mut tx,
                            &job,
                            to,
                            "system",
                            kind,
                            json!({}),
                            Sets {
                                state_note: Some(note.into()),
                                ..Default::default()
                            },
                        )
                        .await?;
                    }
                }
            }
            tx.commit().await?;
        }
    }
    for device in state.registry.connected_devices() {
        dispatch_pending(state, device, Pass::NewWork).await?;
    }
    Ok(())
}
