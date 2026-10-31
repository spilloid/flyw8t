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
use flyw8t_domain::job::{decide, state_for_outcome, ExecState, Report, Verification};
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

/// Events kept per job for reports that change nothing (see `apply_report`).
const MAX_EVENTS_PER_JOB: i64 = 50;
/// Device-supplied text (errors, reasons) is truncated to this many characters when stored.
const MAX_DEVICE_TEXT: usize = 4096;

fn clip(s: &str) -> String {
    s.chars().take(MAX_DEVICE_TEXT).collect()
}

/// A bounded summary of a device outcome, for event details.
fn outcome_summary(o: &ExecOutcome) -> Value {
    let short = |s: &str| s.chars().take(300).collect::<String>();
    match o {
        ExecOutcome::Failed { error } => json!({ "kind": "failed", "error": short(error) }),
        ExecOutcome::NotStarted { reason } => {
            json!({ "kind": "not_started", "reason": short(reason) })
        }
        ExecOutcome::Interrupted { reason } => {
            json!({ "kind": "interrupted", "reason": short(reason) })
        }
        other => serde_json::to_value(other).unwrap_or(Value::Null),
    }
}

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
        Some(ExecOutcome::Failed { error }) => (None, Some(clip(error))),
        Some(ExecOutcome::NotStarted { reason }) => {
            (None, Some(format!("Not executed: {}", clip(reason))))
        }
        Some(ExecOutcome::Interrupted { reason }) => (None, Some(clip(reason))),
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
    announce(&mut tx, req.device_id).await?;
    tx.commit().await?;

    dispatch_pending(state, req.device_id, Pass::NewWork).await?;
    Ok(job.id)
}

// ---------------------------------------------------------------------------------------
// Dispatch

/// Channel on which "this device has new work or a cancel" is announced to every server
/// instance, so the one holding the device's connection acts at once (ADR-0009). A lost
/// announcement costs latency only: the sweeper re-offers on its next pass.
pub const DISPATCH_CHANNEL: &str = "flyw8t_dispatch";

/// Announce work for `device_id`, delivered when the surrounding transaction commits.
async fn announce(tx: &mut PgConnection, device_id: Uuid) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(DISPATCH_CHANNEL)
        .bind(device_id.to_string())
        .execute(tx)
        .await?;
    Ok(())
}

/// Why a dispatch pass is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// A device just connected: also re-offer unacknowledged jobs and re-send pending
    /// cancels, since the previous connection may have lost them.
    NewConnection,
    /// New or retryable work on an existing connection. An offer already written to this
    /// connection is repeated only once it has gone unacknowledged for `redelivery_after`.
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
                 OR (state = 'dispatched' AND cancel_requested_at IS NULL
                     AND (($2 AND last_dispatch_conn IS DISTINCT FROM $3)
                          OR last_dispatched_at <= now() - make_interval(secs => $4))))
          ORDER BY created_at",
    )
    .bind(device_id)
    .bind(pass == Pass::NewConnection)
    .bind(conn)
    .bind(state.config.redelivery_after.as_secs_f64())
    .fetch_all(&state.db)
    .await?;
    for (id,) in ids {
        dispatch_one(state, id, conn).await?;
    }
    // Pending cancels: re-sent on a new connection, or after the redelivery interval. The
    // agent answers a cancel for any job id, known or not, so repeating one is harmless.
    let cancels: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM jobs WHERE device_id = $1 AND cancel_requested_at IS NOT NULL
            AND state IN ('dispatched', 'acknowledged', 'running', 'outcome_unknown')
            AND ($2 OR last_cancel_sent_at IS NULL
                 OR last_cancel_sent_at <= now() - make_interval(secs => $3))",
    )
    .bind(device_id)
    .bind(pass == Pass::NewConnection)
    .bind(state.config.redelivery_after.as_secs_f64())
    .fetch_all(&state.db)
    .await?;
    for (job_id,) in cancels {
        if state
            .registry
            .send_on(device_id, conn, ServerMsg::JobCancel { job_id })
        {
            sqlx::query("UPDATE jobs SET last_cancel_sent_at = now() WHERE id = $1")
                .bind(job_id)
                .execute(&state.db)
                .await?;
        }
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
    let (last_conn, stale, deliverable): (Option<Uuid>, bool, bool) = sqlx::query_as(
        "SELECT last_dispatch_conn,
                coalesce(last_dispatched_at <= now() - make_interval(secs => $2), true),
                deliver_by > clock_timestamp()
           FROM jobs WHERE id = $1",
    )
    .bind(job_id)
    .bind(state.config.redelivery_after.as_secs_f64())
    .fetch_one(&mut *tx)
    .await?;
    // The scan that selected this job may be stale by now; never send past the deadline.
    if !deliverable {
        return Ok(());
    }
    async fn record_conn(tx: &mut PgConnection, job_id: Uuid, conn: Uuid) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE jobs SET last_dispatch_conn = $2, last_dispatched_at = now() WHERE id = $1",
        )
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
                // This offer never left the server. Requeue only if no other offer has been
                // sent since: a reconnect may already have redelivered it on a new connection,
                // which rewrites last_dispatch_conn (adversarial review finding 1).
                let mut tx = state.db.begin().await?;
                if let Some(job) = lock(&mut tx, job_id).await? {
                    let (still_ours,): (bool,) = sqlx::query_as(
                        "SELECT last_dispatch_conn IS NOT DISTINCT FROM $2 FROM jobs WHERE id = $1",
                    )
                    .bind(job_id)
                    .bind(conn)
                    .fetch_one(&mut *tx)
                    .await?;
                    if job.state() == ExecState::Dispatched && still_ours {
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
            if (last_conn != Some(conn) || stale)
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
                json!({ "reason": if last_conn != Some(conn) { "not acknowledged on a previous connection" } else { "not acknowledged within the redelivery interval" } }),
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
    let (reduced, detail, unchanged_kind) = match &report.phase {
        JobPhase::Accepted => (Report::Accepted, json!({}), "acknowledged_again"),
        JobPhase::NotAccepted { reason } => (
            Report::NotAccepted {
                retryable: matches!(reason, NotAccepted::Busy | NotAccepted::StorageError),
            },
            json!({ "reason": reason }),
            "declined",
        ),
        JobPhase::Started { .. } => (Report::Started, json!({}), "started_report"),
        JobPhase::Finished(f) => (
            Report::Finished(state_for_outcome(&f.outcome)),
            json!({ "outcome": outcome_summary(&f.outcome) }),
            "final_report_again",
        ),
    };
    let decision = decide(current, reduced);
    let mut job = job;
    if decision.implied_dispatch {
        transition(
            &mut tx,
            &job,
            ExecState::Dispatched,
            &actor,
            "implied_dispatch",
            json!({ "reason": "the device reported on a job recorded as queued" }),
            Sets::default(),
        )
        .await?;
        job.state = ExecState::Dispatched.as_str().into();
    }
    match decision.to {
        None => {
            // Reports that change nothing are counted; only the first few are kept as events,
            // so a device repeating itself (or a hostile one) cannot grow history without bound.
            sqlx::query("UPDATE jobs SET unchanged_reports = unchanged_reports + 1 WHERE id = $1")
                .bind(job.id)
                .execute(&mut *tx)
                .await?;
            let (events,): (i64,) =
                sqlx::query_as("SELECT count(*) FROM job_events WHERE job_id = $1")
                    .bind(job.id)
                    .fetch_one(&mut *tx)
                    .await?;
            if events < MAX_EVENTS_PER_JOB {
                let mut detail = detail;
                detail["state"] = json!(current.as_str());
                event(&mut tx, job.id, unchanged_kind, None, None, &actor, detail).await?;
            }
        }
        Some(to) => {
            let from = job.state();
            let (kind, sets) = match report.phase {
                JobPhase::Accepted => (
                    "acknowledged",
                    Sets {
                        acknowledged: true,
                        ..Default::default()
                    },
                ),
                JobPhase::NotAccepted { reason } => (
                    "declined",
                    Sets {
                        state_note: Some(format!(
                            "The device declined the job ({reason:?}); it did not run."
                        )),
                        ..Default::default()
                    },
                ),
                JobPhase::Started { at } => (
                    "started",
                    Sets {
                        started_at: Some(at),
                        acknowledged: true,
                        ..Default::default()
                    },
                ),
                JobPhase::Finished(finished) => {
                    finished_sets(&mut tx, &job, from, to, *finished).await?
                }
            };
            transition(&mut tx, &job, to, &actor, kind, detail, sets).await?;
        }
    }
    tx.commit().await?;
    Ok(if decision.ack {
        ReportResult::AckFinal
    } else {
        ReportResult::Stored
    })
}

/// Columns and event kind for a final report moving `from` -> `to`.
async fn finished_sets(
    tx: &mut PgConnection,
    job: &JobCore,
    from: ExecState,
    to: ExecState,
    finished: Finished,
) -> anyhow::Result<(&'static str, Sets)> {
    if to == ExecState::OutcomeUnknown {
        let note = match &finished.outcome {
            ExecOutcome::Interrupted { reason } => clip(reason),
            _ => "outcome unknown".into(),
        };
        return Ok((
            "interrupted",
            Sets {
                state_note: Some(note),
                finished: Some(finished),
                ..Default::default()
            },
        ));
    }
    let late = from == ExecState::OutcomeUnknown;
    let mut sets = Sets {
        acknowledged: true,
        ..Default::default()
    };
    if to == ExecState::Completed {
        let verdict = evidence::evaluate(&job.action()?, &finished);
        if verdict.verification == Verification::Verified {
            record_job_inventory(tx, job, &finished).await?;
        }
        sets.verification = Some(verdict.verification);
        sets.verification_note = Some(verdict.explanation);
    }
    if late {
        sets.state_note = Some(
            "Resolved by a result the device reported after the outcome was marked unknown.".into(),
        );
    }
    if let ExecOutcome::Cancelled { started } = finished.outcome {
        sets.state_note = Some(if started {
            "Cancelled while running; output is partial.".into()
        } else {
            "Cancelled before it started; it did not run.".into()
        });
    }
    sets.finished = Some(finished);
    Ok((if late { "resolved_late" } else { "finished" }, sets))
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
    announce(&mut tx, job.device_id).await?;
    tx.commit().await?;
    // Sent at once if the device is connected to this instance; otherwise the instance that
    // holds its connection sends it on the announcement. Either way, `last_cancel_sent_at`
    // records an actual send, so the resend rule never waits on a send that did not happen.
    if state
        .registry
        .send(job.device_id, ServerMsg::JobCancel { job_id })
    {
        sqlx::query("UPDATE jobs SET last_cancel_sent_at = now() WHERE id = $1")
            .bind(job_id)
            .execute(&state.db)
            .await?;
    }
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
