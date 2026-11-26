//! A schedule authorizes distinct occurrences of one approved revision on one device.
//! The locked schedule row, occurrence receipt and job journal are updated in one transaction.

use crate::audit::Audit;
use crate::auth::{self, Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::fields::ScriptFields;
use crate::jobs::{self, ScriptJobActor};
use crate::web::{check_csrf, ctx, html, page, to, Form};
use crate::{trust, Shared};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::response::Response;
use flyw8t_domain::job::{outcome, ExecState, Verification};
use flyw8t_domain::{Permission, Role};
use flyw8t_protocol::messages::ScriptOffer;
use flyw8t_protocol::script::{parse_parameters, Param, ParamSource, Revision};
use flyw8t_protocol::trust::run::{check_approvals, check_values};
use flyw8t_protocol::trust::{Bytes as Salt, SignedApproval};
use flyw8t_web::schedules::{OccurrenceRow, ScheduleRow};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::json;
use sqlx::{types::Json, PgConnection};
use std::collections::BTreeMap;
use time::macros::format_description;
use time::{Duration, OffsetDateTime, PrimitiveDateTime};
use uuid::Uuid;

const MAX_ACTIVE_PER_DEVICE: i64 = 25;
const HISTORY_SIZE: i64 = 50;

#[derive(sqlx::FromRow)]
struct Target {
    organization_id: Uuid,
    hostname: String,
    site_id: Option<Uuid>,
}

async fn device(state: &Shared, p: &Principal, id: Uuid) -> AppResult<Target> {
    let (all, orgs) = p.scope();
    sqlx::query_as(
        "SELECT organization_id, hostname, site_id FROM devices
         WHERE id = $1 AND ($2 OR organization_id = ANY($3))",
    )
    .bind(id)
    .bind(all)
    .bind(&orgs)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)
}

async fn eligible_device(db: &mut PgConnection, organization: Uuid, id: Uuid) -> AppResult<Target> {
    let target: Option<Target> = sqlx::query_as(
        "SELECT organization_id, hostname, site_id FROM devices d
         WHERE d.id = $1 AND d.organization_id = $2 AND d.retired_at IS NULL
           AND lower(d.os_family) = 'windows'
         FOR SHARE OF d",
    )
    .bind(id)
    .bind(organization)
    .fetch_optional(&mut *db)
    .await?;
    let unavailable = || {
        AppError::Conflict(
            "Scheduling requires an enrolled Windows device with an active credential.".into(),
        )
    };
    let target = target.ok_or_else(unavailable)?;
    let credential = sqlx::query(
        "SELECT 1 FROM device_credentials WHERE device_id = $1 AND revoked_at IS NULL FOR SHARE",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    credential.map(|_| target).ok_or_else(unavailable)
}

struct Approved {
    name: String,
    revision: Revision,
    approvals: Vec<SignedApproval>,
    deployment: Uuid,
    parameters: Vec<Param>,
}

async fn approved(
    db: &mut PgConnection,
    org: Uuid,
    script: Uuid,
    number: i32,
) -> AppResult<Approved> {
    let (name,): (String,) = sqlx::query_as(
        "SELECT name FROM scripts WHERE id = $1 AND (organization_id IS NULL OR organization_id = $2)",
    )
    .bind(script)
    .bind(org)
    .fetch_optional(&mut *db)
    .await?
    .ok_or(AppError::NotFound)?;
    let revision = trust::revision_for_in(&mut *db, script, number).await?;
    if revision.language != "powershell" || revision.risk.needs_run_signature() {
        return Err(AppError::Conflict(
            "Schedules require a C0 or C1 PowerShell revision.".into(),
        ));
    }
    let (_, head) = trust::head(&mut *db)
        .await?
        .ok_or_else(|| AppError::Conflict("The deployment has no script trust list.".into()))?;
    let (approvals, _) = trust::approvals_for(&mut *db, &revision, &head.list).await?;
    check_approvals(&head.list, &revision, &approvals, Some(&org))
        .map_err(|error| AppError::Conflict(error.to_string()))?;
    let (parameters, problems) = parse_parameters(&revision.parameters);
    if !problems.is_empty() || parameters.iter().any(Param::is_secret) {
        return Err(AppError::Conflict(
            "Schedules require valid, non-secret parameters.".into(),
        ));
    }
    Ok(Approved {
        name,
        revision,
        approvals,
        deployment: head.list.deployment_id,
        parameters,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cadence {
    Once,
    Daily,
    Weekly,
}

impl Cadence {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "once" => Some(Self::Once),
            "daily" => Some(Self::Daily),
            "weekly" => Some(Self::Weekly),
            _ => None,
        }
    }

    fn next(self, due: OffsetDateTime) -> Option<OffsetDateTime> {
        match self {
            Self::Once => None,
            Self::Daily => due.checked_add(Duration::days(1)),
            Self::Weekly => due.checked_add(Duration::weeks(1)),
        }
    }
}

#[derive(Default, Deserialize)]
pub struct HistoryQuery {
    #[serde(default)]
    history_page: u32,
}

pub async fn list(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    Query(query): Query<HistoryQuery>,
) -> Response {
    page(&p, async {
        p.require(Permission::RunScripts)?;
        let target = device(&state, &p, id).await?;
        let schedules: Vec<(Uuid, String, i32, String, Option<OffsetDateTime>, Option<String>, String, Uuid)> =
            sqlx::query_as(
                "SELECT ss.id, s.name, ss.revision_number, ss.cadence, ss.next_at, ss.stop_reason, u.email, ss.created_by
                 FROM script_schedules ss JOIN scripts s ON s.id = ss.script_id JOIN users u ON u.id = ss.created_by
                 WHERE ss.device_id = $1 AND ss.organization_id = $2
                 AND (ss.next_at IS NOT NULL OR ss.stopped_at IS NOT NULL)
                 ORDER BY ss.next_at NULLS LAST, ss.stopped_at DESC, ss.id LIMIT 75",
            )
            .bind(id)
            .bind(target.organization_id)
            .fetch_all(&state.db)
            .await?;
        let occurrences: Vec<(String, i32, OffsetDateTime, String, Option<String>, Option<Uuid>, Option<String>, Option<String>)> =
            sqlx::query_as(
                "SELECT s.name, ss.revision_number, o.due_at, o.outcome, o.reason, o.job_id, j.state, j.verification
                 FROM script_schedule_occurrences o JOIN script_schedules ss ON ss.id = o.schedule_id
                 JOIN scripts s ON s.id = ss.script_id LEFT JOIN jobs j ON j.id = o.job_id
                 WHERE ss.device_id = $1 AND ss.organization_id = $2
                 ORDER BY o.due_at DESC, o.schedule_id LIMIT $3 OFFSET $4",
            )
            .bind(id)
            .bind(target.organization_id)
            .bind(HISTORY_SIZE + 1)
            .bind(i64::from(query.history_page) * HISTORY_SIZE)
            .fetch_all(&state.db)
            .await?;
        let has_older = occurrences.len() > HISTORY_SIZE as usize;
        let history = occurrences.into_iter().take(HISTORY_SIZE as usize).map(
            |(script, revision, due, recorded, reason, job_id, state, verification)| {
                let label = match (state, verification) {
                    (Some(state), Some(verification)) => outcome(
                        ExecState::parse(&state).unwrap_or(ExecState::OutcomeUnknown),
                        Verification::parse(&verification).unwrap_or(Verification::Pending)
                    ).label.to_string(),
                    _ => recorded,
                };
                OccurrenceRow { script, revision, due, label, reason, job_id }
            },
        ).collect();
        let rows = schedules.into_iter().map(|(id, script, revision, cadence, next, stop_reason, creator, creator_id)| {
            ScheduleRow {
                id, script, revision, cadence, next, stop_reason, creator,
                can_cancel: p.role.is_global() || p.user_id == creator_id,
            }
        }).collect();
        html(flyw8t_web::schedules::index(&ctx(&p, None), id, &target.hostname, rows, history, query.history_page, has_older))
    })
    .await
}

pub async fn new_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path((id, script, number)): Path<(Uuid, Uuid, i32)>,
) -> Response {
    page(&p, async {
        p.require(Permission::RunScripts)?;
        let target = device(&state, &p, id).await?;
        let mut db = state.db.acquire().await?;
        eligible_device(&mut db, target.organization_id, id).await?;
        let candidate = approved(&mut db, target.organization_id, script, number).await?;
        let asks = candidate
            .parameters
            .into_iter()
            .filter_map(|p| match p.source {
                ParamSource::Ask { prompt } => Some((p.name, prompt)),
                _ => None,
            })
            .collect();
        html(flyw8t_web::schedules::new_form(
            &ctx(&p, None),
            id,
            script,
            number,
            &candidate.name,
            asks,
        ))
    })
    .await
}

pub async fn create(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path((id, script, number)): Path<(Uuid, Uuid, i32)>,
    body: Bytes,
) -> Response {
    let form = Form::parse(&body);
    page(&p, async {
        check_csrf(&p, &form)?;
        p.require(Permission::RunScripts)?;
        let target = device(&state, &p, id).await?;
        let fields = ScriptFields::load(&state, target.organization_id, target.site_id, id).await?;
        let starts = PrimitiveDateTime::parse(
            form.get("starts").unwrap_or(""),
            format_description!("[year]-[month]-[day]T[hour]:[minute]"),
        )
        .map_err(|_| AppError::BadRequest("Enter a start date and time in UTC.".into()))?
        .assume_utc();
        let cadence = form.get("cadence").filter(|s| Cadence::parse(s).is_some())
            .ok_or_else(|| AppError::BadRequest("Choose one-time, daily or weekly.".into()))?;
        let delivery = form.get("delivery").and_then(|s| s.parse::<i32>().ok())
            .filter(|s| matches!(s, 900 | 3600 | 86400 | 604800))
            .ok_or_else(|| AppError::BadRequest("Choose a delivery window.".into()))?;
        let timeout = form.get("timeout").and_then(|s| s.parse::<i32>().ok())
            .filter(|s| (1..=3600).contains(s))
            .ok_or_else(|| AppError::BadRequest("The timeout must be 1 to 3600 seconds.".into()))?;

        let mut tx = state.db.begin().await?;
        // This lock also serializes creation against the device's schedule count and retirement.
        sqlx::query("SELECT id FROM devices WHERE id = $1 AND organization_id = $2 FOR UPDATE")
            .bind(id).bind(target.organization_id).fetch_optional(&mut *tx).await?
            .ok_or(AppError::NotFound)?;
        let current = eligible_device(&mut tx, target.organization_id, id).await?;
        if current.site_id != target.site_id {
            return Err(AppError::Conflict("The device changed sites. Reopen this form to use its current site values.".into()));
        }
        auth::recheck_actor(&mut tx, &p, Some(target.organization_id), false).await?;
        let (now,): (OffsetDateTime,) = sqlx::query_as("SELECT clock_timestamp()").fetch_one(&mut *tx).await?;
        if starts <= now {
            return Err(AppError::BadRequest("The start time must be in the future.".into()));
        }
        let (count,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM script_schedules WHERE device_id = $1 AND organization_id = $2 AND next_at IS NOT NULL")
            .bind(id).bind(target.organization_id).fetch_one(&mut *tx).await?;
        if count >= MAX_ACTIVE_PER_DEVICE {
            return Err(AppError::Conflict(format!("This device already has {MAX_ACTIVE_PER_DEVICE} active script schedules.")));
        }
        let candidate = approved(&mut tx, target.organization_id, script, number).await?;
        let mut values = BTreeMap::new();
        for parameter in &candidate.parameters {
            let value = match &parameter.source {
                ParamSource::Constant(value) => value,
                ParamSource::Ask { .. } => form.get(&format!("v_{}", parameter.name)).ok_or_else(|| {
                    AppError::BadRequest(format!("Enter a value for {}.", parameter.name))
                })?,
                ParamSource::Field { level, key, secret } => fields.value(level, key, *secret).map_err(AppError::BadRequest)?,
            };
            values.insert(parameter.name.clone(), value.to_string());
        }
        check_values(&candidate.revision, &values, &BTreeMap::new())
            .map_err(|e| AppError::BadRequest(e.to_string()))?;
        let (schedule,): (Uuid,) = sqlx::query_as(
            "INSERT INTO script_schedules
                (organization_id, device_id, script_id, revision_number, parameter_values, timeout_secs,
                 delivery_secs, cadence, first_at, next_at, created_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10) RETURNING id",
        )
        .bind(target.organization_id).bind(id).bind(script).bind(number).bind(Json(values))
        .bind(timeout).bind(delivery).bind(cadence).bind(starts).bind(p.user_id)
        .fetch_one(&mut *tx).await?;
        Audit::user(&p, "script.schedule.create")
            .org(target.organization_id)
            .target("device", id)
            .detail(json!({"schedule_id":schedule,"script_id":script,"revision":number,"cadence":cadence}))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        to(format!("/devices/{id}/schedules"))
    })
    .await
}

pub async fn cancel(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path((id, schedule)): Path<(Uuid, Uuid)>,
    body: Bytes,
) -> Response {
    let form = Form::parse(&body);
    page(&p, async {
        check_csrf(&p, &form)?;
        p.require(Permission::RunScripts)?;
        let target = device(&state, &p, id).await?;
        let mut tx = state.db.begin().await?;
        // Take the schedule lock before the actor lock, matching the worker.
        let (creator, next): (Uuid, Option<OffsetDateTime>) = sqlx::query_as(
            "SELECT created_by, next_at FROM script_schedules
             WHERE id = $1 AND device_id = $2 AND organization_id = $3 FOR UPDATE",
        )
        .bind(schedule).bind(id).bind(target.organization_id)
        .fetch_optional(&mut *tx).await?.ok_or(AppError::NotFound)?;
        auth::recheck_actor(&mut tx, &p, Some(target.organization_id), false).await?;
        if !p.role.is_global() && p.user_id != creator {
            return Err(AppError::Forbidden);
        }
        if next.is_some() {
            sqlx::query("UPDATE script_schedules SET next_at = NULL, stopped_at = now(), stop_reason = 'Cancelled by an operator' WHERE id = $1")
                .bind(schedule).execute(&mut *tx).await?;
            Audit::user(&p, "script.schedule.cancel")
                .org(target.organization_id).target("device", id)
                .detail(json!({"schedule_id":schedule})).record(&mut *tx).await?;
        }
        tx.commit().await?;
        to(format!("/devices/{id}/schedules"))
    })
    .await
}

#[derive(sqlx::FromRow)]
struct Due {
    id: Uuid,
    organization_id: Uuid,
    device_id: Uuid,
    script_id: Uuid,
    revision_number: i32,
    parameter_values: Json<BTreeMap<String, String>>,
    timeout_secs: i32,
    delivery_secs: i32,
    cadence: String,
    next_at: OffsetDateTime,
    created_by: Uuid,
}

async fn creator_email(db: &mut PgConnection, due: &Due) -> AppResult<String> {
    let (email, role): (String, String) = sqlx::query_as(
        "SELECT email, role FROM users WHERE id = $1 AND disabled_at IS NULL FOR SHARE",
    )
    .bind(due.created_by)
    .fetch_optional(&mut *db)
    .await?
    .ok_or_else(|| AppError::Conflict("The schedule owner is disabled.".into()))?;
    let role = Role::parse(&role)
        .filter(|role| role.allows(Permission::RunScripts))
        .ok_or_else(|| {
            AppError::Conflict("The schedule owner lost permission to run scripts.".into())
        })?;
    if !role.is_global() {
        let membership = sqlx::query(
            "SELECT 1 FROM user_organizations WHERE user_id = $1 AND organization_id = $2 FOR KEY SHARE",
        )
        .bind(due.created_by)
        .bind(due.organization_id)
        .fetch_optional(&mut *db)
        .await?;
        if membership.is_none() {
            return Err(AppError::Conflict(
                "The schedule owner lost organization access.".into(),
            ));
        }
    }
    Ok(email)
}

async fn enqueue(db: &mut PgConnection, due: &Due, deliver_by: OffsetDateTime) -> AppResult<Uuid> {
    // Device then actor is the same lock order as interactive script creation.
    let target = eligible_device(db, due.organization_id, due.device_id).await?;
    let email = creator_email(db, due).await?;
    // Trust is append-only. A table share lock serializes this job's creation against
    // an upload of the next signed list, which may revoke the revision.
    sqlx::query("LOCK TABLE trust_versions IN SHARE MODE")
        .execute(&mut *db)
        .await?;
    let candidate = approved(db, due.organization_id, due.script_id, due.revision_number).await?;
    let values = &due.parameter_values.0;
    check_values(&candidate.revision, values, &BTreeMap::new())
        .map_err(|error| AppError::Conflict(error.to_string()))?;
    let mut salt = [0; 32];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| anyhow::anyhow!("script salt RNG"))?;
    let offer = ScriptOffer {
        job_id: Uuid::new_v4(),
        deployment_id: candidate.deployment,
        timeout_secs: due.timeout_secs as u32,
        revision: candidate.revision,
        approvals: candidate.approvals,
        authorization: None,
        salt: Salt(salt.to_vec()),
        values: values.clone(),
        secrets: BTreeMap::new(),
    };
    let summary = json!({
        "script": candidate.name, "revision": due.revision_number,
        "risk": offer.revision.risk.as_str(), "values": values,
        "device": target.hostname, "schedule_id": due.id, "scheduled_at": due.next_at,
    });
    jobs::insert_script_job(
        db,
        ScriptJobActor::Scheduled {
            user_id: due.created_by,
            email: &email,
            schedule_id: due.id,
        },
        due.device_id,
        due.organization_id,
        &offer,
        summary,
        deliver_by,
    )
    .await
}

pub async fn sweep(state: &Shared) -> anyhow::Result<()> {
    // Bound the catch-up work per sweep so an outage cannot starve other workers.
    for _ in 0..32 {
        let mut tx = state.db.begin().await?;
        let row: Option<Due> = sqlx::query_as(
            "SELECT id, organization_id, device_id, script_id, revision_number, parameter_values,
                    timeout_secs, delivery_secs, cadence, next_at, created_by
             FROM script_schedules WHERE next_at <= clock_timestamp()
             ORDER BY next_at, id LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(due) = row else { break };
        let (now,): (OffsetDateTime,) = sqlx::query_as("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let deliver_by = due.next_at + Duration::seconds(i64::from(due.delivery_secs));
        let (outcome, reason, job) = if now >= deliver_by {
            (
                "missed",
                Some("The delivery window ended before a job was created.".into()),
                None,
            )
        } else {
            match enqueue(&mut tx, &due, deliver_by).await {
                Ok(job) => ("queued", None, Some(job)),
                Err(AppError::Conflict(reason)) => ("blocked", Some(reason), None),
                Err(AppError::NotFound) => (
                    "blocked",
                    Some("The approved revision is unavailable.".into()),
                    None,
                ),
                Err(error) => return Err(error.into()),
            }
        };
        sqlx::query(
            "INSERT INTO script_schedule_occurrences (schedule_id,due_at,outcome,reason,job_id)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(due.id)
        .bind(due.next_at)
        .bind(outcome)
        .bind(&reason)
        .bind(job)
        .execute(&mut *tx)
        .await?;
        if outcome == "blocked" {
            sqlx::query("UPDATE script_schedules SET next_at = NULL, stopped_at = now(), stop_reason = $2 WHERE id = $1")
                .bind(due.id).bind(&reason).execute(&mut *tx).await?;
        } else {
            let next = Cadence::parse(&due.cadence).and_then(|cadence| cadence.next(due.next_at));
            sqlx::query("UPDATE script_schedules SET next_at = $2 WHERE id = $1")
                .bind(due.id)
                .bind(next)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    }
    Ok(())
}
