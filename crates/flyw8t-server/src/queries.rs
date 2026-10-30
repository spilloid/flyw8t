//! Read models for the console and API. Every query is scoped to the caller's organizations;
//! a record outside scope is indistinguishable from one that does not exist.

use crate::auth::Principal;
use crate::Shared;
use flyw8t_domain::job::{ExecState, Verification};
use flyw8t_protocol::catalog;
use flyw8t_web::model::*;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

fn connection(
    state: &Shared,
    id: Uuid,
    last_seen: Option<OffsetDateTime>,
    last_connected: Option<OffsetDateTime>,
) -> Connection {
    match state.registry.connected_since(id) {
        Some(since) => Connection::Connected { since },
        None if last_connected.is_none() => Connection::NeverConnected,
        None => Connection::Disconnected { last_seen },
    }
}

fn like_pattern(q: &str) -> String {
    let escaped = q
        .trim()
        .to_lowercase()
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

type DeviceTuple = (
    Uuid,
    String,
    Uuid,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
);

const DEVICE_SELECT: &str = "
    SELECT d.id, d.hostname, o.id, o.name, s.name, inv.os, d.agent_version, d.last_seen_at, d.last_connected_at, d.retired_at
      FROM devices d
      JOIN organizations o ON o.id = d.organization_id
      LEFT JOIN sites s ON s.id = d.site_id
      LEFT JOIN LATERAL (
          SELECT coalesce(i.data->'os'->>'long_version', i.data->'os'->>'name', i.data->'os'->>'family') AS os
            FROM inventory_snapshots i WHERE i.device_id = d.id ORDER BY i.received_at DESC LIMIT 1
      ) inv ON true";

fn device_row(state: &Shared, t: DeviceTuple) -> DeviceRow {
    let (
        id,
        hostname,
        org_id,
        org_name,
        site,
        os,
        agent_version,
        last_seen,
        last_connected,
        retired,
    ) = t;
    DeviceRow {
        id,
        hostname,
        organization: OrgRef {
            id: org_id,
            name: org_name,
        },
        site,
        os,
        agent_version,
        connection: connection(state, id, last_seen, last_connected),
        retired: retired.is_some(),
    }
}

pub async fn devices(
    state: &Shared,
    p: &Principal,
    f: &DeviceFilter,
) -> sqlx::Result<Vec<DeviceRow>> {
    let (all, orgs) = p.scope();
    let q = (!f.q.trim().is_empty()).then(|| like_pattern(&f.q));
    let rows: Vec<DeviceTuple> = sqlx::query_as(&format!(
        "{DEVICE_SELECT}
          WHERE ($1 OR d.organization_id = ANY($2))
            AND ($3::text IS NULL OR lower(d.hostname) LIKE $3)
            AND ($4::uuid IS NULL OR d.organization_id = $4)
          ORDER BY lower(d.hostname), d.id LIMIT 1000"
    ))
    .bind(all)
    .bind(&orgs)
    .bind(q)
    .bind(f.organization)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|t| device_row(state, t))
        .filter(|d| match f.connection.as_str() {
            "connected" => matches!(d.connection, Connection::Connected { .. }),
            "offline" => !matches!(d.connection, Connection::Connected { .. }),
            _ => true,
        })
        .collect())
}

pub async fn device(state: &Shared, p: &Principal, id: Uuid) -> sqlx::Result<Option<DeviceDetail>> {
    let (all, orgs) = p.scope();
    let row: Option<DeviceTuple> = sqlx::query_as(&format!(
        "{DEVICE_SELECT} WHERE d.id = $1 AND ($2 OR d.organization_id = ANY($3))"
    ))
    .bind(id)
    .bind(all)
    .bind(&orgs)
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let row = device_row(state, row);
    let (enrolled_at,): (OffsetDateTime,) =
        sqlx::query_as("SELECT enrolled_at FROM devices WHERE id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    let inv: Option<(OffsetDateTime, String, Value)> = sqlx::query_as(
        "SELECT received_at, source, data FROM inventory_snapshots WHERE device_id = $1 ORDER BY received_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let inventory = inv.and_then(|(received_at, source, data)| {
        serde_json::from_value(data)
            .ok()
            .map(|report| InventoryView {
                received_at,
                source,
                report,
            })
    });
    let cred: Option<(Vec<u8>, OffsetDateTime, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT public_key, created_at, revoked_at FROM device_credentials WHERE device_id = $1
          ORDER BY revoked_at IS NULL DESC, created_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let credential = cred.map(|(key, created_at, revoked_at)| CredentialView {
        created_at,
        revoked_at,
        fingerprint: crate::gateway::fingerprint(&key),
    });
    let recent_jobs = jobs(
        state,
        p,
        &JobQuery {
            device: Some(id),
            limit: 25,
            ..Default::default()
        },
    )
    .await?;
    Ok(Some(DeviceDetail {
        row,
        enrolled_at,
        inventory,
        credential,
        recent_jobs,
        remote_access: state.remote_access.describe(id),
    }))
}

#[derive(Default)]
pub struct JobQuery {
    pub device: Option<Uuid>,
    pub state: Option<ExecState>,
    pub attention_since: Option<OffsetDateTime>,
    pub limit: i64,
}

type JobTuple = (
    Uuid,
    Uuid,
    String,
    Uuid,
    String,
    String,
    Value,
    String,
    String,
    String,
    OffsetDateTime,
    Option<OffsetDateTime>,
);

const JOB_SELECT: &str = "
    SELECT j.id, j.device_id, d.hostname, o.id, o.name, j.action, j.request, j.state, j.verification, u.email,
           j.created_at, j.terminal_at
      FROM jobs j
      JOIN devices d ON d.id = j.device_id
      JOIN organizations o ON o.id = j.organization_id
      JOIN users u ON u.id = j.requested_by";

fn params_summary(request: &Value) -> String {
    request
        .get("params")
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .map(|(k, v)| {
                    format!(
                        "{k}={}",
                        v.as_str().map_or_else(|| v.to_string(), str::to_string)
                    )
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

fn job_row(t: JobTuple) -> JobRow {
    let (
        id,
        device_id,
        hostname,
        org_id,
        org_name,
        action,
        request,
        state,
        verification,
        email,
        created_at,
        terminal_at,
    ) = t;
    JobRow {
        id,
        device_id,
        hostname,
        organization: OrgRef {
            id: org_id,
            name: org_name,
        },
        action,
        params: params_summary(&request),
        state: ExecState::parse(&state).unwrap_or(ExecState::OutcomeUnknown),
        verification: Verification::parse(&verification).unwrap_or(Verification::Pending),
        requested_by: email,
        created_at,
        terminal_at,
    }
}

pub async fn jobs(state: &Shared, p: &Principal, q: &JobQuery) -> sqlx::Result<Vec<JobRow>> {
    let (all, orgs) = p.scope();
    let rows: Vec<JobTuple> = sqlx::query_as(&format!(
        "{JOB_SELECT}
          WHERE ($1 OR j.organization_id = ANY($2))
            AND ($3::uuid IS NULL OR j.device_id = $3)
            AND ($4::text IS NULL OR j.state = $4)
            AND ($5::timestamptz IS NULL OR (j.created_at >= $5 AND
                 (j.state IN ('outcome_unknown', 'failed', 'timed_out') OR j.verification = 'failed')))
          ORDER BY j.created_at DESC LIMIT $6"
    ))
    .bind(all)
    .bind(&orgs)
    .bind(q.device)
    .bind(q.state.map(ExecState::as_str))
    .bind(q.attention_since)
    .bind(q.limit.clamp(1, 500))
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(job_row).collect())
}

#[derive(sqlx::FromRow)]
struct JobExtra {
    request_channel: String,
    timeout_secs: i32,
    deliver_by: OffsetDateTime,
    dispatch_count: i32,
    acknowledged_at: Option<OffsetDateTime>,
    started_at: Option<OffsetDateTime>,
    finished_at: Option<OffsetDateTime>,
    cancel_requested_at: Option<OffsetDateTime>,
    state_note: Option<String>,
    verification_note: Option<String>,
    exit_code: Option<i32>,
    stdout: Option<String>,
    stdout_truncated: Option<bool>,
    stderr: Option<String>,
    stderr_truncated: Option<bool>,
    result: Option<Value>,
    error: Option<String>,
}

pub async fn job(state: &Shared, p: &Principal, id: Uuid) -> sqlx::Result<Option<JobDetail>> {
    let (all, orgs) = p.scope();
    let row: Option<JobTuple> = sqlx::query_as(&format!(
        "{JOB_SELECT} WHERE j.id = $1 AND ($2 OR j.organization_id = ANY($3))"
    ))
    .bind(id)
    .bind(all)
    .bind(&orgs)
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let row = job_row(row);
    let x: JobExtra = sqlx::query_as(
        "SELECT request_channel, timeout_secs, deliver_by, dispatch_count, acknowledged_at, started_at, finished_at,
                cancel_requested_at, state_note, verification_note, exit_code, stdout, stdout_truncated, stderr,
                stderr_truncated, result, error
           FROM jobs WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await?;
    let events: Vec<(OffsetDateTime, String, Option<String>, Option<String>, String, Value)> =
        sqlx::query_as("SELECT at, kind, from_state, to_state, actor, detail FROM job_events WHERE job_id = $1 ORDER BY id")
            .bind(id)
            .fetch_all(&state.db)
            .await?;
    let stream = |d: Option<String>, t: Option<bool>| {
        d.map(|data| StreamView {
            data,
            truncated: t.unwrap_or(false),
        })
    };
    let success_contract = catalog::info(&row.action)
        .map_or("Unknown action.", |i| i.success_contract)
        .to_string();
    Ok(Some(JobDetail {
        row,
        request_channel: x.request_channel,
        timeout_secs: x.timeout_secs,
        deliver_by: x.deliver_by,
        dispatch_count: x.dispatch_count,
        acknowledged_at: x.acknowledged_at,
        started_at: x.started_at,
        finished_at: x.finished_at,
        cancel_requested_at: x.cancel_requested_at,
        state_note: x.state_note,
        verification_note: x.verification_note,
        exit_code: x.exit_code,
        stdout: stream(x.stdout, x.stdout_truncated),
        stderr: stream(x.stderr, x.stderr_truncated),
        result: x.result,
        error: x.error,
        success_contract,
        events: events
            .into_iter()
            .map(
                |(at, kind, from_state, to_state, actor, detail)| JobEventView {
                    at,
                    kind,
                    from_state,
                    to_state,
                    actor,
                    detail,
                },
            )
            .collect(),
    }))
}

pub async fn overview(state: &Shared, p: &Principal) -> sqlx::Result<Overview> {
    let (all, orgs) = p.scope();
    let ids: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM devices WHERE retired_at IS NULL AND ($1 OR organization_id = ANY($2))",
    )
    .bind(all)
    .bind(&orgs)
    .fetch_all(&state.db)
    .await?;
    let connected = ids
        .iter()
        .filter(|(id,)| state.registry.connected_since(*id).is_some())
        .count();
    let (in_flight, ok, failed, unknown): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE state IN ('queued', 'dispatched', 'acknowledged', 'running')),
                count(*) FILTER (WHERE state = 'completed' AND verification = 'verified' AND created_at > now() - interval '24 hours'),
                count(*) FILTER (WHERE (state IN ('failed', 'timed_out') OR verification = 'failed') AND created_at > now() - interval '24 hours'),
                count(*) FILTER (WHERE state = 'outcome_unknown')
           FROM jobs WHERE ($1 OR organization_id = ANY($2))",
    )
    .bind(all)
    .bind(&orgs)
    .fetch_one(&state.db)
    .await?;
    let since = OffsetDateTime::now_utc() - time::Duration::hours(24);
    Ok(Overview {
        devices_total: ids.len() as i64,
        devices_connected: connected as i64,
        jobs_in_flight: in_flight,
        jobs_succeeded_24h: ok,
        jobs_failed_24h: failed,
        jobs_unknown: unknown,
        attention: jobs(
            state,
            p,
            &JobQuery {
                attention_since: Some(since),
                limit: 10,
                ..Default::default()
            },
        )
        .await?,
        recent: jobs(
            state,
            p,
            &JobQuery {
                limit: 15,
                ..Default::default()
            },
        )
        .await?,
    })
}

pub async fn org_refs(state: &Shared, p: &Principal) -> sqlx::Result<Vec<OrgRef>> {
    let (all, orgs) = p.scope();
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM organizations WHERE ($1 OR id = ANY($2)) ORDER BY lower(name)",
    )
    .bind(all)
    .bind(&orgs)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name)| OrgRef { id, name })
        .collect())
}

pub async fn organizations(
    state: &Shared,
    p: &Principal,
    only: Option<Uuid>,
) -> sqlx::Result<Vec<OrgSummary>> {
    let (all, orgs) = p.scope();
    let rows: Vec<(Uuid, String, OffsetDateTime, i64)> = sqlx::query_as(
        "SELECT o.id, o.name, o.created_at, (SELECT count(*) FROM devices d WHERE d.organization_id = o.id AND d.retired_at IS NULL)
           FROM organizations o WHERE ($1 OR o.id = ANY($2)) AND ($3::uuid IS NULL OR o.id = $3) ORDER BY lower(o.name)",
    )
    .bind(all)
    .bind(&orgs)
    .bind(only)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, name, created_at, device_count) in rows {
        let sites: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM sites WHERE organization_id = $1 ORDER BY lower(name)",
        )
        .bind(id)
        .fetch_all(&state.db)
        .await?;
        out.push(OrgSummary {
            id,
            name,
            device_count,
            created_at,
            sites: sites
                .into_iter()
                .map(|(id, name)| SiteView { id, name })
                .collect(),
        });
    }
    Ok(out)
}

pub async fn enrollment_tokens(
    state: &Shared,
    org: Uuid,
) -> sqlx::Result<Vec<EnrollmentTokenView>> {
    let rows: Vec<(Uuid, Option<String>, String, OffsetDateTime, OffsetDateTime, i32, i32, bool)> = sqlx::query_as(
        "SELECT t.id, s.name, u.email, t.created_at, t.expires_at, t.uses, t.max_uses, t.revoked_at IS NOT NULL
           FROM enrollment_tokens t JOIN users u ON u.id = t.created_by LEFT JOIN sites s ON s.id = t.site_id
          WHERE t.organization_id = $1 ORDER BY t.created_at DESC LIMIT 50",
    )
    .bind(org)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, site, created_by, created_at, expires_at, uses, max_uses, revoked)| {
                EnrollmentTokenView {
                    id,
                    site,
                    created_by,
                    created_at,
                    expires_at,
                    uses,
                    max_uses,
                    revoked,
                }
            },
        )
        .collect())
}

pub async fn audit(state: &Shared) -> sqlx::Result<Vec<AuditRow>> {
    let rows: Vec<(i64, OffsetDateTime, String, String, String, Option<String>, Option<Uuid>, String, Option<String>, Value)> =
        sqlx::query_as(
            "SELECT a.id, a.at, a.actor_label, a.channel, a.action, a.target_type, a.target_id, a.outcome, o.name, a.detail
               FROM audit_events a LEFT JOIN organizations o ON o.id = a.organization_id
              ORDER BY a.id DESC LIMIT 200",
        )
        .fetch_all(&state.db)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                at,
                actor_label,
                channel,
                action,
                target_type,
                target_id,
                outcome,
                organization,
                detail,
            )| AuditRow {
                id,
                at,
                actor_label,
                channel,
                action,
                target_type,
                target_id,
                outcome,
                organization,
                detail,
            },
        )
        .collect())
}

pub async fn users(state: &Shared) -> sqlx::Result<Vec<UserRow>> {
    let rows: Vec<(Uuid, String, String, String, Vec<String>, bool, bool)> = sqlx::query_as(
        "SELECT u.id, u.email, u.display_name, u.role,
                coalesce(array_agg(o.name ORDER BY o.name) FILTER (WHERE o.name IS NOT NULL), '{}'),
                u.disabled_at IS NOT NULL, u.totp_enabled_at IS NOT NULL
           FROM users u LEFT JOIN user_organizations uo ON uo.user_id = u.id LEFT JOIN organizations o ON o.id = uo.organization_id
          GROUP BY u.id ORDER BY u.email",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, email, display_name, role, organizations, disabled, mfa)| UserRow {
                id,
                email,
                display_name,
                role,
                organizations,
                disabled,
                mfa,
            },
        )
        .collect())
}

pub async fn api_tokens(state: &Shared) -> sqlx::Result<Vec<ApiTokenRow>> {
    let rows: Vec<(Uuid, String, String, String, Vec<String>, OffsetDateTime, Option<OffsetDateTime>, Option<OffsetDateTime>, bool)> =
        sqlx::query_as(
            "SELECT t.id, u.email, t.name, t.prefix, t.scopes, t.created_at, t.last_used_at, t.expires_at, t.revoked_at IS NOT NULL
               FROM api_tokens t JOIN users u ON u.id = t.user_id ORDER BY t.created_at DESC",
        )
        .fetch_all(&state.db)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, owner, name, prefix, scopes, created_at, last_used_at, expires_at, revoked)| {
                ApiTokenRow {
                    id,
                    owner,
                    name,
                    prefix,
                    scopes,
                    created_at,
                    last_used_at,
                    expires_at,
                    revoked,
                }
            },
        )
        .collect())
}
