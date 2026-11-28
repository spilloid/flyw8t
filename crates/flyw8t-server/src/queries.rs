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

/// `q` with LIKE's own characters escaped, so it matches only itself.
pub(crate) fn like_escape(q: &str) -> String {
    q.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// A "contains" pattern for a lowercased column.
pub(crate) fn like_pattern(q: &str) -> String {
    format!("%{}%", like_escape(&q.trim().to_lowercase()))
}

type DeviceTuple = (
    Uuid,
    String,
    Option<String>,
    Vec<String>,
    Uuid,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
    Option<Value>,
);

/// The parts of an inventory report the device list shows. Read leniently: a snapshot that does not fit (an older
/// agent, or a device sending nonsense) gives no health figures; it never fails the page.
#[derive(serde::Deserialize)]
struct HealthWire {
    #[serde(with = "time::serde::rfc3339")]
    collected_at: OffsetDateTime,
    /// The server's own receipt time, not the device's claim.
    #[serde(with = "time::serde::rfc3339")]
    received_at: OffsetDateTime,
    hardware: flyw8t_protocol::inventory::Hardware,
    disks: Vec<flyw8t_protocol::inventory::Disk>,
    uptime_secs: u64,
}

fn device_health(v: Option<Value>) -> Option<DeviceHealth> {
    let w: HealthWire = serde_json::from_value(v?).ok()?;
    let fullest_disk = w
        .disks
        .into_iter()
        .filter(|d| !d.removable && d.total_bytes > 0)
        .map(|d| DiskUse {
            mount_point: d.mount_point,
            total_bytes: d.total_bytes,
            available_bytes: d.available_bytes,
        })
        // The fullest by share used; between equals, the one with the least room left.
        .max_by(|a, b| {
            a.used_percent()
                .cmp(&b.used_percent())
                .then(b.available_bytes.cmp(&a.available_bytes))
        });
    Some(DeviceHealth {
        collected_at: w.collected_at,
        received_at: w.received_at,
        memory_total_bytes: w.hardware.memory_total_bytes,
        memory_available_bytes: w.hardware.memory_available_bytes,
        uptime_secs: w.uptime_secs,
        fullest_disk,
    })
}

const DEVICE_SELECT: &str = "
    SELECT d.id, d.hostname, d.display_name,
           coalesce((SELECT array_agg(t.tag ORDER BY t.tag) FROM device_tags t WHERE t.device_id = d.id), '{}'),
           o.id, o.name, s.name, inv.os, d.agent_version, d.last_seen_at, d.last_connected_at, d.retired_at,
           inv.health
      FROM devices d
      JOIN organizations o ON o.id = d.organization_id
      LEFT JOIN sites s ON s.id = d.site_id
      LEFT JOIN LATERAL (
          SELECT coalesce(i.data->'os'->>'long_version', i.data->'os'->>'name', i.data->'os'->>'family') AS os,
                 jsonb_build_object('collected_at', i.data->'collected_at', 'received_at', i.received_at, 'hardware', i.data->'hardware',
                                    'disks', i.data->'disks', 'uptime_secs', i.data->'uptime_secs') AS health
            FROM inventory_snapshots i WHERE i.device_id = d.id ORDER BY i.received_at DESC LIMIT 1
      ) inv ON true";

fn device_row(state: &Shared, t: DeviceTuple) -> DeviceRow {
    let (
        id,
        hostname,
        display_name,
        tags,
        org_id,
        org_name,
        site,
        os,
        agent_version,
        last_seen,
        last_connected,
        retired,
        health,
    ) = t;
    DeviceRow {
        id,
        hostname,
        display_name,
        tags,
        organization: OrgRef {
            id: org_id,
            name: org_name,
        },
        site,
        os,
        agent_version,
        connection: connection(state, id, last_seen, last_connected),
        retired: retired.is_some(),
        health: device_health(health),
    }
}

pub async fn devices(
    state: &Shared,
    p: &Principal,
    f: &DeviceFilter,
) -> sqlx::Result<Vec<DeviceRow>> {
    // The connection and attention filters and both orders are applied here, not in SQL (connection state is the
    // registry's). With any of them, read past one page first, so a device far down the alphabet is not missed.
    let scan = if f.connection.is_empty() && !f.attention && f.sort.is_empty() {
        DEVICE_PAGE_LIMIT
    } else {
        DEVICE_SCAN_LIMIT
    };
    let mut rows = scan_devices(state, p, f, scan).await?;
    rows.truncate(DEVICE_PAGE_LIMIT);
    Ok(rows)
}

/// The devices matching `f`, filtered and ordered, from the first `scan` by name that SQL selects.
async fn scan_devices(
    state: &Shared,
    p: &Principal,
    f: &DeviceFilter,
    scan: usize,
) -> sqlx::Result<Vec<DeviceRow>> {
    let (all, orgs) = p.scope();
    let q = (!f.q.trim().is_empty()).then(|| like_pattern(&f.q));
    let rows: Vec<DeviceTuple> = sqlx::query_as(&format!(
        "{DEVICE_SELECT}
          WHERE ($1 OR d.organization_id = ANY($2))
            AND ($3::text IS NULL OR lower(d.hostname) LIKE $3 OR lower(d.display_name) LIKE $3
                 OR EXISTS (SELECT 1 FROM device_tags t WHERE t.device_id = d.id AND t.tag LIKE $3))
            AND ($4::uuid IS NULL OR d.organization_id = $4)
            AND ($5::text IS NULL OR EXISTS (SELECT 1 FROM device_tags t WHERE t.device_id = d.id AND t.tag = $5))
            AND CASE $6 WHEN 'all' THEN true WHEN 'retired' THEN d.retired_at IS NOT NULL ELSE d.retired_at IS NULL END
          ORDER BY lower(coalesce(d.display_name, d.hostname)), d.id LIMIT $7"
    ))
    .bind(all)
    .bind(&orgs)
    .bind(q)
    .bind(f.organization)
    .bind((!f.tag.is_empty()).then_some(f.tag.as_str()))
    .bind(f.status.as_str())
    .bind(scan as i64)
    .fetch_all(&state.db)
    .await?;
    let now = OffsetDateTime::now_utc();
    let mut rows: Vec<DeviceRow> = rows
        .into_iter()
        .map(|t| device_row(state, t))
        .filter(|d| match f.connection.as_str() {
            "connected" => matches!(d.connection, Connection::Connected { .. }),
            "offline" => !matches!(d.connection, Connection::Connected { .. }),
            _ => true,
        })
        .filter(|d| !f.attention || !d.concerns(now).is_empty())
        .collect();
    // Both orders are stable, so devices that tie stay in name order.
    match f.sort.as_str() {
        // Longest silent first: never connected, then the oldest last message, then the connected.
        "seen" => rows.sort_by_key(|d| match &d.connection {
            Connection::NeverConnected | Connection::Disconnected { last_seen: None } => (0, 0),
            Connection::Disconnected { last_seen: Some(t) } => (1, t.unix_timestamp()),
            Connection::Connected { .. } => (2, 0),
        }),
        // Fullest disk first; devices with no disk figures last.
        "disk" => rows.sort_by_key(|d| {
            std::cmp::Reverse(
                d.health
                    .as_ref()
                    .and_then(|h| h.fullest_disk.as_ref())
                    .map(|disk| disk.used_percent() as i16)
                    .unwrap_or(-1),
            )
        }),
        _ => {}
    }
    Ok(rows)
}

/// One device's list row, if the caller can see it.
pub async fn device_summary(
    state: &Shared,
    p: &Principal,
    id: Uuid,
) -> sqlx::Result<Option<DeviceRow>> {
    let (all, orgs) = p.scope();
    let row: Option<DeviceTuple> = sqlx::query_as(&format!(
        "{DEVICE_SELECT} WHERE d.id = $1 AND ($2 OR d.organization_id = ANY($3))"
    ))
    .bind(id)
    .bind(all)
    .bind(&orgs)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|t| device_row(state, t)))
}

pub struct ActivityCursor(OffsetDateTime, i16, i64);

impl ActivityCursor {
    pub fn parse(value: &str) -> Option<Self> {
        let (at, rest) = value.split_once(':')?;
        let (source, id) = rest.split_once(':')?;
        let at = OffsetDateTime::from_unix_timestamp_nanos(at.parse().ok()?).ok()?;
        let source = source.parse().ok().filter(|n| matches!(*n, 0 | 1))?;
        let id = id.parse().ok().filter(|n| *n > 0)?;
        Some(Self(at, source, id))
    }

    pub fn as_query_value(&self) -> String {
        format!("{}:{}:{}", self.0.unix_timestamp_nanos(), self.1, self.2)
    }
}

/// Combine durable records using the server's event time. The two tables have independent IDs.
pub async fn device_activity(
    state: &Shared,
    p: &Principal,
    device: Uuid,
    before: Option<ActivityCursor>,
) -> sqlx::Result<(Vec<DeviceActivityEvent>, Option<ActivityCursor>)> {
    const PAGE: usize = 50;
    type Row = (
        OffsetDateTime,
        i16,
        i64,
        String,
        String,
        String,
        Option<Uuid>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let (all, orgs) = p.scope();
    let (at, source, id) = before.map_or((None, None, None), |c| (Some(c.0), Some(c.1), Some(c.2)));
    let rows: Vec<Row> = sqlx::query_as(
        "WITH scoped_device AS (
             SELECT id, organization_id, enrolled_at FROM devices WHERE id = $1 AND ($2 OR organization_id = ANY($3))
         ), device_jobs AS (
             SELECT j.id, j.organization_id,
                    CASE WHEN j.action = 'script.run' THEN
                        coalesce((j.request ->> 'script') || ' · revision ' ||
                                 (j.request ->> 'revision'), j.action)
                    ELSE j.action END AS action
               FROM jobs j JOIN scoped_device d ON j.device_id = d.id AND j.organization_id = d.organization_id
         ), activity AS (
             SELECT a.at, 0::smallint AS source, a.id,
                    CASE WHEN a.action IN ('device.support.connected', 'device.support.ended')
                         THEN coalesce(a.detail->>'technician', a.actor_label) ELSE a.actor_label END AS actor,
                    CASE a.action
                         WHEN 'device.agent_update_policy' THEN a.action || '.' || (a.detail->>'to_opted_out')
                         WHEN 'device.agent_update_preflight' THEN a.action || '.' || (a.detail->>'policy')
                         WHEN 'device.background_terminal_policy.result' THEN
                             CASE WHEN a.detail->>'status' IN ('enabled', 'disabled') AND a.outcome = 'success'
                                  THEN a.action || '.' || (a.detail->>'status') ELSE a.action END
                         ELSE a.action END AS action,
                    a.outcome, NULL::uuid AS job, NULL::text AS job_action,
                    CASE WHEN a.action IN ('device.support.connected', 'device.support.ended')
                              AND ($2 OR a.detail->>'technician_id' = $8)
                         THEN a.detail->>'session_id' END AS support_session,
                    CASE a.action
                         WHEN 'device.connect' THEN a.detail->>'agent_version'
                         WHEN 'device.agent_update_preflight' THEN a.detail->'device_reported_candidate'->>'version'
                         END AS reported_version
               FROM audit_events a JOIN scoped_device d ON a.target_id = d.id
              WHERE a.target_type = 'device' AND (
                    a.organization_id = d.organization_id OR (
                        a.organization_id IS NULL AND a.actor_type = 'device' AND a.actor_id = d.id
                        AND a.action IN ('device.connect', 'device.disconnect')
                    )
              )
             UNION ALL
             SELECT a.at, 0::smallint, a.id, a.actor_label, a.action || '.' || (a.detail->>'to_enabled'),
                    a.outcome, NULL::uuid, NULL::text, NULL::text, NULL::text
               FROM audit_events a JOIN scoped_device d ON a.organization_id = d.organization_id
              WHERE a.target_type = 'organization' AND a.action = 'organization.agent_update_policy'
                AND a.target_id = d.organization_id AND a.at >= d.enrolled_at
             UNION ALL
             SELECT a.at, 0::smallint, a.id, a.actor_label, a.action, a.outcome, j.id, j.action, NULL::text, NULL::text
               FROM audit_events a JOIN device_jobs j ON a.target_id = j.id AND a.organization_id = j.organization_id
              WHERE a.target_type = 'job'
             UNION ALL
             SELECT e.at, 1::smallint, e.id, e.actor, e.to_state, 'recorded', j.id, j.action, NULL::text, NULL::text
               FROM job_events e JOIN device_jobs j ON e.job_id = j.id
              WHERE e.to_state IN ('dispatched', 'acknowledged', 'running', 'completed', 'failed',
                                   'timed_out', 'cancelled', 'expired', 'outcome_unknown')
                 OR (e.from_state = 'dispatched' AND e.to_state = 'queued')
         )
         SELECT at, source, id, actor, action, outcome, job, job_action, support_session, reported_version FROM activity
          WHERE $4::timestamptz IS NULL OR (at, source, id) < ($4, $5, $6)
          ORDER BY at DESC, source DESC, id DESC LIMIT $7",
    )
    .bind(device)
    .bind(all)
    .bind(&orgs)
    .bind(at)
    .bind(source)
    .bind(id)
    .bind((PAGE + 1) as i64)
    .bind(p.user_id.to_string())
    .fetch_all(&state.db)
    .await?;
    let older = (rows.len() > PAGE).then(|| {
        let (at, source, id, ..) = rows[PAGE - 1];
        ActivityCursor(at, source, id)
    });
    let events = rows
        .into_iter()
        .take(PAGE)
        .map(
            |(
                at,
                _,
                _,
                actor,
                action,
                outcome,
                job,
                job_action,
                support_session,
                reported_version,
            )| {
                let label = match action.as_str() {
                    "device.enroll" => "Device enrolled",
                    "device.connect" => "Agent authenticated",
                    "device.disconnect" => "Agent connection closed",
                    "device.update" => "Device details changed",
                    "device.agent_update_policy.true" => {
                        "Device opted out of automatic agent updates"
                    }
                    "device.agent_update_policy.false" => {
                        "Device follows the organization update policy"
                    }
                    "organization.agent_update_policy.true" => {
                        "Organization enabled automatic agent updates"
                    }
                    "organization.agent_update_policy.false" => {
                        "Organization paused automatic agent updates"
                    }
                    "device.agent_update_preflight.enabled" => {
                        "Fleet policy allowed the update preflight"
                    }
                    "device.agent_update_preflight.organization_paused" => {
                        "Update preflight blocked by organization policy"
                    }
                    "device.agent_update_preflight.device_opted_out" => {
                        "Update preflight blocked by device opt-out"
                    }
                    "device.revoke" => "Device credential revoked",
                    "device.retire" => "Device retired",
                    "device.physical_console.requested" => "Physical console check requested",
                    "device.physical_console.result" => "Physical console check recorded",
                    "device.background_terminal_policy.requested" => {
                        "Background terminal policy check requested"
                    }
                    "device.background_terminal_policy.result.enabled" => {
                        "Agent reported background terminal policy enabled"
                    }
                    "device.background_terminal_policy.result.disabled" => {
                        "Agent reported background terminal policy disabled"
                    }
                    "device.background_terminal_policy.result" => {
                        "Background terminal policy check recorded"
                    }
                    "device.background_terminal_admission.requested" => {
                        "Background terminal access confirmation requested"
                    }
                    "device.background_terminal_admission.result" => {
                        "Background terminal access confirmation recorded"
                    }
                    "device.support.connected" => "Linked screen share connected",
                    "device.support.ended" => "Linked screen share ended",
                    "job.create" => "Job requested",
                    "job.authorize" => "Script run authorization submitted",
                    "script.schedule.create" => "Script schedule created",
                    "script.schedule.cancel" => "Script schedule canceled",
                    "job.cancel" => "Job cancellation requested",
                    "dispatched" => "Job dispatched",
                    "acknowledged" => "Agent accepted the job",
                    "running" => "Agent started the job",
                    "completed" => "Agent reported job completion",
                    "failed" => "Job failed",
                    "timed_out" => "Job timed out",
                    "cancelled" => "Job canceled",
                    "script_approval_withdrawn" => "Script approval withdrawn before dispatch",
                    "expired" => "Job expired before dispatch",
                    "outcome_unknown" => "Job outcome unknown",
                    "queued" => "Job returned to queue",
                    other => other,
                };
                DeviceActivityEvent {
                    at,
                    action: match outcome.as_str() {
                        "failed" | "denied" => format!("{label} ({outcome})"),
                        _ => label.to_string(),
                    },
                    actor: actor.strip_prefix("user:").unwrap_or(&actor).to_string(),
                    job,
                    job_action,
                    support_session: support_session.and_then(|id| id.parse().ok()),
                    version_report: reported_version
                        .filter(|v| {
                            !v.is_empty()
                                && v.len() <= 50
                                && v.bytes().all(|b| {
                                    b.is_ascii_alphanumeric()
                                        || matches!(b, b'.' | b'-' | b'+' | b'_')
                                })
                        })
                        .map(|version| {
                            if action == "device.connect" {
                                format!("Agent reported version {version}")
                            } else {
                                format!("Agent reported candidate version {version}")
                            }
                        }),
                }
            },
        )
        .collect();
    Ok((events, older))
}

pub async fn inventory_history(
    state: &Shared,
    p: &Principal,
    id: Uuid,
) -> sqlx::Result<Vec<InventorySample>> {
    use flyw8t_protocol::inventory::{Disk, Hardware};
    let (all, orgs) = p.scope();
    let samples: Vec<(OffsetDateTime, Option<Value>, Option<Value>)> = sqlx::query_as(
        "SELECT i.received_at, i.data->'hardware', i.data->'disks'
         FROM inventory_snapshots i JOIN devices d ON d.id = i.device_id
         WHERE d.id = $1 AND ($2 OR d.organization_id = ANY($3))
         ORDER BY i.received_at DESC, i.id DESC LIMIT 24",
    )
    .bind(id)
    .bind(all)
    .bind(orgs)
    .fetch_all(&state.db)
    .await?;
    Ok(samples
        .into_iter()
        .rev()
        .map(|(received_at, hardware, disks)| {
            let memory_used = hardware
                .and_then(|data| serde_json::from_value::<Hardware>(data).ok())
                .filter(|h| h.memory_total_bytes > 0)
                .map(|h| used_percent(h.memory_total_bytes, h.memory_available_bytes));
            let disk_used = disks
                .and_then(|data| serde_json::from_value::<Vec<Disk>>(data).ok())
                .unwrap_or_default()
                .into_iter()
                .filter(|d| !d.removable && d.total_bytes > 0)
                .map(|d| {
                    (
                        d.mount_point,
                        used_percent(d.total_bytes, d.available_bytes),
                    )
                })
                .collect();
            InventorySample {
                received_at,
                memory_used,
                disk_used,
            }
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
    let org_id = row.organization.id;
    let (enrolled_at, notes, site_id, os_family, device_opted_out, organization_enabled):
        (OffsetDateTime, String, Option<Uuid>, String, bool, bool) = sqlx::query_as(
        "SELECT d.enrolled_at, d.notes, d.site_id, d.os_family, d.agent_updates_opt_out, o.automatic_agent_updates
         FROM devices d JOIN organizations o ON o.id = d.organization_id WHERE d.id = $1 AND d.organization_id = $2",
    )
    .bind(id)
    .bind(org_id)
    .fetch_one(&state.db)
    .await?;
    let sites = sites(state, org_id).await?;
    let fields = crate::fields::resolve(state, p, org_id, site_id, Some(id)).await?;
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
        os_family,
        enrolled_at,
        inventory,
        credential,
        recent_jobs,
        remote_access: state.remote_access.describe(id),
        notes,
        site_id,
        sites,
        fields,
        agent_update_policy: AgentUpdatePolicy {
            organization_enabled,
            device_opted_out,
        },
    }))
}

#[derive(Default)]
pub struct JobQuery {
    pub device: Option<Uuid>,
    pub state: Option<ExecState>,
    pub attention_since: Option<OffsetDateTime>,
    pub batch: Option<Uuid>,
    pub limit: i64,
    /// A catalog action's name.
    pub action: Option<String>,
    /// Rows to skip, newest first: the pages before this one.
    pub offset: i64,
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
            AND ($7::uuid IS NULL OR j.batch_id = $7)
            AND ($8::text IS NULL OR j.action = $8)
          ORDER BY j.created_at DESC, j.id DESC LIMIT $6 OFFSET $9"
    ))
    .bind(all)
    .bind(&orgs)
    .bind(q.device)
    .bind(q.state.map(ExecState::as_str))
    .bind(q.attention_since)
    .bind(q.limit.clamp(1, 500))
    .bind(q.batch)
    .bind(q.action.as_deref())
    .bind(q.offset.max(0))
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
    let now = OffsetDateTime::now_utc();
    let since = now - time::Duration::hours(24);
    // Device concerns come from the same rows, in the same scope, as the device list.
    let active = scan_devices(state, p, &DeviceFilter::default(), DEVICE_SCAN_LIMIT).await?;
    let devices_truncated = (active.len() as i64) < ids.len() as i64;
    let mut concerned: Vec<DeviceAttention> = active
        .into_iter()
        .filter_map(|device| {
            let concerns = device.concerns(now);
            (!concerns.is_empty()).then_some(DeviceAttention { device, concerns })
        })
        .collect();
    let device_attention_total = concerned.len() as i64;
    // Most concerns first; the list is already in name order and the sort is stable.
    concerned.sort_by_key(|a| std::cmp::Reverse(a.concerns.len()));
    concerned.truncate(Overview::DEVICE_ATTENTION_LIMIT);
    let agent_versions: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT agent_version, count(*) FROM devices
          WHERE retired_at IS NULL AND ($1 OR organization_id = ANY($2))
          GROUP BY agent_version ORDER BY count(*) DESC, agent_version NULLS LAST LIMIT 6",
    )
    .bind(all)
    .bind(&orgs)
    .fetch_all(&state.db)
    .await?;
    Ok(Overview {
        organizations: org_refs(state, p).await?,
        device_attention: concerned,
        device_attention_total,
        agent_versions,
        devices_truncated,
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

/// The sites of one organization (callers check the organization is in scope).
pub async fn sites(state: &Shared, org: Uuid) -> sqlx::Result<Vec<OrgRef>> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM sites WHERE organization_id = $1 ORDER BY lower(name)",
    )
    .bind(org)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name)| OrgRef { id, name })
        .collect())
}

/// Every tag in use on devices the caller can see, for the filter.
pub async fn tags(state: &Shared, p: &Principal) -> sqlx::Result<Vec<String>> {
    let (all, orgs) = p.scope();
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT t.tag FROM device_tags t JOIN devices d ON d.id = t.device_id
          WHERE ($1 OR d.organization_id = ANY($2)) ORDER BY t.tag",
    )
    .bind(all)
    .bind(&orgs)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|(t,)| t).collect())
}

/// Totals for one batch of jobs, within the caller's scope.
pub async fn batch(state: &Shared, p: &Principal, id: Uuid) -> sqlx::Result<Option<BatchSummary>> {
    let (all, orgs) = p.scope();
    let (total, succeeded, failed, unknown): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*),
                count(*) FILTER (WHERE state = 'completed' AND verification IN ('verified', 'not_applicable')),
                count(*) FILTER (WHERE state IN ('failed', 'timed_out', 'expired', 'cancelled')
                                    OR (state = 'completed' AND verification = 'failed')),
                count(*) FILTER (WHERE state = 'outcome_unknown')
           FROM jobs WHERE batch_id = $1 AND ($2 OR organization_id = ANY($3))",
    )
    .bind(id)
    .bind(all)
    .bind(&orgs)
    .fetch_one(&state.db)
    .await?;
    if total == 0 {
        return Ok(None);
    }
    Ok(Some(BatchSummary {
        id,
        total,
        succeeded,
        failed,
        unknown,
        in_progress: total - succeeded - failed - unknown,
    }))
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
    let rows: Vec<(Uuid, String, OffsetDateTime, i64, bool)> = sqlx::query_as(
        "SELECT o.id, o.name, o.created_at, (SELECT count(*) FROM devices d WHERE d.organization_id = o.id AND d.retired_at IS NULL),
                o.automatic_agent_updates
           FROM organizations o WHERE ($1 OR o.id = ANY($2)) AND ($3::uuid IS NULL OR o.id = $3) ORDER BY lower(o.name)",
    )
    .bind(all)
    .bind(&orgs)
    .bind(only)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, name, created_at, device_count, automatic_agent_updates) in rows {
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
            automatic_agent_updates,
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

/// Audit events a page holds.
pub const AUDIT_PAGE_SIZE: i64 = 100;
/// Audit events one export holds at most.
pub const AUDIT_EXPORT_LIMIT: i64 = 10_000;

/// Audit events matching `f`, newest first, within the caller's organizations. An event that belongs to no
/// organization (a sign-in, a user change) is visible only to those who see every organization.
pub async fn audit(
    state: &Shared,
    p: &Principal,
    f: &AuditFilter,
    limit: i64,
) -> sqlx::Result<Vec<AuditRow>> {
    type Row = (
        i64,
        OffsetDateTime,
        String,
        String,
        String,
        Option<String>,
        Option<Uuid>,
        String,
        Option<String>,
        Value,
        Option<String>,
        Option<String>,
    );
    let (all, orgs) = p.scope();
    let actor = f.actor.trim();
    let action = f.action.trim();
    let from = f.from.map(|d| d.midnight().assume_utc());
    // The day after `to`, exclusive: the whole of that day is included.
    let until =
        f.to.and_then(|d| d.next_day())
            .map(|d| d.midnight().assume_utc());
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT a.id, a.at, a.actor_label, a.channel, a.action, a.target_type, a.target_id, a.outcome, o.name,
                a.detail, a.client_ip, a.credential
           FROM audit_events a LEFT JOIN organizations o ON o.id = a.organization_id
          WHERE ($1 OR a.organization_id = ANY($2))
            AND ($3 = '' OR lower(a.actor_label) LIKE $4)
            AND ($5 = '' OR a.action LIKE $6)
            AND ($7::text IS NULL OR a.outcome = $7)
            AND ($8::uuid IS NULL OR a.organization_id = $8)
            AND ($9::timestamptz IS NULL OR a.at >= $9)
            AND ($10::timestamptz IS NULL OR a.at < $10)
            AND ($11::bigint IS NULL OR a.id < $11)
          ORDER BY a.id DESC LIMIT $12",
    )
    .bind(all)
    .bind(&orgs)
    .bind(actor)
    .bind(like_pattern(actor))
    .bind(action)
    .bind(format!("{}%", like_escape(action)))
    .bind(f.outcome.as_deref())
    .bind(f.organization)
    .bind(from)
    .bind(until)
    .bind(f.before)
    .bind(limit.clamp(1, AUDIT_EXPORT_LIMIT + 1))
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
                client_ip,
                credential,
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
                client_ip,
                credential,
            },
        )
        .collect())
}

pub async fn users(state: &Shared) -> sqlx::Result<Vec<UserRow>> {
    let rows: Vec<(Uuid, String, String, String, Vec<String>, bool, bool, i64, i64)> = sqlx::query_as(
        "SELECT u.id, u.email, u.display_name, u.role,
                coalesce(array_agg(o.name ORDER BY o.name) FILTER (WHERE o.name IS NOT NULL), '{}'),
                u.disabled_at IS NOT NULL, u.totp_enabled_at IS NOT NULL,
                (SELECT count(*) FROM webauthn_credentials w WHERE w.user_id = u.id),
                (SELECT count(*) FROM sessions s WHERE s.user_id = u.id AND s.revoked_at IS NULL AND s.expires_at > now())
           FROM users u LEFT JOIN user_organizations uo ON uo.user_id = u.id LEFT JOIN organizations o ON o.id = uo.organization_id
          GROUP BY u.id ORDER BY u.email",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, email, display_name, role, organizations, disabled, mfa, passkeys, sessions)| {
                UserRow {
                    id,
                    email,
                    display_name,
                    role,
                    organizations,
                    disabled,
                    mfa,
                    passkeys,
                    sessions,
                }
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
