//! View models: plain data the server fills from the database and the views render.
//! The same structs serialize as the JSON API's response bodies.

use flyw8t_domain::job::{ExecState, Verification};
use flyw8t_protocol::inventory::InventoryReport;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// Who is looking, and what the page chrome needs.
#[derive(Debug, Clone)]
pub struct PageCtx {
    pub user_name: String,
    pub role: &'static str,
    pub csrf: String,
    pub now: OffsetDateTime,
    pub can_run: bool,
    pub is_admin: bool,
    pub can_view_device_activity: bool,
    pub can_enroll: bool,
    pub can_support: bool,
    /// May start sessions that include remote control (ADR-0012).
    pub can_control: bool,
    /// May rename, tag, annotate and re-site devices.
    pub can_manage_devices: bool,
    /// May retire devices.
    pub can_retire: bool,
    /// May read the script library.
    pub can_view_scripts: bool,
    pub flash: Option<Flash>,
    /// The server's own version, shown in the frame.
    pub version: &'static str,
    /// The operator's other products, as configured (`FLYW8T_FAMILY_LINKS`): links only, never a shared sign-in.
    pub family: Vec<FamilyLink>,
}

/// One configured link to another product of the family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyLink {
    pub label: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct Flash {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrgRef {
    pub id: Uuid,
    pub name: String,
}

/// A site's page: where it belongs and its devices (as id and name).
#[derive(Debug, Clone, Serialize)]
pub struct SitePage {
    pub id: Uuid,
    pub name: String,
    pub organization: OrgRef,
    pub devices: Vec<OrgRef>,
    pub network_assets: i64,
    pub network_collectors: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkSite {
    pub id: Uuid,
    pub name: String,
    pub organization: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkCollector {
    pub id: Uuid,
    pub name: String,
    pub site: NetworkSite,
    pub cidr: String,
    pub interval_secs: i32,
    pub heartbeat_at: Option<OffsetDateTime>,
    pub inventory_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    pub version: Option<String>,
    pub portglass_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkAsset {
    pub id: Uuid,
    pub site: NetworkSite,
    pub collector_id: Uuid,
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: String,
    pub vendor: String,
    pub device_type: String,
    pub status: String,
    pub open_ports: Vec<i32>,
    pub first_seen_at: OffsetDateTime,
    pub collected_at: OffsetDateTime,
    pub received_at: OffsetDateTime,
    pub interval_secs: i32,
    pub collector_revoked: bool,
}

#[derive(Debug, Clone)]
pub struct NetworkWorkspace {
    pub sites: Vec<NetworkSite>,
    pub selected_site: Option<Uuid>,
    pub query: String,
    pub page: u32,
    pub total: i64,
    pub assets: Vec<NetworkAsset>,
    pub collectors: Vec<NetworkCollector>,
}

#[derive(Debug, Clone)]
pub struct NetworkHistory {
    pub collected_at: OffsetDateTime,
    pub received_at: OffsetDateTime,
    pub collector: String,
    pub observation: String,
}

/// Whether the server holds a live, authenticated connection to the device right now.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Connection {
    Connected {
        #[serde(with = "time::serde::rfc3339")]
        since: OffsetDateTime,
    },
    Disconnected {
        #[serde(with = "time::serde::rfc3339::option")]
        last_seen: Option<OffsetDateTime>,
    },
    NeverConnected,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceRow {
    pub id: Uuid,
    /// What the device reports. Never used for authorization.
    pub hostname: String,
    /// What people call it, if someone named it.
    pub display_name: Option<String>,
    pub tags: Vec<String>,
    pub organization: OrgRef,
    pub site: Option<String>,
    pub os: Option<String>,
    pub agent_version: Option<String>,
    pub connection: Connection,
    pub retired: bool,
    /// Disk, memory and uptime from the device's latest inventory, if it has sent one that can be read.
    pub health: Option<DeviceHealth>,
}

/// What a device last said about its own disks, memory and uptime. A claim made by the endpoint, as old as
/// `collected_at`: never live, and never used for authorization.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceHealth {
    #[serde(with = "time::serde::rfc3339")]
    pub collected_at: OffsetDateTime,
    /// When the server received that report. Staleness is judged by this, never by the device's clock.
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
    pub uptime_secs: u64,
    /// The fixed disk with the largest share of its space used. Removable disks are left out: a full installer
    /// stick is not a fault.
    pub fullest_disk: Option<DiskUse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskUse {
    pub mount_point: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

/// Percent of `total` that is not `available`, rounded down; 0 when `total` is 0.
pub fn used_percent(total: u64, available: u64) -> u8 {
    let used = total.saturating_sub(available) as u128;
    used.saturating_mul(100)
        .checked_div(total as u128)
        .unwrap_or(0)
        .min(100) as u8
}

impl DiskUse {
    pub fn used_percent(&self) -> u8 {
        used_percent(self.total_bytes, self.available_bytes)
    }
}

impl DeviceHealth {
    pub fn memory_used_percent(&self) -> u8 {
        used_percent(self.memory_total_bytes, self.memory_available_bytes)
    }
}

/// A fixed disk this full is listed under "needs attention".
pub const DISK_NEARLY_FULL_PERCENT: u8 = 90;
/// A device not heard from for this long is listed under "needs attention".
pub const OFFLINE_ATTENTION_DAYS: i64 = 7;
/// A connected device whose newest inventory is older than this is listed under "needs attention". The agent sends
/// inventory every 6 hours; the device page calls it stale at the same age.
pub const STALE_INVENTORY_DAYS: i64 = 2;

/// Why a device is listed under "needs attention".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Concern {
    /// Enrolled, but it has never connected.
    NeverConnected,
    /// Not connected, and not heard from for `OFFLINE_ATTENTION_DAYS` or more.
    LongOffline { days: i64 },
    /// Its fullest fixed disk is at or above `DISK_NEARLY_FULL_PERCENT`, as of its last inventory.
    DiskNearlyFull {
        mount_point: String,
        used_percent: u8,
    },
    /// Connected, but the server received its newest inventory `STALE_INVENTORY_DAYS` or more ago.
    StaleInventory { days: i64 },
    /// Connected for `STALE_INVENTORY_DAYS` or more without sending an inventory the server can read.
    NoInventory { days: i64 },
}

/// The device list shows at most this many devices.
pub const DEVICE_PAGE_LIMIT: usize = 2000;
/// Filters, orders and the overview's figures are worked out over at most this many devices, by name.
pub const DEVICE_SCAN_LIMIT: usize = 50_000;

impl DeviceRow {
    /// What about this device wants a person's attention, most serious first. Retired devices have none. Disk
    /// fullness is as old as the inventory it comes from; the page says so.
    pub fn concerns(&self, now: OffsetDateTime) -> Vec<Concern> {
        let mut out = Vec::new();
        if self.retired {
            return out;
        }
        if let Some(disk) = self.health.as_ref().and_then(|h| h.fullest_disk.as_ref()) {
            if disk.used_percent() >= DISK_NEARLY_FULL_PERCENT {
                out.push(Concern::DiskNearlyFull {
                    mount_point: disk.mount_point.clone(),
                    used_percent: disk.used_percent(),
                });
            }
        }
        match &self.connection {
            Connection::NeverConnected | Connection::Disconnected { last_seen: None } => {
                out.push(Concern::NeverConnected)
            }
            Connection::Disconnected { last_seen: Some(t) } => {
                let days = (now - *t).whole_days();
                if days >= OFFLINE_ATTENTION_DAYS {
                    out.push(Concern::LongOffline { days });
                }
            }
            // By the server's clock, so a device with a wrong clock cannot look fresh.
            Connection::Connected { since } => match &self.health {
                Some(h) => {
                    let days = (now - h.received_at).whole_days();
                    if days >= STALE_INVENTORY_DAYS {
                        out.push(Concern::StaleInventory { days });
                    }
                }
                None => {
                    let days = (now - *since).whole_days();
                    if days >= STALE_INVENTORY_DAYS {
                        out.push(Concern::NoInventory { days });
                    }
                }
            },
        }
        out
    }

    /// The name to show: the chosen one, else the hostname.
    pub fn name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.hostname)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InventoryView {
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    pub source: String,
    pub report: InventoryReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialView {
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceDetail {
    #[serde(flatten)]
    pub row: DeviceRow,
    /// OS family reported on enrollment and refreshed with inventory.
    #[serde(skip)]
    pub os_family: String,
    #[serde(with = "time::serde::rfc3339")]
    pub enrolled_at: OffsetDateTime,
    pub inventory: Option<InventoryView>,
    pub credential: Option<CredentialView>,
    pub recent_jobs: Vec<JobRow>,
    /// Remote-access provider status for this device (see docs/decisions/ADR-0006).
    pub remote_access: String,
    pub notes: String,
    pub site_id: Option<Uuid>,
    /// Sites of the device's organization, for choosing one.
    #[serde(skip)]
    pub sites: Vec<OrgRef>,
    /// Custom fields as they resolve for this device (secrets masked).
    pub fields: Vec<ResolvedField>,
    #[serde(skip)]
    pub agent_update_policy: AgentUpdatePolicy,
}

#[derive(Debug, Clone, Copy)]
pub struct AgentUpdatePolicy {
    pub organization_enabled: bool,
    pub device_opted_out: bool,
}

impl AgentUpdatePolicy {
    pub fn allows_automatic_updates(self) -> bool {
        self.organization_enabled && !self.device_opted_out
    }
}

pub struct InventorySample {
    pub received_at: OffsetDateTime,
    pub memory_used: Option<u8>,
    pub disk_used: Vec<(String, u8)>,
}

pub struct DeviceActivityEvent {
    pub at: OffsetDateTime,
    pub action: String,
    pub actor: String,
    pub job: Option<Uuid>,
    pub job_action: Option<String>,
    pub support_session: Option<Uuid>,
    pub version_report: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobRow {
    pub id: Uuid,
    pub device_id: Uuid,
    pub hostname: String,
    pub organization: OrgRef,
    pub action: String,
    /// Short human rendering of the parameters, e.g. `target=10.0.0.1`.
    pub params: String,
    pub state: ExecState,
    pub verification: Verification,
    pub requested_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub terminal_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobEventView {
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    pub kind: String,
    pub from_state: Option<String>,
    pub to_state: Option<String>,
    pub actor: String,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamView {
    pub data: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobDetail {
    #[serde(flatten)]
    pub row: JobRow,
    pub request_channel: String,
    pub timeout_secs: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub deliver_by: OffsetDateTime,
    pub dispatch_count: i32,
    #[serde(with = "time::serde::rfc3339::option")]
    pub acknowledged_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub cancel_requested_at: Option<OffsetDateTime>,
    pub state_note: Option<String>,
    pub verification_note: Option<String>,
    pub exit_code: Option<i32>,
    pub stdout: Option<StreamView>,
    pub stderr: Option<StreamView>,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub success_contract: String,
    pub events: Vec<JobEventView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiteView {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrgSummary {
    pub id: Uuid,
    pub name: String,
    pub device_count: i64,
    pub sites: Vec<SiteView>,
    #[serde(skip)]
    pub automatic_agent_updates: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentTokenView {
    pub id: Uuid,
    pub site: Option<String>,
    pub created_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub uses: i32,
    pub max_uses: i32,
    pub revoked: bool,
}

/// A secret shown exactly once, right after creation.
#[derive(Debug, Clone)]
pub struct RevealedSecret {
    pub label: String,
    pub secret: String,
    pub hint: String,
    /// Local enrollment commands prompt for the separately displayed token.
    pub commands: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditRow {
    pub id: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    pub actor_label: String,
    pub channel: String,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub outcome: String,
    pub organization: Option<String>,
    pub detail: serde_json::Value,
    /// The address the request came from, where one was recorded.
    pub client_ip: Option<String>,
    /// `session:<id prefix>` or `token:<prefix>`; never a secret.
    pub credential: Option<String>,
}

/// What the audit page and its export are narrowed to. Text filters are kept as typed, to show them back.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Part of the actor's label (an email, a device name).
    pub actor: String,
    /// An action, or the start of one: `user.` matches every user action.
    pub action: String,
    /// `success`, `denied` or `failed`.
    pub outcome: Option<String>,
    pub organization: Option<Uuid>,
    /// Inclusive UTC days.
    pub from: Option<time::Date>,
    pub to: Option<time::Date>,
    /// Only events older than this id: the page after the one that ended there.
    pub before: Option<i64>,
}

impl AuditFilter {
    pub fn is_empty(&self) -> bool {
        self.actor.is_empty()
            && self.action.is_empty()
            && self.outcome.is_none()
            && self.organization.is_none()
            && self.from.is_none()
            && self.to.is_none()
    }
}

/// One page of the audit log.
#[derive(Debug, Clone)]
pub struct AuditPage {
    pub rows: Vec<AuditRow>,
    pub filter: AuditFilter,
    /// The id to continue from, when older matching events exist.
    pub older: Option<i64>,
    pub organizations: Vec<OrgRef>,
}

/// One user, for the administrator's page about them.
#[derive(Debug, Clone)]
pub struct UserDetail {
    pub directory: bool,
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub disabled_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub organization_ids: Vec<Uuid>,
    /// Two-step verification is set up.
    pub mfa: bool,
    pub passkeys: i64,
    /// Live sessions, partial ones included.
    pub sessions: i64,
    /// API tokens that still work.
    pub api_tokens: i64,
    pub password_changed_at: Option<OffsetDateTime>,
    /// The password was made up for them by an administrator and they have not replaced it.
    pub password_temporary: bool,
    /// The administrator looking at the page.
    pub is_self: bool,
    /// The only enabled administrator: cannot be demoted or disabled.
    pub only_admin: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub organizations: Vec<String>,
    pub disabled: bool,
    /// Two-step verification is set up.
    pub mfa: bool,
    /// Passkeys and security keys registered.
    pub passkeys: i64,
    /// Live sessions, partial ones included.
    pub sessions: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenRow {
    pub id: Uuid,
    pub owner: String,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub devices_total: i64,
    pub devices_connected: i64,
    pub jobs_in_flight: i64,
    pub jobs_succeeded_24h: i64,
    pub jobs_failed_24h: i64,
    pub jobs_unknown: i64,
    pub attention: Vec<JobRow>,
    pub recent: Vec<JobRow>,
    /// Organizations the caller can see: the first-run steps are shown until there is a device.
    pub organizations: Vec<OrgRef>,
    /// Active devices with a concern, most serious first, at most `Overview::DEVICE_ATTENTION_LIMIT`.
    pub device_attention: Vec<DeviceAttention>,
    /// How many active devices have a concern, including those not listed.
    pub device_attention_total: i64,
    /// Agent versions among active devices, most common first. `None` is a device that has not reported one.
    pub agent_versions: Vec<(Option<String>, i64)>,
    /// True when the device figures cover only part of the fleet (more active devices than one page loads).
    pub devices_truncated: bool,
}

impl Overview {
    pub const DEVICE_ATTENTION_LIMIT: usize = 8;
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceAttention {
    pub device: DeviceRow,
    pub concerns: Vec<Concern>,
}

/// Filters echoed back into the device list form.
#[derive(Debug, Clone, Default)]
pub struct DeviceFilter {
    pub q: String,
    pub organization: Option<Uuid>,
    pub connection: String,
    pub tag: String,
    /// `""` active devices, `"retired"`, or `"all"`.
    pub status: String,
    /// `""` by name, `"seen"` longest-silent first, `"disk"` fullest disk first.
    pub sort: String,
    /// Only devices with a concern (see `DeviceRow::concerns`).
    pub attention: bool,
}

/// One custom field's definition, for the administration page.
#[derive(Debug, Clone, Serialize)]
pub struct FieldDefView {
    pub id: Uuid,
    pub key: String,
    pub label: String,
    /// `text`, `number`, `boolean`, `choice` or `secret`.
    pub kind: String,
    pub choices: Vec<String>,
    /// Where values may be set: `global`, `organization`, `device`.
    pub scopes: Vec<String>,
    /// `organization`: every organization must set one. `device`: every device must resolve to one.
    pub required_at: Option<String>,
    pub default_value: Option<String>,
    pub technician_can_edit: bool,
    pub archived: bool,
    /// The current global value, if the field may have one.
    pub global: Option<FieldValueView>,
}

/// A value as shown: secrets never are.
#[derive(Debug, Clone, Serialize)]
pub struct FieldValueView {
    /// The value, or `••••••` for a secret.
    pub display: String,
    pub secret: bool,
    pub set_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub set_at: OffsetDateTime,
}

/// A field as it applies to one organization, site or device: the value it resolves to, and where that came from.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedField {
    pub id: Uuid,
    pub key: String,
    pub label: String,
    pub kind: String,
    pub choices: Vec<String>,
    /// What applies here, from `source`.
    pub value: Option<FieldValueView>,
    /// `device`, `site`, `organization`, `global`, `default` or `unset`.
    pub source: &'static str,
    /// The value set on this very organization, site or device, if any (it may be overridden or inherited).
    pub own: Option<FieldValueView>,
    /// A value may be set at this level by this field's rules.
    pub settable_here: bool,
    /// The viewer may set it here.
    #[serde(skip)]
    pub can_edit: bool,
    /// A required value is missing at this level.
    pub missing: bool,
}

/// A required field and the organizations or devices that lack it.
#[derive(Debug, Clone, Serialize)]
pub struct MissingRequired {
    pub key: String,
    pub label: String,
    /// `organization` or `device` (a field's own requirement); for what a script reads, also `global` or `site`.
    pub level: &'static str,
    /// (id, name), at most 50.
    pub targets: Vec<(Uuid, String)>,
    pub total: usize,
}

/// One change of a value, newest first.
#[derive(Debug, Clone, Serialize)]
pub struct FieldHistoryRow {
    /// The value set, `••••••` for a secret, or `None` when it was cleared (the target inherits again).
    pub display: Option<String>,
    pub set_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub set_at: OffsetDateTime,
}

/// Jobs created together for several devices, summarized.
#[derive(Debug, Clone, Serialize)]
pub struct BatchSummary {
    pub id: Uuid,
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub unknown: i64,
    pub in_progress: i64,
}

/// What a change to many devices will touch, shown before it happens.
#[derive(Debug, Clone)]
pub struct BulkConfirm {
    /// `run` or `retire`.
    pub op: &'static str,
    pub devices: Vec<DeviceRow>,
}

/// Device chosen by the technician for a linked invitation.
pub struct SupportDevice {
    pub id: Uuid,
    pub name: String,
    pub organization: OrgRef,
}

/// One attended support session, for the technician.
#[derive(Debug, Clone, Serialize)]
pub struct SupportSessionView {
    pub id: Uuid,
    pub created_by: String,
    pub organization: String,
    #[serde(skip)]
    pub linked_device: Option<(Uuid, String)>,
    /// The viewer did not create this session (an administrator): they may see its state and
    /// end it, but never attach to its signaling.
    #[serde(skip)]
    pub observer: bool,
    pub note: Option<String>,
    pub state: &'static str,
    pub state_label: &'static str,
    pub terminal: bool,
    pub capabilities: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub invite_expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub ended_at: Option<OffsetDateTime>,
    pub end_reason: Option<String>,
    #[serde(skip)]
    pub now: OffsetDateTime,
}

/// A freshly created invitation, shown once.
#[derive(Debug, Clone)]
pub struct SupportInvite {
    pub session_id: Uuid,
    pub code: String,
    pub link: String,
    pub entry_url: String,
    pub minutes: u64,
}

/// What the person being helped sees before deciding.
#[derive(Debug, Clone)]
pub struct SupportConsentView {
    pub session_id: Uuid,
    /// The request includes remote control (the helper, ADR-0012).
    pub control: bool,
    pub technician_name: String,
    pub technician_email: String,
    pub server_host: String,
    pub capabilities: Vec<String>,
    pub state: &'static str,
    pub state_label: &'static str,
}

/// Setting up an authenticator app: the secret, shown once, until a code confirms it.
#[derive(Debug, Clone)]
pub struct MfaSetupView {
    pub csrf: String,
    pub email: String,
    /// Base32 secret, for typing into an app that cannot scan.
    pub secret: String,
    pub otpauth_uri: String,
    /// MFA is required and this user has not reached the console yet.
    pub forced: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AccountView {
    pub directory: bool,
    pub email: String,
    pub display_name: String,
    pub mfa_enabled_at: Option<OffsetDateTime>,
    pub recovery_remaining: i64,
    pub require_mfa: bool,
    pub passkeys: Vec<PasskeyRow>,
    /// Sudo mode lasts until then, when the session is in it.
    pub sudo_until: Option<OffsetDateTime>,
    pub sessions: Vec<SessionRow>,
    pub password_changed_at: Option<OffsetDateTime>,
    /// An administrator made up the current password; the person should choose their own.
    pub password_temporary: bool,
}

/// A live browser session of the person viewing the account page.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: Uuid,
    /// The session this page was loaded with.
    pub current: bool,
    /// The password was accepted and the second factor is still owed.
    pub partial: bool,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub client_ip: String,
    pub user_agent: String,
}

#[derive(Debug, Clone)]
pub struct PasskeyRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

/// A WebAuthn ceremony for `/static/passkey.js`: the form it posts to and the options for the browser (JSON, with
/// binary values in base64url).
#[derive(Debug, Clone)]
pub struct WebAuthnCeremony {
    pub action: String,
    pub options: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PasskeyNewView {
    pub ceremony: WebAuthnCeremony,
    /// The first passkey needs the password, and the current code when two-step verification is on.
    pub needs_password: bool,
    pub needs_code: bool,
}

#[derive(Debug, Clone)]
pub struct SudoView {
    /// `None` when the user has no passkey yet.
    pub ceremony: Option<WebAuthnCeremony>,
    /// Where to go once confirmed: a path on this site.
    pub next: String,
    pub minutes: u64,
}

/// One script in the library list.
#[derive(Debug, Clone)]
pub struct ScriptListRow {
    pub id: Uuid,
    pub name: String,
    pub language_label: &'static str,
    /// The organization it belongs to; `None` for a global script.
    pub organization: Option<String>,
    /// The latest revision's number, risk class, author and time; `None` before the first save.
    pub latest: Option<i32>,
    pub risk_class: Option<String>,
    pub updated_by: Option<String>,
    pub updated_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct ScriptView {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    /// `None`: a global script.
    pub organization: Option<OrgRef>,
    pub language: String,
    pub language_label: &'static str,
    /// File extension for downloads and uploads: `ps1`, `sh`, `py`.
    pub extension: &'static str,
}

/// One saved revision, in full.
#[derive(Debug, Clone)]
pub struct RevisionView {
    pub number: i32,
    pub source: String,
    pub risk_class: String,
    pub parameters: String,
    /// SHA-256 of what it would run, hex.
    pub hash: String,
    pub note: String,
    pub author: String,
    pub created_at: OffsetDateTime,
    /// What checked its syntax when it was saved, or why nothing did.
    pub checker: Option<String>,
    pub unchecked: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RevisionSummary {
    pub number: i32,
    pub risk_class: String,
    pub note: String,
    pub author: String,
    pub created_at: OffsetDateTime,
    pub hash_prefix: String,
}

/// Something the checks found: in the `source` or the `parameters`, at a line when known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptProblem {
    pub section: &'static str,
    pub line: Option<u32>,
    pub message: String,
}

/// What the editor shows: the latest revision, or the text someone submitted that could not be saved.
#[derive(Debug, Clone)]
pub struct ScriptDraft {
    /// The revision the text was based on (0: none yet). A save only succeeds if it is still the latest.
    pub base: i32,
    pub source: String,
    pub parameters: String,
    pub risk_class: String,
    pub note: String,
}

/// One row of a line diff. Line numbers count from 1 in the older and newer text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffRow {
    Same {
        old: usize,
        new: usize,
        text: String,
    },
    Removed {
        old: usize,
        text: String,
    },
    Added {
        new: usize,
        text: String,
    },
    /// This many unchanged lines, not shown.
    Folded(usize),
}

/// What changed from the revision before. A diff is `None` when it was too large to compute.
#[derive(Debug, Clone)]
pub struct RevisionChanges {
    pub source: Option<Vec<DiffRow>>,
    pub parameters: Option<Vec<DiffRow>>,
    /// The earlier risk class, when it changed.
    pub risk_from: Option<String>,
}

/// The trust page (ADR-0015): the chain the server holds. Shown for convenience only: under a compromised server
/// none of it can be relied on, which the page says.
#[derive(Debug, Clone)]
pub struct TrustView {
    pub fingerprint: String,
    pub deployment: String,
    pub version: u64,
    pub head: String,
    pub rp_id: String,
    pub origins: Vec<String>,
    pub threshold: u64,
    pub signers: Vec<SignerRow>,
    pub removed: Vec<String>,
    pub revoked: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SignerRow {
    pub person: String,
    pub key_id: String,
    pub kind: String,
    pub role: String,
    pub may_approve: String,
}

#[derive(Debug, Clone)]
pub struct ApprovalRow {
    pub person: String,
    pub key_id: String,
    /// Still verifies under the current trust list.
    pub valid: bool,
    pub approved_at: OffsetDateTime,
}

#[derive(Debug, Clone, Default)]
pub struct ApprovalsView {
    /// Whether a trust list exists yet.
    pub trusted: bool,
    pub rows: Vec<ApprovalRow>,
}

/// An approved revision that could run on a device.
#[derive(Debug, Clone)]
pub struct RunOption {
    pub script_id: uuid::Uuid,
    pub number: i32,
    pub name: String,
    pub risk: String,
    /// Parameters asked at run time: name and prompt.
    pub asks: Vec<(String, Option<String>)>,
    /// Why it cannot run here, if it cannot.
    pub blocked: Option<String>,
}
