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
    pub can_enroll: bool,
    pub can_support: bool,
    pub flash: Option<Flash>,
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
    pub hostname: String,
    pub organization: OrgRef,
    pub site: Option<String>,
    pub os: Option<String>,
    pub agent_version: Option<String>,
    pub connection: Connection,
    pub retired: bool,
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
    #[serde(with = "time::serde::rfc3339")]
    pub enrolled_at: OffsetDateTime,
    pub inventory: Option<InventoryView>,
    pub credential: Option<CredentialView>,
    pub recent_jobs: Vec<JobRow>,
    /// Remote-access provider status for this device (see docs/decisions/ADR-0006).
    pub remote_access: String,
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
}

/// Filters echoed back into the device list form.
#[derive(Debug, Clone, Default)]
pub struct DeviceFilter {
    pub q: String,
    pub organization: Option<Uuid>,
    pub connection: String,
}

/// One attended support session, for the technician.
#[derive(Debug, Clone, Serialize)]
pub struct SupportSessionView {
    pub id: Uuid,
    pub created_by: String,
    pub organization: String,
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
    pub email: String,
    pub display_name: String,
    pub mfa_enabled_at: Option<OffsetDateTime>,
    pub recovery_remaining: i64,
    pub require_mfa: bool,
}
