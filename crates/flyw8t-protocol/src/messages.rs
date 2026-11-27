//! Message envelopes. Every message is one JSON text frame tagged by `type`.

use crate::catalog::Action;
use crate::inventory::InventoryReport;
use crate::PhysicalConsoleState;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Server -> agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// First message on every connection. `nonce` is base64 of `auth::NONCE_LEN` random bytes.
    Challenge {
        protocol_version: u32,
        nonce: String,
    },
    /// Authentication succeeded; the connection is live.
    Welcome {
        device_id: Uuid,
        heartbeat_secs: u32,
        /// The device's organization, for `flyw8t-agent trust pin` to compare with the one given locally
        /// (ADR-0015 section 3). Absent from servers before ADR-0015.
        #[serde(default)]
        organization_id: Option<Uuid>,
        /// The original token's scope, when the server still has the enrollment record.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        enrollment_scope: Option<EnrollmentScope>,
    },
    /// Enrollment succeeded. The agent persists `device_id` and its key, then reconnects
    /// and authenticates normally. The organization is decided by the token, never the agent.
    Enrolled {
        device_id: Uuid,
        organization: String,
        /// The organization's id, which an agent enrolling with `--org` requires to match (ADR-0015 section 3).
        #[serde(default)]
        organization_id: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        enrollment_scope: Option<EnrollmentScope>,
    },
    /// Trust-list versions (ADR-0015 section 7): the whole chain for a request made before authenticating, or the
    /// versions after the one the agent holds. The agent verifies every one; the server is only the courier.
    TrustUpdate {
        versions: Vec<crate::trust::SignedList>,
    },
    /// The server refuses this connection and will close it.
    Refused { code: RefusalCode, message: String },
    /// Run a job. May be delivered more than once; the agent must deduplicate by `job_id`.
    JobOffer {
        job_id: Uuid,
        action: Action,
        timeout_secs: u32,
    },
    /// Run an approved script (ADR-0015 section 7). Sent only to agents that listed `scripts.v1`. May be delivered
    /// more than once; the agent deduplicates by `job_id` and checks everything in it before anything runs.
    ScriptOffer(Box<ScriptOffer>),
    /// Stop a job if it has not finished. Also sent for job ids the agent may never have seen,
    /// so a late duplicate offer is not run.
    JobCancel { job_id: Uuid },
    /// The server has durably stored the final report for `job_id`; the agent may stop
    /// re-sending it.
    ReportAck { job_id: Uuid },
    /// Read-only observation, sent only when this connection advertised the capability.
    CheckPhysicalConsole { request_id: Uuid },
    /// Inspect the endpoint administrator's setting on this connection.
    CheckBackgroundTerminalPolicy { request_id: Uuid },
}

/// The organization and site the server assigned when the device enrolled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentScope {
    pub organization_id: Uuid,
    pub site_id: Option<Uuid>,
}

/// One script run, with everything the agent needs to decide for itself whether it may run.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptOffer {
    pub job_id: Uuid,
    pub deployment_id: Uuid,
    pub timeout_secs: u32,
    pub revision: crate::script::Revision,
    pub approvals: Vec<crate::trust::SignedApproval>,
    /// Present for C2 and C3.
    pub authorization: Option<crate::trust::SignedAuthorization>,
    pub salt: crate::trust::Bytes,
    #[serde(deserialize_with = "crate::trust::run::strict_map")]
    pub values: std::collections::BTreeMap<String, String>,
    /// Values of parameters declared `secret`. `Debug` shows their names only.
    #[serde(deserialize_with = "crate::trust::run::strict_map")]
    pub secrets: std::collections::BTreeMap<String, String>,
}

impl std::fmt::Debug for ScriptOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptOffer")
            .field("job_id", &self.job_id)
            .field("script_id", &self.revision.script_id)
            .field("revision", &self.revision.revision)
            .field("values", &self.values)
            .field(
                "secrets",
                &self
                    .secrets
                    .keys()
                    .map(|k| (k, "[redacted]"))
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// The capability an agent lists to receive [`ScriptOffer`].
pub const CAP_SCRIPTS: &str = "scripts.v1";

/// Support for checking local policy. Grants no session or permission to execute a command.
pub const CAP_BACKGROUND_TERMINAL_POLICY: &str = "background_terminal_policy.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundTerminalPolicy {
    Enabled,
    Disabled,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    ProtocolVersion,
    BadMessage,
    AuthFailed,
    EnrollmentFailed,
    Revoked,
    RateLimited,
    /// A newer connection for the same device replaced this one.
    Superseded,
}

/// Agent -> server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMsg {
    /// Enroll a new device. `public_key` is the base64 Ed25519 public key; `signature` is over
    /// `auth::enroll_message`.
    Enroll {
        protocol_version: u32,
        token: String,
        public_key: String,
        signature: String,
        facts: DeviceFacts,
    },
    /// Authenticate as an enrolled device. `signature` is over `auth::auth_message`.
    Authenticate {
        protocol_version: u32,
        device_id: Uuid,
        signature: String,
        agent_version: String,
        /// Older agents omit this. Older servers ignore additional authentication fields.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        physical_console_check: bool,
        /// What this agent supports beyond the built-in catalog, such as `scripts.v1` (ADR-0015 section 7). The
        /// server offers nothing an agent did not list.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<String>,
    },
    /// Ask for trust-list versions: before authenticating, the whole chain (enrollment, `trust pin`); after, the
    /// versions after `after`.
    TrustRequest {
        after: Option<u64>,
    },
    Heartbeat {
        agent_version: String,
        uptime_secs: u64,
        running_jobs: u32,
    },
    Inventory(Box<InventoryReport>),
    Job(JobReport),
    /// Reply on the same authenticated socket as the matching check.
    PhysicalConsoleStatus {
        request_id: Uuid,
        state: PhysicalConsoleState,
    },
    BackgroundTerminalPolicyStatus {
        request_id: Uuid,
        policy: BackgroundTerminalPolicy,
    },
}

/// What a device says about itself when enrolling. Display hints only; the server decides
/// the device's organization from the enrollment token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFacts {
    pub hostname: String,
    pub os_family: String,
    pub agent_version: String,
}

/// The agent's latest knowledge about one job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobReport {
    pub job_id: Uuid,
    pub phase: JobPhase,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum JobPhase {
    /// Durably journaled on the agent. From here on the agent will never run it a second time.
    Accepted,
    /// Not journaled, not run. Provably not executed; the server may offer it again.
    NotAccepted { reason: NotAccepted },
    /// Execution began.
    Started {
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// Execution is over, one way or another. Re-sent until the server acknowledges it.
    Finished(Box<Finished>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotAccepted {
    /// The agent's bounded job queue is full.
    Busy,
    /// This agent build does not know the action.
    UnsupportedAction,
    /// Parameters failed the agent's own validation.
    InvalidParams,
    /// The agent could not durably record the job, so it refused to run it.
    StorageError,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finished {
    pub outcome: ExecOutcome,
    #[serde(with = "time::serde::rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
    pub stdout: Option<CapturedStream>,
    pub stderr: Option<CapturedStream>,
    /// Structured result for in-process actions (`system.info`, `process.top`).
    pub structured: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecOutcome {
    /// A child process ran and exited with this code.
    Exited { code: i32 },
    /// An in-process collector ran to completion.
    Collected,
    /// The action could not run or errored. Says why.
    Failed { error: String },
    /// The agent's timeout fired and it stopped the work. Output is partial.
    TimedOut,
    /// Cancelled on request. `started` says whether any execution happened first.
    Cancelled { started: bool },
    /// Journaled but never started (for example, the agent restarted first). Provably not run.
    NotStarted { reason: String },
    /// Execution started but the agent lost track of it (crash, power loss, service kill).
    /// Whether it completed, and what it did, is unknown.
    Interrupted { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedStream {
    /// Captured text, decoded lossily as UTF-8.
    pub data: String,
    /// Bytes the stream produced in total, including any that were discarded.
    pub total_bytes: u64,
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_check_is_an_optional_v1_authentication_field() {
        let old = serde_json::json!({
            "type": "authenticate", "protocol_version": 1, "device_id": Uuid::nil(),
            "signature": "test-signature", "agent_version": "0.1.7"
        });
        let auth: AgentMsg = serde_json::from_value(old.clone()).unwrap();
        assert!(matches!(
            auth,
            AgentMsg::Authenticate {
                physical_console_check: false,
                ..
            }
        ));
        assert_eq!(serde_json::to_value(auth).unwrap(), old);

        // The released v1 decoder accepts unknown struct-variant fields. Exercise its
        // actual Authenticate shape with the new field present.
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum Legacy {
            Authenticate {
                protocol_version: u32,
                device_id: Uuid,
                signature: String,
                agent_version: String,
            },
        }
        let mut current = old;
        current["physical_console_check"] = true.into();
        let auth: AgentMsg = serde_json::from_value(current.clone()).unwrap();
        assert!(matches!(
            auth,
            AgentMsg::Authenticate {
                physical_console_check: true,
                ..
            }
        ));
        let Legacy::Authenticate {
            protocol_version,
            device_id,
            signature,
            agent_version,
        } = serde_json::from_value(serde_json::to_value(auth).unwrap()).unwrap();
        assert_eq!((protocol_version, device_id), (1, Uuid::nil()));
        assert_eq!(
            (signature.as_str(), agent_version.as_str()),
            ("test-signature", "0.1.7")
        );
        current["physical_console_check"] = "yes".into();
        assert!(serde_json::from_value::<AgentMsg>(current).is_err());
    }

    #[test]
    fn physical_console_wire_carries_only_a_request_and_one_of_four_observations() {
        let request_id = Uuid::from_u128(7);
        let request =
            serde_json::json!({"type": "check_physical_console", "request_id": request_id});
        let decoded: ServerMsg = serde_json::from_value(request.clone()).unwrap();
        assert_eq!(decoded, ServerMsg::CheckPhysicalConsole { request_id });
        assert_eq!(serde_json::to_value(decoded).unwrap(), request);
        for (state, wire) in [
            (PhysicalConsoleState::ActiveConsole, "active_console"),
            (
                PhysicalConsoleState::NoInteractiveUser,
                "no_interactive_user",
            ),
            (PhysicalConsoleState::NoConsole, "no_console"),
            (PhysicalConsoleState::Unavailable, "unavailable"),
        ] {
            let response = AgentMsg::PhysicalConsoleStatus { request_id, state };
            let json = serde_json::json!({"type":"physical_console_status","request_id": request_id,"state":wire});
            assert_eq!(serde_json::to_value(&response).unwrap(), json);
            assert_eq!(serde_json::from_value::<AgentMsg>(json).unwrap(), response);
        }
        assert!(serde_json::from_value::<AgentMsg>(serde_json::json!({
            "type":"physical_console_status","request_id":request_id,"state":"rdp"
        }))
        .is_err());
    }

    #[test]
    fn job_offer_round_trips() {
        let msg = ServerMsg::JobOffer {
            job_id: Uuid::from_u128(9),
            action: Action::ProcessTop { limit: 3 },
            timeout_secs: 30,
        };
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains(r#""type":"job_offer""#));
        assert_eq!(serde_json::from_str::<ServerMsg>(&s).unwrap(), msg);
    }

    #[test]
    fn finished_report_round_trips() {
        let report = AgentMsg::Job(JobReport {
            job_id: Uuid::from_u128(1),
            phase: JobPhase::Finished(Box::new(Finished {
                outcome: ExecOutcome::Exited { code: 0 },
                started_at: Some(OffsetDateTime::UNIX_EPOCH),
                finished_at: OffsetDateTime::UNIX_EPOCH,
                stdout: Some(CapturedStream {
                    data: "ok".into(),
                    total_bytes: 2,
                    truncated: false,
                }),
                stderr: None,
                structured: None,
            })),
        });
        let s = serde_json::to_string(&report).unwrap();
        assert_eq!(serde_json::from_str::<AgentMsg>(&s).unwrap(), report);
    }

    #[test]
    fn unknown_message_types_are_rejected() {
        assert!(serde_json::from_str::<AgentMsg>(r#"{"type":"exec","cmd":"whoami"}"#).is_err());
    }
}
