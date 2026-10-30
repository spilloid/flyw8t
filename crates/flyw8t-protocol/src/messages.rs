//! Message envelopes. Every message is one JSON text frame tagged by `type`.

use crate::catalog::Action;
use crate::inventory::InventoryReport;
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
    },
    /// Enrollment succeeded. The agent persists `device_id` and its key, then reconnects
    /// and authenticates normally. The organization is decided by the token, never the agent.
    Enrolled {
        device_id: Uuid,
        organization: String,
    },
    /// The server refuses this connection and will close it.
    Refused { code: RefusalCode, message: String },
    /// Run a job. May be delivered more than once; the agent must deduplicate by `job_id`.
    JobOffer {
        job_id: Uuid,
        action: Action,
        timeout_secs: u32,
    },
    /// Stop a job if it has not finished. Also sent for job ids the agent may never have seen,
    /// so a late duplicate offer is not run.
    JobCancel { job_id: Uuid },
    /// The server has durably stored the final report for `job_id`; the agent may stop
    /// re-sending it.
    ReportAck { job_id: Uuid },
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
    },
    Heartbeat {
        agent_version: String,
        uptime_secs: u64,
        running_jobs: u32,
    },
    Inventory(Box<InventoryReport>),
    Job(JobReport),
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
