//! Frames for a human technician's live PowerShell session on an opted-in agent.

use crate::script::WindowsExecutionAccount;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

pub const CAP_BACKGROUND_TERMINAL: &str = "background_terminal.v1";
pub const TERMINAL_FRAME_BYTES: usize = 4096;
pub const TERMINAL_REPLAY_BYTES: usize = 256 * 1024;
pub const TERMINAL_LEASE: Duration = Duration::from_secs(15);
pub const TERMINAL_RENEWAL: Duration = Duration::from_secs(5);
pub const TERMINAL_GRACE: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalCommand {
    Open {
        attachment: Uuid,
        account: WindowsExecutionAccount,
    },
    Resume {
        attachment: Uuid,
        account: WindowsExecutionAccount,
        offset: u64,
    },
    Input {
        attachment: Uuid,
        sequence: u64,
        data: String,
    },
    Renew {
        attachment: Uuid,
    },
    Detach {
        attachment: Uuid,
    },
    Close {
        attachment: Uuid,
        reason: TerminalEndReason,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalEvent {
    Ready {
        attachment: Uuid,
        account: WindowsExecutionAccount,
        /// First available byte at or after the requested replay offset.
        offset: u64,
    },
    Output {
        attachment: Uuid,
        offset: u64,
        data: Vec<u8>,
    },
    Ack {
        attachment: Uuid,
        sequence: u64,
    },
    Ended {
        attachment: Uuid,
        reason: TerminalEndReason,
    },
    Rejected {
        attachment: Uuid,
        reason: TerminalEndReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalEndReason {
    Closed,
    ProcessExited,
    PolicyDisabled,
    AccessRevoked,
    Expired,
    AgentStopped,
    Unavailable,
    Busy,
    InvalidInput,
}

impl std::fmt::Debug for TerminalCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TerminalCommand")
    }
}

impl std::fmt::Debug for TerminalEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TerminalEvent")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentMsg, ServerMsg};

    #[test]
    fn terminal_frames_round_trip_without_debugging_contents() {
        let attachment = Uuid::nil();
        let command = ServerMsg::BackgroundTerminal {
            session_id: Uuid::nil(),
            command: TerminalCommand::Input {
                attachment,
                sequence: 1,
                data: "technician input\u{3}".into(),
            },
        };
        let event = AgentMsg::BackgroundTerminal {
            session_id: Uuid::nil(),
            event: TerminalEvent::Output {
                attachment,
                offset: 7,
                data: b"process output".to_vec(),
            },
        };
        assert!(!format!("{command:?}").contains("technician input"));
        assert!(!format!("{event:?}").contains("112, 114, 111"));
        let wire = serde_json::to_string(&command).unwrap();
        assert_eq!(serde_json::from_str::<ServerMsg>(&wire).unwrap(), command);
        let wire = serde_json::to_string(&event).unwrap();
        assert_eq!(serde_json::from_str::<AgentMsg>(&wire).unwrap(), event);
    }
}
