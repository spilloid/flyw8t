//! The allowlisted action catalog.
//!
//! flyw8t does not execute arbitrary commands. A job names one of the actions below; each is
//! compiled into the agent, takes only typed and validated parameters, and is read-only.
//! Validation runs on the server before a job is created *and* again on the agent before it
//! runs: the agent never trusts that the server validated.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// One allowlisted action and its parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "params")]
pub enum Action {
    /// OS, hardware, disk and network inventory, collected in-process.
    #[serde(rename = "system.info")]
    SystemInfo,
    /// The processes using the most memory, collected in-process.
    #[serde(rename = "process.top")]
    ProcessTop { limit: u16 },
    /// Network adapter configuration (`ipconfig /all` on Windows, `ip addr` elsewhere).
    #[serde(rename = "net.ipconfig")]
    NetIpconfig,
    /// Four ICMP echo requests to one host.
    #[serde(rename = "net.ping")]
    NetPing { target: String },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionError {
    #[error("unknown action {0:?}")]
    Unknown(String),
    #[error("invalid parameter {param}: {reason}")]
    InvalidParam {
        param: &'static str,
        reason: &'static str,
    },
}

/// Risk classification of an action. Only `ReadOnly` exists today; anything that changes
/// endpoint state needs a new class, its own approval rules, and a verification contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    ReadOnly,
}

/// How the server decides whether a completed execution produced the evidence it promised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessContract {
    /// The agent must return a structured payload that parses as the action's result type.
    StructuredPayload,
    /// The process must exit with one of these codes and write something to stdout.
    ExitCodeWithOutput(&'static [i32]),
}

/// Static description of an action, for the UI and API catalog.
#[derive(Debug, Clone, Serialize)]
pub struct ActionInfo {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub risk: Risk,
    pub default_timeout_secs: u32,
    pub max_timeout_secs: u32,
    /// Parameter names this action takes, in form order.
    pub params: &'static [&'static str],
    /// Plain-language statement of what counts as success, shown next to results.
    pub success_contract: &'static str,
}

pub const CATALOG: &[ActionInfo] = &[
    ActionInfo {
        name: "system.info",
        title: "System information",
        description: "Operating system, CPU, memory, disks and network adapters.",
        risk: Risk::ReadOnly,
        default_timeout_secs: 30,
        max_timeout_secs: 120,
        params: &[],
        success_contract: "The agent returned a complete, well-formed inventory document.",
    },
    ActionInfo {
        name: "process.top",
        title: "Top processes by memory",
        description: "The processes using the most memory right now.",
        risk: Risk::ReadOnly,
        default_timeout_secs: 30,
        max_timeout_secs: 120,
        params: &["limit"],
        success_contract: "The agent returned a well-formed process list.",
    },
    ActionInfo {
        name: "net.ipconfig",
        title: "Network configuration",
        description: "Adapter addresses, gateways and DNS servers (ipconfig /all).",
        risk: Risk::ReadOnly,
        default_timeout_secs: 30,
        max_timeout_secs: 120,
        params: &[],
        success_contract: "The command exited 0 and printed output.",
    },
    ActionInfo {
        name: "net.ping",
        title: "Ping a host",
        description: "Four ICMP echo requests from the device to one host or IP address.",
        risk: Risk::ReadOnly,
        default_timeout_secs: 30,
        max_timeout_secs: 120,
        params: &["target"],
        success_contract: "The ping command ran to completion (exit 0 = replies, 1 = no reply) and printed output. A host that does not answer is a diagnostic result, not a failed job.",
    },
];

impl Action {
    pub fn name(&self) -> &'static str {
        match self {
            Action::SystemInfo => "system.info",
            Action::ProcessTop { .. } => "process.top",
            Action::NetIpconfig => "net.ipconfig",
            Action::NetPing { .. } => "net.ping",
        }
    }

    pub fn info(&self) -> &'static ActionInfo {
        info(self.name()).expect("every Action variant has a CATALOG entry")
    }

    pub fn success_contract(&self) -> SuccessContract {
        match self {
            Action::SystemInfo | Action::ProcessTop { .. } => SuccessContract::StructuredPayload,
            Action::NetIpconfig => SuccessContract::ExitCodeWithOutput(&[0]),
            Action::NetPing { .. } => SuccessContract::ExitCodeWithOutput(&[0, 1]),
        }
    }

    /// Build an action from a catalog name and untrusted string parameters (form or API
    /// input). The result is validated.
    pub fn from_request(
        name: &str,
        param: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ActionError> {
        let action = match name {
            "system.info" => Action::SystemInfo,
            "process.top" => {
                let raw = param("limit").unwrap_or_else(|| "15".into());
                let limit = raw
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| ActionError::InvalidParam {
                        param: "limit",
                        reason: "must be a whole number",
                    })?;
                Action::ProcessTop { limit }
            }
            "net.ipconfig" => Action::NetIpconfig,
            "net.ping" => Action::NetPing {
                target: param("target").unwrap_or_default().trim().to_string(),
            },
            other => return Err(ActionError::Unknown(other.to_string())),
        };
        action.validate()?;
        Ok(action)
    }

    /// Validate parameters. Called by the server before creating a job and by the agent
    /// before running one.
    pub fn validate(&self) -> Result<(), ActionError> {
        match self {
            Action::SystemInfo | Action::NetIpconfig => Ok(()),
            Action::ProcessTop { limit } => {
                if (1..=50).contains(limit) {
                    Ok(())
                } else {
                    Err(ActionError::InvalidParam {
                        param: "limit",
                        reason: "must be between 1 and 50",
                    })
                }
            }
            Action::NetPing { target } => validate_ping_target(target),
        }
    }
}

pub fn info(name: &str) -> Option<&'static ActionInfo> {
    CATALOG.iter().find(|a| a.name == name)
}

/// A ping target is an IP address or a DNS hostname, nothing else. In particular it can never
/// begin with `-`, so it cannot be read as a command-line option by the ping binary.
fn validate_ping_target(target: &str) -> Result<(), ActionError> {
    let bad = |reason| {
        Err(ActionError::InvalidParam {
            param: "target",
            reason,
        })
    };
    if target.is_empty() {
        return bad("is required");
    }
    if target.len() > 253 {
        return bad("is longer than a hostname can be");
    }
    if target.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    for label in target.split('.') {
        if label.is_empty() || label.len() > 63 {
            return bad("is not a valid hostname or IP address");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return bad("is not a valid hostname or IP address");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return bad("is not a valid hostname or IP address");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_a_catalog_entry() {
        let all = [
            Action::SystemInfo,
            Action::ProcessTop { limit: 5 },
            Action::NetIpconfig,
            Action::NetPing {
                target: "1.1.1.1".into(),
            },
        ];
        for a in &all {
            assert_eq!(a.info().name, a.name());
        }
        assert_eq!(all.len(), CATALOG.len());
    }

    #[test]
    fn wire_format_is_tagged_and_stable() {
        let json = serde_json::to_string(&Action::NetPing {
            target: "example.com".into(),
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"action":"net.ping","params":{"target":"example.com"}}"#
        );
        let unit: Action = serde_json::from_str(r#"{"action":"system.info"}"#).unwrap();
        assert_eq!(unit, Action::SystemInfo);
    }

    #[test]
    fn unknown_actions_do_not_deserialize() {
        assert!(serde_json::from_str::<Action>(
            r#"{"action":"shell.exec","params":{"cmd":"whoami"}}"#
        )
        .is_err());
        assert!(matches!(
            Action::from_request("shell.exec", |_| None),
            Err(ActionError::Unknown(_))
        ));
    }

    #[test]
    fn ping_target_rejects_option_injection_and_shell_metacharacters() {
        for bad in [
            "",
            "-t",
            "-n 1000 host",
            "host;whoami",
            "host && calc",
            "a..b",
            "host name",
            "$(id)",
            "host|x",
            "-",
            "a-.com",
            &"a".repeat(64),
        ] {
            assert!(
                Action::NetPing {
                    target: bad.to_string()
                }
                .validate()
                .is_err(),
                "{bad:?} should be rejected"
            );
        }
        for good in [
            "1.1.1.1",
            "::1",
            "fe80::1",
            "example.com",
            "dc01",
            "my-host.corp.local",
        ] {
            assert!(
                Action::NetPing {
                    target: good.to_string()
                }
                .validate()
                .is_ok(),
                "{good:?} should be accepted"
            );
        }
    }

    #[test]
    fn process_top_limit_is_bounded() {
        assert!(Action::ProcessTop { limit: 0 }.validate().is_err());
        assert!(Action::ProcessTop { limit: 51 }.validate().is_err());
        assert!(Action::ProcessTop { limit: 50 }.validate().is_ok());
        assert!(Action::from_request("process.top", |_| Some("abc".into())).is_err());
        assert_eq!(
            Action::from_request("process.top", |_| None).unwrap(),
            Action::ProcessTop { limit: 15 }
        );
    }
}
