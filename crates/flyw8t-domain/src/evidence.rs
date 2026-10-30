//! Evaluating a completed execution against its action's success contract.

use crate::job::Verification;
use flyw8t_protocol::catalog::{Action, SuccessContract};
use flyw8t_protocol::inventory::{InventoryReport, ProcessList};
use flyw8t_protocol::messages::{ExecOutcome, Finished};

/// Verdict plus the reason a technician will read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub verification: Verification,
    pub explanation: String,
}

fn verdict(verification: Verification, explanation: impl Into<String>) -> Verdict {
    Verdict {
        verification,
        explanation: explanation.into(),
    }
}

/// Evaluate a final report. Only executions that ran to their end are verifiable; everything
/// else is `NotApplicable`.
pub fn evaluate(action: &Action, finished: &Finished) -> Verdict {
    match (&finished.outcome, action.success_contract()) {
        (ExecOutcome::Collected, SuccessContract::StructuredPayload) => {
            let Some(payload) = finished.structured.clone() else {
                return verdict(
                    Verification::Failed,
                    "The device reported success but sent no result payload.",
                );
            };
            let parsed = match action {
                Action::SystemInfo => {
                    serde_json::from_value::<InventoryReport>(payload).map(|_| ())
                }
                Action::ProcessTop { .. } => {
                    serde_json::from_value::<ProcessList>(payload).map(|_| ())
                }
                _ => unreachable!("structured contract only for in-process actions"),
            };
            match parsed {
                Ok(()) => verdict(
                    Verification::Verified,
                    "Result payload is complete and well-formed.",
                ),
                Err(e) => verdict(
                    Verification::Failed,
                    format!("Result payload is malformed: {e}"),
                ),
            }
        }
        (ExecOutcome::Exited { code }, SuccessContract::ExitCodeWithOutput(accepted)) => {
            if !accepted.contains(code) {
                return verdict(
                    Verification::Failed,
                    format!("Exit code {code} is not an accepted result for {} (accepted: {accepted:?}).", action.name()),
                );
            }
            let has_output = finished
                .stdout
                .as_ref()
                .is_some_and(|s| !s.data.trim().is_empty());
            if has_output {
                verdict(
                    Verification::Verified,
                    format!("Exited {code} with output."),
                )
            } else {
                verdict(
                    Verification::Failed,
                    format!("Exited {code} but printed nothing."),
                )
            }
        }
        (ExecOutcome::Exited { .. } | ExecOutcome::Collected, _) => verdict(
            Verification::Failed,
            "The device reported a kind of result this action never produces.",
        ),
        _ => verdict(Verification::NotApplicable, "Execution did not complete."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flyw8t_protocol::messages::CapturedStream;
    use time::OffsetDateTime;

    fn finished(
        outcome: ExecOutcome,
        stdout: Option<&str>,
        structured: Option<serde_json::Value>,
    ) -> Finished {
        Finished {
            outcome,
            started_at: None,
            finished_at: OffsetDateTime::UNIX_EPOCH,
            stdout: stdout.map(|s| CapturedStream {
                data: s.into(),
                total_bytes: s.len() as u64,
                truncated: false,
            }),
            stderr: None,
            structured,
        }
    }

    #[test]
    fn exit_zero_without_output_is_not_success() {
        let v = evaluate(
            &Action::NetIpconfig,
            &finished(ExecOutcome::Exited { code: 0 }, Some("  \n"), None),
        );
        assert_eq!(v.verification, Verification::Failed);
    }

    #[test]
    fn nonzero_exit_fails_ipconfig_but_ping_accepts_no_reply() {
        let f = finished(
            ExecOutcome::Exited { code: 1 },
            Some("Request timed out."),
            None,
        );
        assert_eq!(
            evaluate(&Action::NetIpconfig, &f).verification,
            Verification::Failed
        );
        let ping = Action::NetPing {
            target: "10.0.0.1".into(),
        };
        assert_eq!(evaluate(&ping, &f).verification, Verification::Verified);
        let f2 = finished(ExecOutcome::Exited { code: 2 }, Some("bad"), None);
        assert_eq!(evaluate(&ping, &f2).verification, Verification::Failed);
    }

    #[test]
    fn structured_payload_must_parse() {
        let bad = finished(
            ExecOutcome::Collected,
            None,
            Some(serde_json::json!({"hostname": "x"})),
        );
        assert_eq!(
            evaluate(&Action::SystemInfo, &bad).verification,
            Verification::Failed
        );
        let missing = finished(ExecOutcome::Collected, None, None);
        assert_eq!(
            evaluate(&Action::SystemInfo, &missing).verification,
            Verification::Failed
        );
        let ok = finished(
            ExecOutcome::Collected,
            None,
            Some(serde_json::json!({"processes": [], "total": 0})),
        );
        assert_eq!(
            evaluate(&Action::ProcessTop { limit: 5 }, &ok).verification,
            Verification::Verified
        );
    }

    #[test]
    fn mismatched_result_kind_is_rejected() {
        // A device claiming a process exit for an in-process action is not evidence.
        let f = finished(ExecOutcome::Exited { code: 0 }, Some("hi"), None);
        assert_eq!(
            evaluate(&Action::SystemInfo, &f).verification,
            Verification::Failed
        );
    }

    #[test]
    fn non_completions_are_not_applicable() {
        for o in [
            ExecOutcome::TimedOut,
            ExecOutcome::Failed { error: "x".into() },
            ExecOutcome::Interrupted { reason: "x".into() },
        ] {
            assert_eq!(
                evaluate(&Action::NetIpconfig, &finished(o, Some("partial"), None)).verification,
                Verification::NotApplicable
            );
        }
    }
}
