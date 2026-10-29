//! The job lifecycle state machine. See `docs/job-lifecycle.md`.
//!
//! A job has two dimensions:
//!
//! * **Execution state** ([`ExecState`]) — where the job is in delivery and execution.
//! * **Verification** ([`Verification`]) — whether a completed execution produced the evidence
//!   its action's success contract requires.
//!
//! A job *succeeded* only when execution is `Completed` **and** verification is `Verified`.
//! Dispatching is not executing, and exiting 0 is not proof.

use flyw8t_protocol::messages::ExecOutcome;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecState {
    /// Request recorded; authorization not yet decided.
    Created,
    /// Authorization passed for this actor, device and action.
    Authorized,
    /// Waiting for the device to be reachable.
    Queued,
    /// Offer written to the device's connection. Not proof the device received it.
    Dispatched,
    /// The device durably journaled the job. It will not run it twice.
    Acknowledged,
    /// The device reported that execution began.
    Running,
    /// The device reported that execution ran to its end. See verification for the verdict.
    Completed,
    /// Execution could not run or errored, or was provably never started.
    Failed,
    /// The device's own timeout stopped the work. Output is partial.
    TimedOut,
    /// Cancelled before or during execution.
    Cancelled,
    /// Never reached the device before its delivery deadline. Provably not executed.
    Expired,
    /// flyw8t cannot tell whether the job ran or what it did. Resolvable only by a final
    /// report from the device.
    OutcomeUnknown,
}

pub const ALL_STATES: [ExecState; 12] = [
    ExecState::Created,
    ExecState::Authorized,
    ExecState::Queued,
    ExecState::Dispatched,
    ExecState::Acknowledged,
    ExecState::Running,
    ExecState::Completed,
    ExecState::Failed,
    ExecState::TimedOut,
    ExecState::Cancelled,
    ExecState::Expired,
    ExecState::OutcomeUnknown,
];

impl ExecState {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecState::Created => "created",
            ExecState::Authorized => "authorized",
            ExecState::Queued => "queued",
            ExecState::Dispatched => "dispatched",
            ExecState::Acknowledged => "acknowledged",
            ExecState::Running => "running",
            ExecState::Completed => "completed",
            ExecState::Failed => "failed",
            ExecState::TimedOut => "timed_out",
            ExecState::Cancelled => "cancelled",
            ExecState::Expired => "expired",
            ExecState::OutcomeUnknown => "outcome_unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        ALL_STATES.into_iter().find(|st| st.as_str() == s)
    }

    /// No further transition is possible.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ExecState::Completed
                | ExecState::Failed
                | ExecState::TimedOut
                | ExecState::Cancelled
                | ExecState::Expired
        )
    }

    /// The device may still be holding or running this job.
    pub fn is_in_flight(self) -> bool {
        matches!(
            self,
            ExecState::Dispatched | ExecState::Acknowledged | ExecState::Running
        )
    }

    /// Not yet sent to the device; cancelling is guaranteed to prevent execution.
    pub fn is_pre_dispatch(self) -> bool {
        matches!(
            self,
            ExecState::Created | ExecState::Authorized | ExecState::Queued
        )
    }

    /// Whether `self -> to` is a legal transition. The server applies every transition as a
    /// conditional update on the expected current state, so this table plus that condition is
    /// the whole concurrency story.
    pub fn can_transition_to(self, to: ExecState) -> bool {
        use ExecState::*;
        let finals = |t: ExecState| matches!(t, Completed | Failed | TimedOut | Cancelled);
        match self {
            Created => matches!(to, Authorized | Cancelled),
            Authorized => matches!(to, Queued | Cancelled),
            Queued => matches!(to, Dispatched | Cancelled | Expired),
            // Back to Queued only when the agent says it did not accept the offer.
            // Straight to a final state when the ack was lost but the final report arrived.
            Dispatched => {
                matches!(to, Acknowledged | Running | Queued | OutcomeUnknown) || finals(to)
            }
            Acknowledged => matches!(to, Running | OutcomeUnknown) || finals(to),
            Running => to == OutcomeUnknown || finals(to),
            // Only a final report from the device resolves an unknown outcome.
            OutcomeUnknown => finals(to),
            Completed | Failed | TimedOut | Cancelled | Expired => false,
        }
    }
}

/// Map a device's final report to the execution state it proves.
pub fn state_for_outcome(outcome: &ExecOutcome) -> ExecState {
    match outcome {
        ExecOutcome::Exited { .. } | ExecOutcome::Collected => ExecState::Completed,
        ExecOutcome::Failed { .. } | ExecOutcome::NotStarted { .. } => ExecState::Failed,
        ExecOutcome::TimedOut => ExecState::TimedOut,
        ExecOutcome::Cancelled { .. } => ExecState::Cancelled,
        ExecOutcome::Interrupted { .. } => ExecState::OutcomeUnknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// Waiting for execution to complete, or for its evidence to be evaluated.
    Pending,
    /// The evidence satisfies the action's success contract.
    Verified,
    /// Execution completed but the evidence does not satisfy the contract.
    Failed,
    /// Execution did not complete, so there is nothing to verify.
    NotApplicable,
}

impl Verification {
    pub fn as_str(self) -> &'static str {
        match self {
            Verification::Pending => "pending",
            Verification::Verified => "verified",
            Verification::Failed => "failed",
            Verification::NotApplicable => "not_applicable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Verification::Pending,
            Verification::Verified,
            Verification::Failed,
            Verification::NotApplicable,
        ]
        .into_iter()
        .find(|v| v.as_str() == s)
    }
}

/// How a result should read at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    InProgress,
    Succeeded,
    Failed,
    Unknown,
    Neutral,
}

/// The single honest headline for a job, derived from both dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub label: &'static str,
    pub tone: Tone,
    pub explanation: &'static str,
}

pub fn outcome(state: ExecState, verification: Verification) -> Outcome {
    use ExecState::*;
    let o = |label, tone, explanation| Outcome {
        label,
        tone,
        explanation,
    };
    match (state, verification) {
        (Completed, Verification::Verified) => o(
            "Succeeded",
            Tone::Succeeded,
            "The device ran the action and its result satisfies the success contract.",
        ),
        (Completed, Verification::Failed) => o(
            "Verification failed",
            Tone::Failed,
            "The device ran the action, but the result does not satisfy the success contract.",
        ),
        (Completed, _) => o(
            "Completed, verifying",
            Tone::InProgress,
            "The device reported completion; its evidence has not been evaluated yet.",
        ),
        (Created | Authorized, _) => o("Pending", Tone::InProgress, "The request is being recorded."),
        (Queued, _) => o(
            "Queued",
            Tone::InProgress,
            "Waiting for the device to connect. Not sent yet.",
        ),
        (Dispatched, _) => o(
            "Sent",
            Tone::InProgress,
            "Sent to the device's connection. The device has not confirmed receiving it.",
        ),
        (Acknowledged, _) => o(
            "Accepted by device",
            Tone::InProgress,
            "The device recorded the job and will run it exactly once.",
        ),
        (Running, _) => o("Running", Tone::InProgress, "The device reported that execution began."),
        (Failed, _) => o(
            "Failed",
            Tone::Failed,
            "The action could not run or reported an error.",
        ),
        (TimedOut, _) => o(
            "Timed out",
            Tone::Failed,
            "The device stopped the action at its time limit. Any output is partial.",
        ),
        (Cancelled, _) => o("Cancelled", Tone::Neutral, "Cancelled on request."),
        (Expired, _) => o(
            "Expired",
            Tone::Neutral,
            "The device never received the job before its deadline. It did not run.",
        ),
        (OutcomeUnknown, _) => o(
            "Outcome unknown",
            Tone::Unknown,
            "flyw8t cannot prove whether this ran or what it did. It will update if the device reports a result.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ExecState::*;

    #[test]
    fn terminal_states_have_no_exits() {
        for from in ALL_STATES.into_iter().filter(|s| s.is_terminal()) {
            for to in ALL_STATES {
                assert!(
                    !from.can_transition_to(to),
                    "{from:?} -> {to:?} must be illegal"
                );
            }
        }
    }

    #[test]
    fn nothing_reaches_success_without_passing_through_the_device() {
        // Completed is reachable only from states in which the device holds the job.
        for from in ALL_STATES {
            if from.can_transition_to(Completed) {
                assert!(
                    from.is_in_flight() || from == OutcomeUnknown,
                    "{from:?} -> Completed bypasses the device"
                );
            }
        }
    }

    #[test]
    fn expired_only_from_queued() {
        for from in ALL_STATES {
            assert_eq!(from.can_transition_to(Expired), from == Queued, "{from:?}");
        }
    }

    #[test]
    fn outcome_unknown_resolves_only_to_final_states() {
        for to in ALL_STATES {
            let ok = OutcomeUnknown.can_transition_to(to);
            assert_eq!(
                ok,
                matches!(to, Completed | Failed | TimedOut | Cancelled),
                "{to:?}"
            );
        }
    }

    #[test]
    fn no_self_transitions() {
        for s in ALL_STATES {
            assert!(!s.can_transition_to(s), "{s:?}");
        }
    }

    #[test]
    fn requeue_is_only_from_dispatched() {
        for from in ALL_STATES {
            assert_eq!(
                from.can_transition_to(Queued),
                from == Authorized || from == Dispatched,
                "{from:?}"
            );
        }
    }

    #[test]
    fn state_names_round_trip() {
        for s in ALL_STATES {
            assert_eq!(ExecState::parse(s.as_str()), Some(s));
        }
        assert_eq!(ExecState::parse("succeeded"), None);
    }

    #[test]
    fn outcome_mapping_is_honest() {
        assert_eq!(
            state_for_outcome(&ExecOutcome::Exited { code: 1 }),
            Completed
        );
        assert_eq!(state_for_outcome(&ExecOutcome::Collected), Completed);
        assert_eq!(state_for_outcome(&ExecOutcome::TimedOut), TimedOut);
        assert_eq!(
            state_for_outcome(&ExecOutcome::Interrupted {
                reason: "crash".into()
            }),
            OutcomeUnknown
        );
        assert_eq!(
            state_for_outcome(&ExecOutcome::NotStarted {
                reason: "restart".into()
            }),
            Failed
        );
    }

    #[test]
    fn only_verified_completion_reads_as_success() {
        for s in ALL_STATES {
            for v in [
                Verification::Pending,
                Verification::Verified,
                Verification::Failed,
                Verification::NotApplicable,
            ] {
                let succeeded = outcome(s, v).tone == Tone::Succeeded;
                assert_eq!(
                    succeeded,
                    s == Completed && v == Verification::Verified,
                    "{s:?}/{v:?}"
                );
            }
        }
    }
}
