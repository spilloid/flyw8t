//! Attended support session lifecycle. See `docs/attended-support.md`.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportState {
    Created,
    /// Invitation issued; nobody has opened it.
    Waiting,
    /// The remote participant is bound and sees the consent screen.
    Authorizing,
    /// A control session: the participant allowed control in the browser and was given the
    /// helper; nothing flows until the helper attaches and the person allows it there too.
    AwaitingHelper,
    /// Consent given; media negotiating.
    Connecting,
    Connected,
    Disconnecting,
    Closed,
    Expired,
    Rejected,
    ConnectionFailed,
    Revoked,
}

pub const ALL_SUPPORT_STATES: [SupportState; 12] = [
    SupportState::Created,
    SupportState::Waiting,
    SupportState::Authorizing,
    SupportState::AwaitingHelper,
    SupportState::Connecting,
    SupportState::Connected,
    SupportState::Disconnecting,
    SupportState::Closed,
    SupportState::Expired,
    SupportState::Rejected,
    SupportState::ConnectionFailed,
    SupportState::Revoked,
];

impl SupportState {
    pub fn as_str(self) -> &'static str {
        match self {
            SupportState::Created => "created",
            SupportState::Waiting => "waiting",
            SupportState::Authorizing => "authorizing",
            SupportState::AwaitingHelper => "awaiting_helper",
            SupportState::Connecting => "connecting",
            SupportState::Connected => "connected",
            SupportState::Disconnecting => "disconnecting",
            SupportState::Closed => "closed",
            SupportState::Expired => "expired",
            SupportState::Rejected => "rejected",
            SupportState::ConnectionFailed => "connection_failed",
            SupportState::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        ALL_SUPPORT_STATES.into_iter().find(|x| x.as_str() == s)
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            SupportState::Closed
                | SupportState::Expired
                | SupportState::Rejected
                | SupportState::ConnectionFailed
                | SupportState::Revoked
        )
    }

    /// Where the participant's Allow in the browser leads. A control session never reaches
    /// `Connecting` from the browser alone: the helper must attach and be allowed too.
    pub fn after_browser_consent(control: bool) -> SupportState {
        if control {
            SupportState::AwaitingHelper
        } else {
            SupportState::Connecting
        }
    }

    /// Signaling (SDP/ICE) may be relayed only after the participant's consent.
    pub fn may_relay_signaling(self) -> bool {
        matches!(self, SupportState::Connecting | SupportState::Connected)
    }

    pub fn can_transition_to(self, to: SupportState) -> bool {
        use SupportState::*;
        match self {
            Created => matches!(to, Waiting | Revoked),
            Waiting => matches!(to, Authorizing | Expired | Revoked),
            Authorizing => matches!(
                to,
                Connecting | AwaitingHelper | Rejected | Expired | Revoked | Closed
            ),
            AwaitingHelper => matches!(to, Connecting | Rejected | Expired | Revoked | Closed),
            Connecting => matches!(to, Connected | ConnectionFailed | Disconnecting | Revoked),
            Connected => matches!(to, Disconnecting | ConnectionFailed | Revoked),
            Disconnecting => to == Closed,
            Closed | Expired | Rejected | ConnectionFailed | Revoked => false,
        }
    }

    /// Plain-language label for both participants.
    pub fn label(self) -> &'static str {
        match self {
            SupportState::Created | SupportState::Waiting => {
                "Waiting for the other person to open the invitation"
            }
            SupportState::Authorizing => "Waiting for the other person to allow or decline",
            SupportState::AwaitingHelper => {
                "Waiting for the other person to start the flyw8t helper and allow control"
            }
            SupportState::Connecting => "Allowed. Connecting…",
            SupportState::Connected => "Connected",
            SupportState::Disconnecting => "Ending…",
            SupportState::Closed => "Ended",
            SupportState::Expired => "Expired before it was used",
            SupportState::Rejected => "Declined",
            SupportState::ConnectionFailed => "Could not connect",
            SupportState::Revoked => "Ended by the technician",
        }
    }
}

/// What a session may do. A browser can share pixels and nothing more (`ViewScreen`); input
/// needs the native helper and its own consent (`ControlInput`, ADR-0012).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ViewScreen,
    /// Keyboard and mouse, through the native helper (ADR-0012). Always includes viewing.
    ControlInput,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::ViewScreen => "view_screen",
            Capability::ControlInput => "control_input",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "view_screen" => Some(Capability::ViewScreen),
            "control_input" => Some(Capability::ControlInput),
            _ => None,
        }
    }

    /// Exactly what the person being helped is told they are allowing.
    pub fn consent_text(self) -> &'static str {
        match self {
            Capability::ViewScreen => {
                "See what you choose to share: one browser tab, one window, or your screen. They cannot click, type, or control anything unless control is also listed here."
            }
            Capability::ControlInput => {
                "Use your mouse and keyboard, after you start the flyw8t helper and allow it there too. You see who is in control the whole time and can stop it at once. It cannot reach administrator (UAC) prompts and leaves nothing installed."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SupportState::*;

    #[test]
    fn terminal_states_are_final() {
        for from in ALL_SUPPORT_STATES.into_iter().filter(|s| s.is_terminal()) {
            for to in ALL_SUPPORT_STATES {
                assert!(!from.can_transition_to(to), "{from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn media_requires_passing_through_consent() {
        // Connecting (the only way into signaling) is reachable only from a consent state, and
        // AwaitingHelper only from the browser consent.
        for from in ALL_SUPPORT_STATES {
            assert_eq!(
                from.can_transition_to(Connecting),
                matches!(from, Authorizing | AwaitingHelper),
                "{from:?}"
            );
            assert_eq!(
                from.can_transition_to(AwaitingHelper),
                from == Authorizing,
                "{from:?}"
            );
        }
        assert!(!Waiting.may_relay_signaling());
        assert!(!Authorizing.may_relay_signaling());
        assert!(
            !AwaitingHelper.may_relay_signaling(),
            "nothing flows before the helper is allowed"
        );
        assert_eq!(SupportState::after_browser_consent(true), AwaitingHelper);
        assert_eq!(SupportState::after_browser_consent(false), Connecting);
        assert!(Connecting.may_relay_signaling());
    }

    #[test]
    fn every_live_state_can_be_ended_by_the_technician() {
        for s in [
            Created,
            Waiting,
            Authorizing,
            AwaitingHelper,
            Connecting,
            Connected,
        ] {
            assert!(s.can_transition_to(Revoked), "{s:?}");
        }
    }

    #[test]
    fn names_round_trip() {
        for s in ALL_SUPPORT_STATES {
            assert_eq!(SupportState::parse(s.as_str()), Some(s));
        }
        for c in [Capability::ViewScreen, Capability::ControlInput] {
            assert_eq!(Capability::parse(c.as_str()), Some(c));
        }
        assert_eq!(Capability::parse("run_shell"), None);
    }
}
