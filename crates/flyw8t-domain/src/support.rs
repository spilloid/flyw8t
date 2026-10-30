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

pub const ALL_SUPPORT_STATES: [SupportState; 11] = [
    SupportState::Created,
    SupportState::Waiting,
    SupportState::Authorizing,
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

    /// Signaling (SDP/ICE) may be relayed only after the participant's consent.
    pub fn may_relay_signaling(self) -> bool {
        matches!(self, SupportState::Connecting | SupportState::Connected)
    }

    pub fn can_transition_to(self, to: SupportState) -> bool {
        use SupportState::*;
        match self {
            Created => matches!(to, Waiting | Revoked),
            Waiting => matches!(to, Authorizing | Expired | Revoked),
            Authorizing => matches!(to, Connecting | Rejected | Expired | Revoked | Closed),
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

/// What a session may do. Only `ViewScreen` exists: a browser can share pixels, nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ViewScreen,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::ViewScreen => "view_screen",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        (s == "view_screen").then_some(Capability::ViewScreen)
    }

    /// Exactly what the person being helped is told they are allowing.
    pub fn consent_text(self) -> &'static str {
        match self {
            Capability::ViewScreen => {
                "See what you choose to share: one browser tab, one window, or your screen. They cannot click, type, or control anything."
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
        // Connecting (the only way into signaling) is reachable only from Authorizing.
        for from in ALL_SUPPORT_STATES {
            assert_eq!(
                from.can_transition_to(Connecting),
                from == Authorizing,
                "{from:?}"
            );
        }
        assert!(!Waiting.may_relay_signaling());
        assert!(!Authorizing.may_relay_signaling());
        assert!(Connecting.may_relay_signaling());
    }

    #[test]
    fn every_live_state_can_be_ended_by_the_technician() {
        for s in [Created, Waiting, Authorizing, Connecting, Connected] {
            assert!(s.can_transition_to(Revoked), "{s:?}");
        }
    }

    #[test]
    fn names_round_trip() {
        for s in ALL_SUPPORT_STATES {
            assert_eq!(SupportState::parse(s.as_str()), Some(s));
        }
        assert_eq!(
            Capability::parse("control_input"),
            None,
            "control is not a browser capability"
        );
    }
}
