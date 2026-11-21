//! The entire remote effect surface is this board. No remote event carries an HWND,
//! OS keycode, window message, URL, path or executable action.
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

pub const COLUMNS: u8 = 8;
pub const ROWS: u8 = 4;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    #[default]
    Waiting,
    Active,
    Stopped,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Move { x: u8, y: u8 },
    Button { x: u8, y: u8, down: bool },
    Key { key: String, down: bool },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    scope: String,
    activation: String,
    seq: u32,
    event: Event,
}

#[derive(Default, Serialize, PartialEq, Eq, Debug)]
pub struct Board {
    pub phase: Phase,
    #[serde(skip_serializing_if = "Option::is_none")]
    activation: Option<String>,
    pub x: u8,
    pub y: u8,
    pub marked: Option<(u8, u8)>,
    pub pressed: bool,
    pub held_key: Option<char>,
    pub text: String,
    pub seq: u32,
}

impl Board {
    /// Only the native window's local Allow handler activates this connection.
    pub fn allow(&mut self) {
        if self.phase == Phase::Waiting {
            // The peer can first learn this value in the state sent after Allow.
            // A packet prepared before consent cannot become valid while queued.
            let mut bytes = [0u8; 32];
            if SystemRandom::new().fill(&mut bytes).is_err() {
                self.stop();
                return;
            }
            self.activation = Some(hex::encode(bytes));
            self.phase = Phase::Active;
        }
    }

    pub fn stop(&mut self) {
        self.phase = Phase::Stopped;
        self.activation = None;
        self.release();
    }

    fn release(&mut self) {
        self.pressed = false;
        self.held_key = None;
    }

    pub fn apply(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if self.phase != Phase::Active {
            return Err("local control permission required");
        }
        let result = self.apply_active(bytes);
        if result.is_err() {
            self.stop();
        }
        result
    }

    fn apply_active(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.len() > 256 {
            return Err("oversized fixture input");
        }
        let p: Packet = serde_json::from_slice(bytes).map_err(|_| "invalid fixture input")?;
        if self.activation.as_deref() != Some(p.activation.as_str()) {
            return Err("wrong board activation");
        }
        if p.scope != "owned_board" || self.seq.checked_add(1) != Some(p.seq) {
            return Err("wrong scope or sequence");
        }
        match p.event {
            Event::Move { x, y } => self.position(x, y)?,
            Event::Button { x, y, down } => {
                if self.pressed == down {
                    return Err("unpaired button transition");
                }
                self.position(x, y)?;
                self.pressed = down;
                if down {
                    self.marked = Some((x, y));
                }
            }
            Event::Key { key, down } => {
                let c = if key == "Backspace" {
                    '\u{8}'
                } else if key.len() == 1 && (key.as_bytes()[0].is_ascii_graphic() || key == " ") {
                    key.as_bytes()[0] as char
                } else {
                    return Err("unsupported board key");
                };
                if down && self.held_key.is_none() {
                    self.held_key = Some(c);
                    if c == '\u{8}' {
                        self.text.pop();
                    } else if self.text.len() < 64 {
                        self.text.push(c);
                    }
                } else if !down && self.held_key == Some(c) {
                    self.held_key = None;
                } else {
                    return Err("unpaired key transition");
                }
            }
        }
        self.seq = p.seq;
        Ok(())
    }

    fn position(&mut self, x: u8, y: u8) -> Result<(), &'static str> {
        if x >= COLUMNS || y >= ROWS {
            return Err("outside the test board");
        }
        self.x = x;
        self.y = y;
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn test_packet(board: &Board, seq: u32, event: serde_json::Value) -> Vec<u8> {
    // Use the wire representation available to a viewer, including the
    // activation only when the endpoint published it.
    let state = serde_json::to_value(board).unwrap();
    let mut packet = serde_json::json!({"scope":"owned_board", "seq":seq, "event":event});
    if let Some(activation) = state.get("activation") {
        packet["activation"] = activation.clone();
    }
    serde_json::to_vec(&packet).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn only_local_allow_opens_control_and_stop_releases_everything_once() {
        let mut board = Board::default();
        let click = json!({"kind":"button","down":true,"x":7,"y":3});
        assert!(board.apply(&test_packet(&board, 1, click.clone())).is_err());
        assert_eq!(board, Board::default());
        board.allow();
        board.apply(&test_packet(&board, 1, click)).unwrap();
        board
            .apply(&test_packet(
                &board,
                2,
                json!({"kind":"key","key":"A","down":true}),
            ))
            .unwrap();
        assert_eq!(board.marked, Some((7, 3)));
        assert_eq!(board.text, "A");
        assert!(board.pressed && board.held_key == Some('A'));
        let queued = test_packet(&board, 3, json!({"kind":"move","x":0,"y":0}));
        board.stop();
        board.stop();
        board.allow();
        assert!(!board.pressed && board.held_key.is_none());
        assert!(board.apply(&queued).is_err());
        assert_eq!(board.phase, Phase::Stopped);
        assert_eq!(board.seq, 2);
    }

    #[test]
    fn a_queued_preconsent_packet_and_a_previous_activation_cannot_authorize_input() {
        let mut original = Board::default();
        let event = json!({"kind":"key","key":"A","down":true});
        let queued = test_packet(&original, 1, event.clone());
        assert!(serde_json::to_value(&original)
            .unwrap()
            .get("activation")
            .is_none());
        original.allow();
        let live = test_packet(&original, 1, event);
        assert!(live.len() <= 256);
        let active: Value = serde_json::from_slice(&live).unwrap();
        let activation = active["activation"].as_str().unwrap();
        assert_eq!(activation.len(), 64);

        // Even a valid event with the next sequence number must have been
        // constructed after the participant's decision on this very board.
        assert!(original.apply(&queued).is_err());
        assert_eq!(original.phase, Phase::Stopped);
        assert_eq!(original.seq, 0);
        assert!(serde_json::to_value(&original)
            .unwrap()
            .get("activation")
            .is_none());
        let mut next = Board::default();
        next.allow();
        assert_ne!(next.activation.as_deref(), Some(activation));
        assert_eq!(next.apply(&live), Err("wrong board activation"));
        assert_eq!(next.seq, 0);
        assert!(next.text.is_empty() && next.held_key.is_none());
        assert_eq!(next.phase, Phase::Stopped);
    }

    #[test]
    fn malformed_replay_foreign_scope_and_outside_the_board_end_control() {
        for (scope, seq, event, expected) in [
            (
                "view_screen",
                1,
                json!({"kind":"move","x":0,"y":0}),
                "wrong scope or sequence",
            ),
            (
                "owned_board",
                2,
                json!({"kind":"move","x":0,"y":0}),
                "wrong scope or sequence",
            ),
            (
                "owned_board",
                1,
                json!({"kind":"move","x":8,"y":0}),
                "outside the test board",
            ),
            (
                "owned_board",
                1,
                json!({"kind":"move","x":0,"y":4}),
                "outside the test board",
            ),
            (
                "owned_board",
                1,
                json!({"kind":"move","x":1,"y":0,"hwnd":4}),
                "invalid fixture input",
            ),
            (
                "owned_board",
                1,
                json!({"kind":"allow"}),
                "invalid fixture input",
            ),
            (
                "owned_board",
                1,
                json!({"kind":"key","key":"Enter","down":true}),
                "unsupported board key",
            ),
        ] {
            let mut b = Board::default();
            b.allow();
            let mut packet: Value = serde_json::from_slice(&test_packet(&b, seq, event)).unwrap();
            packet["scope"] = json!(scope);
            assert_eq!(
                b.apply(&serde_json::to_vec(&packet).unwrap()),
                Err(expected)
            );
            assert_eq!(b.phase, Phase::Stopped);
            assert_eq!(b.seq, 0);
        }
        for bytes in [vec![b'x'; 257], b"{}".to_vec()] {
            let mut b = Board::default();
            b.allow();
            assert!(b.apply(&bytes).is_err());
            assert_eq!(b.phase, Phase::Stopped);
            assert_eq!(b.seq, 0);
        }
    }
}
