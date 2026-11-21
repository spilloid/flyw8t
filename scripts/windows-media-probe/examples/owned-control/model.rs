//! The entire remote effect surface is this board. No remote event carries an HWND,
//! OS keycode, window message, URL, path or executable action.
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
    seq: u32,
    event: Event,
}

#[derive(Default, Serialize, PartialEq, Eq, Debug)]
pub struct Board {
    pub phase: Phase,
    pub x: u8,
    pub y: u8,
    pub marked: Option<(u8, u8)>,
    pub pressed: bool,
    pub held_key: Option<char>,
    pub text: String,
    pub seq: u32,
}

impl Board {
    /// Only the native window's local Allow handler calls this.
    pub fn allow(&mut self) {
        if self.phase == Phase::Waiting {
            self.phase = Phase::Active;
        }
    }

    pub fn stop(&mut self) {
        self.phase = Phase::Stopped;
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
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn packet(seq: u32, event: Value) -> Vec<u8> {
        json!({"scope":"owned_board", "seq":seq, "event":event})
            .to_string()
            .into_bytes()
    }

    #[test]
    fn only_local_allow_opens_control_and_stop_releases_everything_once() {
        let mut board = Board::default();
        let click = packet(1, json!({"kind":"button","down":true,"x":7,"y":3}));
        assert!(board.apply(&click).is_err());
        assert_eq!(board, Board::default());
        board.allow();
        board.apply(&click).unwrap();
        board
            .apply(&packet(2, json!({"kind":"key","key":"A","down":true})))
            .unwrap();
        assert_eq!(board.marked, Some((7, 3)));
        assert_eq!(board.text, "A");
        assert!(board.pressed && board.held_key == Some('A'));
        board.stop();
        board.stop();
        board.allow();
        assert!(!board.pressed && board.held_key.is_none());
        assert!(board
            .apply(&packet(3, json!({"kind":"move","x":0,"y":0})))
            .is_err());
        assert_eq!(board.phase, Phase::Stopped);
        assert_eq!(board.seq, 2);
    }

    #[test]
    fn malformed_replay_foreign_scope_and_outside_the_board_end_control() {
        let wrong_scope = String::from_utf8(packet(1, json!({"kind":"move","x":0,"y":0})))
            .unwrap()
            .replace("owned_board", "view_screen")
            .into_bytes();
        for bytes in [
            vec![b'x'; 257],
            b"{}".to_vec(),
            wrong_scope,
            packet(2, json!({"kind":"move","x":0,"y":0})),
            packet(1, json!({"kind":"move","x":8,"y":0})),
            packet(1, json!({"kind":"move","x":0,"y":4})),
            packet(1, json!({"kind":"move","x":1,"y":0,"hwnd":4})),
            packet(1, json!({"kind":"allow"})),
            packet(1, json!({"kind":"key","key":"Enter","down":true})),
        ] {
            let mut b = Board::default();
            b.allow();
            assert!(b.apply(&bytes).is_err());
            assert_eq!(b.phase, Phase::Stopped);
            assert_eq!(b.seq, 0);
        }
    }
}
