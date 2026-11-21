//! One board per connection. Only its verified peer and locally approved Windows
//! login can reach the board model. All transitions share the input mutex.
use super::login::{self, Login};
use super::model::{Board, Phase};

type Observation = Result<Login, &'static str>;

pub struct BoardSession {
    board: Board,
    login: Option<Login>,
    observe: Box<dyn Fn() -> Observation + Send + Sync>,
    code: Option<String>,
}

impl Default for BoardSession {
    fn default() -> Self {
        Self {
            board: Board::default(),
            login: None,
            observe: Box::new(login::current),
            code: None,
        }
    }
}

impl BoardSession {
    #[cfg(test)]
    pub fn with_observer(observe: impl Fn() -> Observation + Send + Sync + 'static) -> Self {
        Self {
            observe: Box::new(observe),
            ..Self::default()
        }
    }

    pub fn board(&self) -> &Board {
        &self.board
    }

    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    // Called once, after notification registration and before sending an offer.
    pub fn bind_login(&mut self) -> Result<(), &'static str> {
        if self.board.phase != Phase::Waiting || self.login.is_some() || self.code.is_some() {
            self.stop();
            return Err("cannot replace the board login");
        }
        match (self.observe)() {
            Ok(login) => {
                self.login = Some(login);
                Ok(())
            }
            Err(reason) => {
                self.stop();
                Err(reason)
            }
        }
    }

    pub fn check_login(&mut self) -> bool {
        if self.board.phase == Phase::Stopped {
            return false;
        }
        // A refusal-only run may exchange a certificate but cannot grant input.
        if let Some(expected) = self.login {
            if (self.observe)() != Ok(expected) {
                self.stop();
                return false;
            }
        }
        true
    }

    // Only the owner of this channel can call this, once, after checking the
    // observed DTLS pair. A reconnect creates another board and another consent.
    pub fn peer_verified(&mut self, code: String) -> Result<(), &'static str> {
        if self.code.is_some() || !self.check_login() {
            self.stop();
            return Err("board authorization ended before peer verification");
        }
        self.code = Some(code);
        Ok(())
    }

    pub fn allow(&mut self) {
        if self.code.is_some() && self.login.is_some() && self.check_login() {
            self.board.allow();
        }
    }

    pub fn apply(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if self.code.is_none() || self.login.is_none() || !self.check_login() {
            self.stop();
            return Err("board login or connection is no longer authorized");
        }
        let result = self.board.apply(bytes);
        if result.is_err() {
            self.stop();
        }
        result
    }

    pub fn stop(&mut self) {
        self.board.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use super::super::model::test_packet;
    use serde_json::json;

    fn session() -> (BoardSession, Arc<Mutex<Observation>>) {
        let observed = Arc::new(Mutex::new(Ok(login::fixture(3, 100))));
        let input = observed.clone();
        let mut session = BoardSession::with_observer(move || *input.lock().unwrap());
        session.bind_login().unwrap();
        (session, observed)
    }

    #[test]
    fn login_replacement_at_handshake_or_allow_ends_the_original_authorization() {
        for after_peer in [false, true] {
            let (mut s, observed) = session();
            if after_peer {
                s.peer_verified("012345".into()).unwrap();
            }
            *observed.lock().unwrap() = Ok(login::fixture(3, 101));
            if after_peer {
                s.allow();
            } else {
                assert!(s.peer_verified("012345".into()).is_err());
            }
            assert_eq!(s.board().phase, Phase::Stopped);
            *observed.lock().unwrap() = Ok(login::fixture(3, 100));
            assert!(s.bind_login().is_err());
            s.allow();
            assert!(s
                .apply(&test_packet(
                    s.board(),
                    1,
                    json!({"kind":"button","x":1,"y":1,"down":true})
                ))
                .is_err());
        }
    }

    #[test]
    fn invalid_login_releases_held_input_and_discards_a_queued_event() {
        for loss in [
            Err("locked"),
            Ok(login::fixture(3, 101)),
            Ok(login::fixture(4, 100)),
        ] {
            let (mut s, observed) = session();
            s.allow();
            assert_eq!(s.board().phase, Phase::Waiting);
            s.peer_verified("012345".into()).unwrap();
            s.allow();
            let press = test_packet(
                s.board(),
                1,
                json!({"kind":"button","x":1,"y":1,"down":true}),
            );
            let key = test_packet(s.board(), 2, json!({"kind":"key","key":"a","down":true}));
            let queued = test_packet(s.board(), 3, json!({"kind":"move","x":4,"y":1}));
            s.apply(&press).unwrap();
            s.apply(&key).unwrap();
            *observed.lock().unwrap() = loss;
            assert!(s.apply(&queued).is_err());
            assert_eq!(s.board().seq, 2);
            assert_eq!(s.board().phase, Phase::Stopped);
            assert!(!s.board().pressed && s.board().held_key.is_none());
            assert!(s.peer_verified("654321".into()).is_err());
            *observed.lock().unwrap() = Ok(login::fixture(3, 100));
            s.allow();
            assert!(s.apply(&queued).is_err());
        }
    }
}
