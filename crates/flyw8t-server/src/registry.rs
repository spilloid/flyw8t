//! Live agent connections on this server instance.
//!
//! The registry is the only source for "connected now". It is in-memory and per-instance, so
//! a restart forgets every connection (agents reconnect), and the database's `last_seen_at`
//! is shown as history, never as liveness.

use flyw8t_protocol::messages::{BackgroundTerminalPolicy, CAP_BACKGROUND_TERMINAL_POLICY};
use flyw8t_protocol::script::WindowsExecutionAccount;
use flyw8t_protocol::{PhysicalConsoleState, ServerMsg};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone)]
pub struct Conn {
    pub conn_id: Uuid,
    /// Order of authentication (`Registry::next_seq`), taken before any await, so a slow
    /// older connection cannot displace a newer one that registered first.
    pub seq: u64,
    pub since: OffsetDateTime,
    pub tx: mpsc::Sender<ServerMsg>,
    pub close: CancellationToken,
    pub physical_console_check: bool,
    /// What the agent said it supports when it authenticated (ADR-0015 section 7).
    pub capabilities: Vec<String>,
}

#[derive(Default)]
pub struct Registry {
    live: Mutex<Live>,
}

#[derive(Default)]
struct Live {
    conns: HashMap<Uuid, Conn>,
    /// At most one check per device, also bounded across this server instance.
    checks: HashMap<Uuid, PendingCheck>,
}

const MAX_DEVICE_CHECKS: usize = 32;
const DEVICE_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq)]
enum CheckKind {
    PhysicalConsole,
    BackgroundTerminalPolicy,
}

enum CheckReply {
    PhysicalConsole(PhysicalConsoleState),
    BackgroundTerminalPolicy(BackgroundTerminalObservation),
}

pub(crate) struct BackgroundTerminalObservation {
    pub policy: BackgroundTerminalPolicy,
    pub agent_account: Option<WindowsExecutionAccount>,
}

impl CheckReply {
    fn kind(&self) -> CheckKind {
        match self {
            Self::PhysicalConsole(_) => CheckKind::PhysicalConsole,
            Self::BackgroundTerminalPolicy(_) => CheckKind::BackgroundTerminalPolicy,
        }
    }
}

struct PendingCheck {
    kind: CheckKind,
    conn_id: Uuid,
    request_id: Uuid,
    deadline: Instant,
    reply: Option<oneshot::Sender<CheckReply>>,
}

/// Removing the waiter also covers cancellation of the requesting HTTP handler.
struct CheckGuard<'a> {
    registry: &'a Registry,
    device_id: Uuid,
    conn_id: Uuid,
    request_id: Uuid,
}

impl Drop for CheckGuard<'_> {
    fn drop(&mut self) {
        let mut live = self.registry.live.lock().unwrap();
        if live.checks.get(&self.device_id).is_some_and(|check| {
            check.conn_id == self.conn_id && check.request_id == self.request_id
        }) {
            live.checks.remove(&self.device_id);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConsoleCheckError {
    #[error("the agent is disconnected")]
    NotConnected,
    #[error("the connected agent does not support this check")]
    Unsupported,
    #[error("the agent or server is busy")]
    Busy,
    #[error("the agent did not answer in time")]
    Timeout,
}

impl Registry {
    /// A number that orders connections by when they authenticated.
    pub fn next_seq() -> u64 {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        SEQ.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a connection; any older connection for the same device is told to close.
    /// Returns `false`, registering nothing, if a newer connection is already registered:
    /// the newest authentication always wins, whatever order the registrations arrive in.
    pub fn register(&self, device_id: Uuid, conn: Conn) -> bool {
        let mut live = self.live.lock().unwrap();
        if live
            .conns
            .get(&device_id)
            .is_some_and(|cur| cur.seq > conn.seq)
        {
            return false;
        }
        if let Some(old) = live.conns.insert(device_id, conn) {
            live.checks.remove(&device_id);
            old.close.cancel();
        }
        true
    }

    /// Remove the device's entry only if it is still this connection.
    pub fn unregister(&self, device_id: Uuid, conn_id: Uuid) {
        let mut live = self.live.lock().unwrap();
        if live
            .conns
            .get(&device_id)
            .is_some_and(|c| c.conn_id == conn_id)
        {
            live.conns.remove(&device_id);
            live.checks.remove(&device_id);
        }
    }

    pub fn connected_since(&self, device_id: Uuid) -> Option<OffsetDateTime> {
        self.live
            .lock()
            .unwrap()
            .conns
            .get(&device_id)
            .map(|c| c.since)
    }

    pub fn connected_devices(&self) -> Vec<Uuid> {
        self.live.lock().unwrap().conns.keys().copied().collect()
    }

    /// The id of the device's current connection, if any.
    pub fn current_conn(&self, device_id: Uuid) -> Option<Uuid> {
        self.live
            .lock()
            .unwrap()
            .conns
            .get(&device_id)
            .map(|c| c.conn_id)
    }

    /// Queue a message for the device's connection. `false` if not connected or its
    /// outbound buffer is full; the caller must treat the message as not sent.
    pub fn send(&self, device_id: Uuid, msg: ServerMsg) -> bool {
        let tx = self
            .live
            .lock()
            .unwrap()
            .conns
            .get(&device_id)
            .map(|c| c.tx.clone());
        tx.is_some_and(|tx| tx.try_send(msg).is_ok())
    }

    /// Like [`send`](Self::send), but only on the given connection. If the device has since
    /// reconnected, nothing is sent and the caller must treat the message as not sent.
    pub fn send_on(&self, device_id: Uuid, conn_id: Uuid, msg: ServerMsg) -> bool {
        let tx = self
            .live
            .lock()
            .unwrap()
            .conns
            .get(&device_id)
            .filter(|c| c.conn_id == conn_id)
            .map(|c| c.tx.clone());
        tx.is_some_and(|tx| tx.try_send(msg).is_ok())
    }

    /// Whether the device's connection `conn_id` said it supports `cap`.
    pub fn has_capability(&self, device_id: Uuid, conn_id: Uuid, cap: &str) -> bool {
        self.live
            .lock()
            .unwrap()
            .conns
            .get(&device_id)
            .is_some_and(|c| c.conn_id == conn_id && c.capabilities.iter().any(|x| x == cap))
    }

    /// Force-close a device's connection (credential revoked).
    pub fn kick(&self, device_id: Uuid) {
        let mut live = self.live.lock().unwrap();
        if let Some(c) = live.conns.remove(&device_id) {
            live.checks.remove(&device_id);
            c.close.cancel();
        }
    }

    /// Ask the current authenticated connection once. The server supplies a fresh audit
    /// correlation ID. A replacement connection must receive a new request of its own.
    pub async fn check_physical_console(
        &self,
        device_id: Uuid,
        request_id: Uuid,
    ) -> Result<PhysicalConsoleState, ConsoleCheckError> {
        self.check_until(device_id, request_id, Instant::now() + DEVICE_CHECK_TIMEOUT)
            .await
    }

    async fn check_until(
        &self,
        device_id: Uuid,
        request_id: Uuid,
        deadline: Instant,
    ) -> Result<PhysicalConsoleState, ConsoleCheckError> {
        match self
            .observe(
                device_id,
                request_id,
                CheckKind::PhysicalConsole,
                deadline,
                None,
            )
            .await?
        {
            (_, CheckReply::PhysicalConsole(state)) => Ok(state),
            _ => Err(ConsoleCheckError::Unsupported),
        }
    }

    /// Check local policy once on the authenticated connection, within the confirmation window.
    /// The result is only an observation.
    pub(crate) async fn check_background_terminal_policy(
        &self,
        device_id: Uuid,
        request_id: Uuid,
        expected_connection: Option<Uuid>,
        valid_until: Option<Instant>,
    ) -> Result<(Uuid, BackgroundTerminalObservation), ConsoleCheckError> {
        let deadline = Instant::now() + DEVICE_CHECK_TIMEOUT;
        match self
            .observe(
                device_id,
                request_id,
                CheckKind::BackgroundTerminalPolicy,
                valid_until.map_or(deadline, |expires| expires.min(deadline)),
                expected_connection,
            )
            .await?
        {
            (connection, CheckReply::BackgroundTerminalPolicy(report)) => Ok((connection, report)),
            _ => Err(ConsoleCheckError::Unsupported),
        }
    }

    async fn observe(
        &self,
        device_id: Uuid,
        request_id: Uuid,
        kind: CheckKind,
        deadline: Instant,
        expected_connection: Option<Uuid>,
    ) -> Result<(Uuid, CheckReply), ConsoleCheckError> {
        let (guard, reply) = {
            let mut live = self.live.lock().unwrap();
            let conn = live
                .conns
                .get(&device_id)
                .ok_or(ConsoleCheckError::NotConnected)?;
            if expected_connection.is_some_and(|id| id != conn.conn_id) {
                return Err(ConsoleCheckError::NotConnected);
            }
            let message = match kind {
                CheckKind::PhysicalConsole if conn.physical_console_check => {
                    ServerMsg::CheckPhysicalConsole { request_id }
                }
                CheckKind::BackgroundTerminalPolicy
                    if conn
                        .capabilities
                        .iter()
                        .any(|cap| cap == CAP_BACKGROUND_TERMINAL_POLICY) =>
                {
                    ServerMsg::CheckBackgroundTerminalPolicy { request_id }
                }
                _ => return Err(ConsoleCheckError::Unsupported),
            };
            if live.checks.len() >= MAX_DEVICE_CHECKS || live.checks.contains_key(&device_id) {
                return Err(ConsoleCheckError::Busy);
            }
            // A caller can wait for the registry lock after checking its own deadline.
            if Instant::now() >= deadline {
                return Err(ConsoleCheckError::Timeout);
            }
            let conn_id = conn.conn_id;
            conn.tx.try_send(message).map_err(|err| match err {
                mpsc::error::TrySendError::Full(_) => ConsoleCheckError::Busy,
                mpsc::error::TrySendError::Closed(_) => ConsoleCheckError::NotConnected,
            })?;
            let (tx, rx) = oneshot::channel();
            live.checks.insert(
                device_id,
                PendingCheck {
                    kind,
                    conn_id,
                    request_id,
                    deadline,
                    reply: Some(tx),
                },
            );
            (
                CheckGuard {
                    registry: self,
                    device_id,
                    conn_id,
                    request_id,
                },
                rx,
            )
        };
        let state = tokio::time::timeout_at(deadline, reply)
            .await
            .map_err(|_| ConsoleCheckError::Timeout)?
            .map_err(|_| ConsoleCheckError::NotConnected)?;
        if self.current_conn(device_id) != Some(guard.conn_id) {
            return Err(ConsoleCheckError::NotConnected);
        }
        Ok((guard.conn_id, state))
    }

    /// A reply has meaning only for its currently registered socket, expected request and deadline.
    pub(crate) fn physical_console_status(
        &self,
        device_id: Uuid,
        conn_id: Uuid,
        request_id: Uuid,
        state: PhysicalConsoleState,
    ) -> bool {
        self.receive_observation(
            device_id,
            conn_id,
            request_id,
            CheckReply::PhysicalConsole(state),
        )
    }

    pub(crate) fn background_terminal_policy_status(
        &self,
        device_id: Uuid,
        conn_id: Uuid,
        request_id: Uuid,
        policy: BackgroundTerminalPolicy,
        agent_account: Option<WindowsExecutionAccount>,
    ) -> bool {
        self.receive_observation(
            device_id,
            conn_id,
            request_id,
            CheckReply::BackgroundTerminalPolicy(BackgroundTerminalObservation {
                policy,
                agent_account,
            }),
        )
    }

    fn receive_observation(
        &self,
        device_id: Uuid,
        conn_id: Uuid,
        request_id: Uuid,
        state: CheckReply,
    ) -> bool {
        let mut live = self.live.lock().unwrap();
        let Some(check) = live.checks.get_mut(&device_id) else {
            return false;
        };
        if check.conn_id != conn_id
            || check.request_id != request_id
            || check.kind != state.kind()
            || Instant::now() >= check.deadline
        {
            return false;
        }
        check
            .reply
            .take()
            .is_some_and(|reply| reply.send(state).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(seq: u64) -> Conn {
        let (tx, _rx) = mpsc::channel(1);
        Conn {
            conn_id: Uuid::new_v4(),
            seq,
            since: OffsetDateTime::now_utc(),
            tx,
            close: CancellationToken::new(),
            physical_console_check: false,
            capabilities: vec![],
        }
    }

    fn connect(
        registry: &Registry,
        device: Uuid,
        capable: bool,
    ) -> (Uuid, mpsc::Receiver<ServerMsg>) {
        let (tx, rx) = mpsc::channel(1);
        let conn = Conn {
            tx,
            physical_console_check: capable,
            ..conn(Registry::next_seq())
        };
        let id = conn.conn_id;
        assert!(registry.register(device, conn));
        (id, rx)
    }

    #[tokio::test]
    async fn only_the_requested_live_socket_can_supply_a_console_observation() {
        let r = Registry::default();
        let device = Uuid::new_v4();
        let other = Uuid::new_v4();
        let request = Uuid::new_v4();
        let state = PhysicalConsoleState::ActiveConsole;
        assert_eq!(
            r.check_physical_console(device, request).await,
            Err(ConsoleCheckError::NotConnected)
        );
        let (_, mut old_rx) = connect(&r, device, false);
        assert_eq!(
            r.check_physical_console(device, request).await,
            Err(ConsoleCheckError::Unsupported)
        );
        assert!(matches!(
            old_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let (id, mut rx) = connect(&r, device, true);
        let (other_id, _other_rx) = connect(&r, other, true);
        let mut check = Box::pin(r.check_physical_console(device, request));
        assert!(futures_util::poll!(&mut check).is_pending());
        assert_eq!(
            rx.try_recv().unwrap(),
            ServerMsg::CheckPhysicalConsole {
                request_id: request
            }
        );
        assert_eq!(
            r.check_physical_console(device, Uuid::new_v4()).await,
            Err(ConsoleCheckError::Busy)
        );
        assert!(!r.physical_console_status(other, other_id, request, state));
        assert!(!r.physical_console_status(device, other_id, request, state));
        assert!(!r.physical_console_status(device, id, Uuid::new_v4(), state));
        assert!(r.physical_console_status(device, id, request, state));
        assert!(!r.physical_console_status(device, id, request, state));
        assert_eq!(check.await, Ok(state));
        assert!(!r.physical_console_status(device, id, request, state));
    }

    #[tokio::test]
    async fn replacement_revocation_and_disconnect_invalidate_in_flight_console_checks() {
        let r = Registry::default();
        let device = Uuid::new_v4();
        let request = Uuid::new_v4();
        let state = PhysicalConsoleState::NoConsole;
        let (old, _rx) = connect(&r, device, true);
        let mut first = Box::pin(r.check_physical_console(device, request));
        assert!(futures_util::poll!(&mut first).is_pending());
        let (current, _rx) = connect(&r, device, true);
        let next_request = Uuid::new_v4();
        let mut second = Box::pin(r.check_physical_console(device, next_request));
        assert!(futures_util::poll!(&mut second).is_pending());
        assert_eq!(first.await, Err(ConsoleCheckError::NotConnected));
        r.unregister(device, old);
        assert!(!r.physical_console_status(device, old, next_request, state));
        assert!(!r.physical_console_status(device, current, request, state));
        // Even an accepted response waiting to be read is unusable after revocation.
        assert!(r.physical_console_status(device, current, next_request, state));
        r.kick(device);
        assert_eq!(second.await, Err(ConsoleCheckError::NotConnected));
        let (current, _rx) = connect(&r, device, true);
        let mut third = Box::pin(r.check_physical_console(device, Uuid::new_v4()));
        assert!(futures_util::poll!(&mut third).is_pending());
        r.unregister(device, current);
        assert_eq!(third.await, Err(ConsoleCheckError::NotConnected));
    }

    #[tokio::test]
    async fn expired_and_cancelled_checks_release_the_slot_and_late_replies_are_ignored() {
        let r = Registry::default();
        let device = Uuid::new_v4();
        let (id, mut rx) = connect(&r, device, true);
        let request = Uuid::new_v4();
        let state = PhysicalConsoleState::NoInteractiveUser;
        assert_eq!(
            r.check_until(device, request, Instant::now()).await,
            Err(ConsoleCheckError::Timeout)
        );
        assert_eq!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        assert!(!r.physical_console_status(device, id, request, state));
        let cancelled = Uuid::new_v4();
        let mut check = Box::pin(r.check_physical_console(device, cancelled));
        assert!(futures_util::poll!(&mut check).is_pending());
        drop(check);
        // Its unsent frame still occupies the one-entry test channel.
        assert_eq!(
            r.check_physical_console(device, Uuid::new_v4()).await,
            Err(ConsoleCheckError::Busy)
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            ServerMsg::CheckPhysicalConsole {
                request_id: cancelled
            }
        );
        let fresh = Uuid::new_v4();
        let mut check = Box::pin(r.check_physical_console(device, fresh));
        assert!(futures_util::poll!(&mut check).is_pending());
        assert!(!r.physical_console_status(device, id, cancelled, state));
        assert!(r.physical_console_status(device, id, fresh, state));
        assert_eq!(check.await, Ok(state));
        drop(rx);
        assert_eq!(
            r.check_physical_console(device, Uuid::new_v4()).await,
            Err(ConsoleCheckError::NotConnected)
        );
    }

    #[tokio::test]
    async fn console_waiters_are_bounded_for_the_whole_instance() {
        let r = Registry::default();
        let mut checks = Vec::new();
        for _ in 0..MAX_DEVICE_CHECKS {
            let device = Uuid::new_v4();
            let (_, rx) = connect(&r, device, true);
            let mut check = Box::pin(r.check_physical_console(device, Uuid::new_v4()));
            assert!(futures_util::poll!(&mut check).is_pending());
            checks.push((rx, check));
        }
        let device = Uuid::new_v4();
        let (_, mut rx) = connect(&r, device, true);
        assert_eq!(
            r.check_physical_console(device, Uuid::new_v4()).await,
            Err(ConsoleCheckError::Busy)
        );
        assert!(rx.try_recv().is_err());
        drop(checks);
        let mut check = Box::pin(r.check_physical_console(device, Uuid::new_v4()));
        assert!(futures_util::poll!(&mut check).is_pending());
    }

    #[test]
    fn the_newest_authentication_wins_in_any_registration_order() {
        let r = Registry::default();
        let d = Uuid::new_v4();
        let (older, newer) = (conn(1), conn(2));
        let (older_close, newer_close) = (older.close.clone(), newer.close.clone());
        let newer_id = newer.conn_id;
        // The newer connection registers first; the older one arrives late.
        assert!(r.register(d, newer));
        assert!(
            !r.register(d, older),
            "a late, older connection must not displace a newer one"
        );
        assert_eq!(r.current_conn(d), Some(newer_id));
        assert!(!newer_close.is_cancelled());
        assert!(
            !older_close.is_cancelled(),
            "the caller refuses it; the registry did not hold it"
        );
        // In the usual order, the newer one supersedes the older.
        let r = Registry::default();
        let (older, newer) = (conn(3), conn(4));
        let older_close = older.close.clone();
        assert!(r.register(d, older));
        assert!(r.register(d, newer));
        assert!(older_close.is_cancelled());
    }
}
