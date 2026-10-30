//! Live agent connections on this server instance.
//!
//! The registry is the only source for "connected now". It is in-memory and per-instance, so
//! a restart forgets every connection (agents reconnect), and the database's `last_seen_at`
//! is shown as history, never as liveness.

use flyw8t_protocol::ServerMsg;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use time::OffsetDateTime;
use tokio::sync::mpsc;
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
}

#[derive(Default)]
pub struct Registry {
    conns: Mutex<HashMap<Uuid, Conn>>,
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
        let mut conns = self.conns.lock().unwrap();
        if conns.get(&device_id).is_some_and(|cur| cur.seq > conn.seq) {
            return false;
        }
        if let Some(old) = conns.insert(device_id, conn) {
            old.close.cancel();
        }
        true
    }

    /// Remove the device's entry only if it is still this connection.
    pub fn unregister(&self, device_id: Uuid, conn_id: Uuid) {
        let mut conns = self.conns.lock().unwrap();
        if conns.get(&device_id).is_some_and(|c| c.conn_id == conn_id) {
            conns.remove(&device_id);
        }
    }

    pub fn connected_since(&self, device_id: Uuid) -> Option<OffsetDateTime> {
        self.conns.lock().unwrap().get(&device_id).map(|c| c.since)
    }

    pub fn connected_devices(&self) -> Vec<Uuid> {
        self.conns.lock().unwrap().keys().copied().collect()
    }

    /// The id of the device's current connection, if any.
    pub fn current_conn(&self, device_id: Uuid) -> Option<Uuid> {
        self.conns
            .lock()
            .unwrap()
            .get(&device_id)
            .map(|c| c.conn_id)
    }

    /// Queue a message for the device's connection. `false` if not connected or its
    /// outbound buffer is full; the caller must treat the message as not sent.
    pub fn send(&self, device_id: Uuid, msg: ServerMsg) -> bool {
        let tx = self
            .conns
            .lock()
            .unwrap()
            .get(&device_id)
            .map(|c| c.tx.clone());
        tx.is_some_and(|tx| tx.try_send(msg).is_ok())
    }

    /// Like [`send`](Self::send), but only on the given connection. If the device has since
    /// reconnected, nothing is sent and the caller must treat the message as not sent.
    pub fn send_on(&self, device_id: Uuid, conn_id: Uuid, msg: ServerMsg) -> bool {
        let tx = self
            .conns
            .lock()
            .unwrap()
            .get(&device_id)
            .filter(|c| c.conn_id == conn_id)
            .map(|c| c.tx.clone());
        tx.is_some_and(|tx| tx.try_send(msg).is_ok())
    }

    /// Force-close a device's connection (credential revoked).
    pub fn kick(&self, device_id: Uuid) {
        if let Some(c) = self.conns.lock().unwrap().remove(&device_id) {
            c.close.cancel();
        }
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
        }
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
