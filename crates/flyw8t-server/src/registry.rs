//! Live agent connections on this server instance.
//!
//! The registry is the only source for "connected now". It is in-memory and per-instance, so
//! a restart forgets every connection (agents reconnect), and the database's `last_seen_at`
//! is shown as history, never as liveness.

use flyw8t_protocol::ServerMsg;
use std::collections::HashMap;
use std::sync::Mutex;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone)]
pub struct Conn {
    pub conn_id: Uuid,
    pub since: OffsetDateTime,
    pub tx: mpsc::Sender<ServerMsg>,
    pub close: CancellationToken,
}

#[derive(Default)]
pub struct Registry {
    conns: Mutex<HashMap<Uuid, Conn>>,
}

impl Registry {
    /// Register a connection; any older connection for the same device is told to close.
    pub fn register(&self, device_id: Uuid, conn: Conn) {
        if let Some(old) = self.conns.lock().unwrap().insert(device_id, conn) {
            old.close.cancel();
        }
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
