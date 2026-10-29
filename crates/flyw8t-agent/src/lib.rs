//! The flyw8t endpoint agent.
//!
//! One outbound, authenticated WebSocket to the server; a durable on-disk journal that makes
//! job execution at-most-once across disconnects, duplicate deliveries and agent restarts; and
//! a small, compiled-in catalog of read-only actions. See `docs/architecture.md`.

pub mod collect;
pub mod config;
pub mod connection;
pub mod executor;
pub mod identity;
pub mod journal;
#[cfg(windows)]
pub mod service;
pub mod tls;

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use config::AgentConfig;
pub use connection::{enroll, Agent, Fatal};
