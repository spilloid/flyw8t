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
pub mod logfile;
pub mod runner;
pub mod script;
#[cfg(windows)]
pub mod service;
pub mod spent;
pub mod tls;
pub mod trust;
#[cfg(windows)]
pub mod winsec;

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What this agent supports beyond the built-in catalog (ADR-0015 section 7). Scripts arrive in build step 4.
pub const CAPABILITIES: &[&str] = &[flyw8t_protocol::messages::CAP_SCRIPTS];

pub use config::AgentConfig;
pub use connection::{enroll, trust_pin, Agent, Fatal};
