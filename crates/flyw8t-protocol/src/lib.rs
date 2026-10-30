//! The flyw8t agent <-> server wire protocol.
//!
//! Everything both sides must agree on lives here: the message envelopes, the allowlisted
//! action catalog and its parameter validation, the inventory shape, and the exact bytes a
//! device signs to prove its identity. See `docs/agent-protocol.md` for the prose contract;
//! this crate is the executable half of it.

pub mod auth;
pub mod catalog;
pub mod inventory;
pub mod messages;

/// Protocol major version. A server refuses an agent speaking a different major version
/// rather than guessing at compatibility.
pub const PROTOCOL_VERSION: u32 = 1;

/// Upper bound on any single WebSocket message, either direction.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Upper bound on captured bytes kept per output stream (stdout or stderr) of one job.
/// Output beyond this is counted but discarded, and the report says it was truncated.
pub const MAX_STREAM_BYTES: usize = 256 * 1024;

pub use catalog::{Action, ActionError, ActionInfo, CATALOG};
pub use inventory::InventoryReport;
pub use messages::{AgentMsg, ExecOutcome, Finished, JobPhase, JobReport, ServerMsg};
