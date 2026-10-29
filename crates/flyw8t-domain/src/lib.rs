//! flyw8t domain rules, free of I/O.
//!
//! The server persists and transports; the rules about what a job's state may become, what
//! counts as evidence, who may do what, and when a silent device becomes a finding live here
//! so they can be tested exhaustively without a database.

pub mod access;
pub mod evidence;
pub mod finding;
pub mod job;

pub use access::{Permission, Role};
pub use evidence::evaluate;
pub use job::{ExecState, Outcome, Tone, Verification};
