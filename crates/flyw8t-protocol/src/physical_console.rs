use serde::{Deserialize, Serialize};

/// Point-in-time observation of a device's physical console. Carries no user identity,
/// session identifier or permission to view or operate a desktop.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalConsoleState {
    ActiveConsole,
    NoInteractiveUser,
    NoConsole,
    Unavailable,
}
