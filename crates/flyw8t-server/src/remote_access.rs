//! Remote-access provider seam (ADR-0006).
//!
//! flyw8t does not implement remote desktop. A provider (MeshCentral first) maps a flyw8t
//! device to its own node and produces a launch link. The RMM never depends on a provider
//! being reachable, and a provider is never the source of device identity or tenancy.

use uuid::Uuid;

pub trait RemoteAccessProvider: Send + Sync {
    /// One line for the device page, honest about what is and is not available.
    fn describe(&self, device_id: Uuid) -> String;
    /// A URL that opens a session for this device, when one can be produced.
    fn launch_url(&self, device_id: Uuid) -> Option<String>;
}

/// The default: no provider. Says so instead of showing a dead button.
pub struct NotConfigured;

impl RemoteAccessProvider for NotConfigured {
    fn describe(&self, _device_id: Uuid) -> String {
        "Not configured. A MeshCentral provider is planned (docs/decisions/ADR-0006).".into()
    }

    fn launch_url(&self, _device_id: Uuid) -> Option<String> {
        None
    }
}
