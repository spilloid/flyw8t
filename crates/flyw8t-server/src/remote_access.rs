//! Remote-access provider seam (ADR-0006).
//!
//! Optional external providers can map a flyw8t device to a launch link. The native
//! attended/unattended engine is the accepted direction (ADR-0013); this seam is not
//! that engine. A provider is never the source of device identity or tenancy.

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
        "Remote control is not available in this build.".into()
    }

    fn launch_url(&self, _device_id: Uuid) -> Option<String> {
        None
    }
}
