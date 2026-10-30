//! Monitoring findings and data freshness. See `docs/monitoring.md`.
//!
//! The vertical slice implements only connectivity: whether a device is connected now, and
//! how stale its last check-in is. The [`Finding`] shape is defined now so the first real
//! monitors (disk, services, event log) land in a model that already preserves evidence,
//! collection time and resolution state.

use serde::Serialize;
use time::{Duration, OffsetDateTime};

/// What the server knows about a device's connection, from most to least certain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Connectivity {
    /// An authenticated connection is open on this server right now.
    Connected,
    /// No open connection. `last_seen` is the last authenticated message received.
    Disconnected { last_seen: Option<OffsetDateTime> },
    /// Enrolled but never completed an authenticated connection.
    NeverConnected,
}

/// How old a piece of cached, device-reported data is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// Collected within the fresh window.
    Fresh,
    /// Older than the fresh window; show its age.
    Aging,
    /// Old enough that a technician should not rely on it.
    Stale,
}

pub fn freshness(
    collected_at: OffsetDateTime,
    now: OffsetDateTime,
    fresh: Duration,
    stale: Duration,
) -> Freshness {
    let age = now - collected_at;
    if age <= fresh {
        Freshness::Fresh
    } else if age <= stale {
        Freshness::Aging
    } else {
        Freshness::Stale
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Resolved,
    Suppressed,
}

/// One monitoring observation with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    /// Stable check identifier, e.g. `connectivity.offline`, `disk.low_space`.
    pub check: String,
    pub severity: Severity,
    pub status: FindingStatus,
    /// The raw facts the verdict was drawn from, as reported.
    pub evidence: serde_json::Value,
    /// When the evidence was collected on the device (device clock).
    pub collected_at: OffsetDateTime,
    /// When the server evaluated it (server clock).
    pub evaluated_at: OffsetDateTime,
    /// Same check + device + key is one finding, updated in place, never duplicated.
    pub dedup_key: String,
}

/// Thresholds for the offline check. A device that misses a few heartbeats is not an
/// incident: nothing is raised until `grace` has passed since the last check-in.
#[derive(Debug, Clone, Copy)]
pub struct OfflinePolicy {
    pub grace: Duration,
    pub critical_after: Duration,
}

impl Default for OfflinePolicy {
    fn default() -> Self {
        Self {
            grace: Duration::minutes(10),
            critical_after: Duration::hours(24),
        }
    }
}

/// Severity an offline finding should have right now, or `None` if none should exist.
pub fn offline_severity(
    c: Connectivity,
    now: OffsetDateTime,
    policy: OfflinePolicy,
) -> Option<Severity> {
    match c {
        Connectivity::Connected | Connectivity::NeverConnected => None,
        Connectivity::Disconnected { last_seen: None } => None,
        Connectivity::Disconnected {
            last_seen: Some(seen),
        } => {
            let silent = now - seen;
            if silent < policy.grace {
                None
            } else if silent < policy.critical_after {
                Some(Severity::Warning)
            } else {
                Some(Severity::Critical)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    #[test]
    fn brief_disconnects_raise_nothing() {
        let c = Connectivity::Disconnected {
            last_seen: Some(NOW - Duration::minutes(3)),
        };
        assert_eq!(offline_severity(c, NOW, OfflinePolicy::default()), None);
    }

    #[test]
    fn severity_escalates_after_grace() {
        let p = OfflinePolicy::default();
        let at = |m| Connectivity::Disconnected {
            last_seen: Some(NOW - Duration::minutes(m)),
        };
        assert_eq!(offline_severity(at(11), NOW, p), Some(Severity::Warning));
        assert_eq!(
            offline_severity(at(60 * 25), NOW, p),
            Some(Severity::Critical)
        );
        assert_eq!(offline_severity(Connectivity::Connected, NOW, p), None);
    }

    #[test]
    fn freshness_windows() {
        let f = |mins| {
            freshness(
                NOW - Duration::minutes(mins),
                NOW,
                Duration::minutes(5),
                Duration::hours(24),
            )
        };
        assert_eq!(f(1), Freshness::Fresh);
        assert_eq!(f(30), Freshness::Aging);
        assert_eq!(f(60 * 48), Freshness::Stale);
    }
}
