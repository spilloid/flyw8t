//! Device-reported inventory. Everything here is a claim made by the endpoint; the server
//! stores it as such, stamped with when it was collected and when it was received.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryReport {
    #[serde(with = "time::serde::rfc3339")]
    pub collected_at: OffsetDateTime,
    pub hostname: String,
    pub os: OsInfo,
    pub hardware: Hardware,
    pub disks: Vec<Disk>,
    pub network: Vec<NetworkInterface>,
    pub uptime_secs: u64,
    pub agent_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsInfo {
    /// `windows`, `linux` or `macos`.
    pub family: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub long_version: Option<String>,
    pub kernel_version: Option<String>,
    pub arch: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hardware {
    pub cpu_model: Option<String>,
    pub cpu_logical_cores: u32,
    pub cpu_physical_cores: Option<u32>,
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Disk {
    pub mount_point: String,
    pub file_system: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub removable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: Option<String>,
    pub addresses: Vec<String>,
}

/// Result payload of `process.top`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessList {
    pub processes: Vec<ProcessEntry>,
    /// Total processes seen, of which `processes` is the top slice.
    pub total: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub name: String,
    pub memory_bytes: u64,
    pub run_time_secs: u64,
}
