//! In-process collectors: inventory and process list. Read-only by construction.

use flyw8t_protocol::inventory::{
    Disk, Hardware, InventoryReport, NetworkInterface, OsInfo, ProcessEntry, ProcessList,
};
use sysinfo::{Disks, Networks, ProcessesToUpdate, System};
use time::OffsetDateTime;

pub fn inventory() -> InventoryReport {
    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu_all();

    let disks = Disks::new_with_refreshed_list()
        .list()
        .iter()
        .map(|d| Disk {
            mount_point: d.mount_point().to_string_lossy().into_owned(),
            file_system: d.file_system().to_string_lossy().into_owned(),
            total_bytes: d.total_space(),
            available_bytes: d.available_space(),
            removable: d.is_removable(),
        })
        .collect();

    let mut network: Vec<NetworkInterface> = Networks::new_with_refreshed_list()
        .iter()
        .map(|(name, data)| {
            let mac = data.mac_address().to_string();
            NetworkInterface {
                name: name.clone(),
                mac: (mac != "00:00:00:00:00:00").then_some(mac),
                addresses: data
                    .ip_networks()
                    .iter()
                    .map(|n| format!("{}/{}", n.addr, n.prefix))
                    .collect(),
            }
        })
        .collect();
    network.sort_by(|a, b| a.name.cmp(&b.name));

    InventoryReport {
        collected_at: OffsetDateTime::now_utc(),
        hostname: System::host_name().unwrap_or_default(),
        os: OsInfo {
            family: std::env::consts::OS.to_string(),
            name: System::name(),
            version: System::os_version(),
            long_version: System::long_os_version(),
            kernel_version: System::kernel_version(),
            arch: std::env::consts::ARCH.to_string(),
        },
        hardware: Hardware {
            cpu_model: sys
                .cpus()
                .first()
                .map(|c| c.brand().trim().to_string())
                .filter(|s| !s.is_empty()),
            cpu_logical_cores: sys.cpus().len() as u32,
            cpu_physical_cores: System::physical_core_count().map(|n| n as u32),
            memory_total_bytes: sys.total_memory(),
            memory_available_bytes: sys.available_memory(),
        },
        disks,
        network,
        uptime_secs: System::uptime(),
        agent_version: crate::AGENT_VERSION.to_string(),
    }
}

pub fn process_top(limit: u16) -> ProcessList {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut all: Vec<ProcessEntry> = sys
        .processes()
        .iter()
        .map(|(pid, p)| ProcessEntry {
            pid: pid.as_u32(),
            name: p.name().to_string_lossy().into_owned(),
            memory_bytes: p.memory(),
            run_time_secs: p.run_time(),
        })
        .collect();
    let total = all.len() as u32;
    all.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes).then(a.pid.cmp(&b.pid)));
    all.truncate(limit as usize);
    ProcessList {
        processes: all,
        total,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn inventory_reports_this_machine() {
        let inv = super::inventory();
        assert!(!inv.hostname.is_empty());
        assert!(inv.hardware.memory_total_bytes > 0);
        assert!(inv.hardware.cpu_logical_cores > 0);
        assert_eq!(inv.os.family, std::env::consts::OS);
    }

    #[test]
    fn process_top_is_bounded_and_sorted() {
        let list = super::process_top(3);
        assert!(list.processes.len() <= 3);
        assert!(list.total >= list.processes.len() as u32);
        assert!(list
            .processes
            .windows(2)
            .all(|w| w[0].memory_bytes >= w[1].memory_bytes));
    }
}
