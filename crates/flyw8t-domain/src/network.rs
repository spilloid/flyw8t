//! NetViz v1 observations. Collector identity and tenancy are assigned by the server.
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use time::OffsetDateTime;

pub const MAX_BATCH: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub struct NetworkRange {
    network: u32,
    mask: u32,
    prefix: u8,
}

impl NetworkRange {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let (ip, prefix) = value
            .split_once('/')
            .ok_or("Enter an IPv4 range, such as 192.168.1.0/24.")?;
        let ip: Ipv4Addr = ip.parse().map_err(|_| "Enter a valid IPv4 range.")?;
        let prefix: u8 = prefix.parse().map_err(|_| "Enter a valid IPv4 prefix.")?;
        if !(16..=32).contains(&prefix) {
            return Err("Collector ranges must be /16 through /32.");
        }
        let mask = u32::MAX << (32 - prefix);
        Ok(Self {
            network: u32::from(ip) & mask,
            mask,
            prefix,
        })
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask == self.network
    }

    pub fn canonical(self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.prefix)
    }
}

/// Wire-compatible with netviz/internal/anchordesk.DeviceRecord. Extra v1 facts
/// (including id/firstSeen/OS) never choose an asset's identity, scope or age.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkObservation {
    pub ip: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default, rename = "deviceType")]
    pub device_type: String,
    pub status: String,
    #[serde(default, rename = "openPorts")]
    pub open_ports: Vec<u16>,
    #[serde(rename = "lastSeen", with = "time::serde::rfc3339")]
    pub collected_at: OffsetDateTime,
}

impl NetworkObservation {
    pub fn normalize(
        &mut self,
        range: NetworkRange,
        now: OffsetDateTime,
    ) -> Result<String, &'static str> {
        let ip: Ipv4Addr = self
            .ip
            .parse()
            .map_err(|_| "A device has an invalid IPv4 address.")?;
        if !range.contains(ip) || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
            return Err("A device address is outside this collector's range or is not unicast.");
        }
        if !matches!(self.status.as_str(), "up" | "down" | "unknown") {
            return Err("Device status must be up, down or unknown.");
        }
        if self.collected_at > now + time::Duration::minutes(5) {
            return Err("An observation is dated in the future. Check the collector's clock.");
        }
        for value in [&self.hostname, &self.vendor, &self.device_type] {
            if value.len() > 200 || value.chars().any(char::is_control) {
                return Err(
                    "Device descriptions must be at most 200 bytes with no control characters.",
                );
            }
        }
        if self.open_ports.len() > 128 || self.open_ports.contains(&0) {
            return Err("A device may report at most 128 non-zero ports.");
        }
        self.ip = ip.to_string();
        self.open_ports.sort_unstable();
        self.open_ports.dedup();
        self.mac = normalize_mac(&self.mac)?;
        if self.device_type.is_empty() {
            self.device_type = "unknown".into();
        }
        Ok(if self.mac.is_empty() {
            format!("ip:{}", self.ip)
        } else {
            format!("mac:{}", self.mac)
        })
    }
}

pub fn normalize_mac(value: &str) -> Result<String, &'static str> {
    if value.trim().is_empty() {
        return Ok(String::new());
    }
    let raw: String = value.chars().filter(|c| !matches!(c, ':' | '-')).collect();
    if raw.len() != 12 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("A device has an invalid MAC address.");
    }
    let raw = raw.to_ascii_lowercase();
    let first = u8::from_str_radix(&raw[..2], 16).map_err(|_| "Invalid MAC address.")?;
    if first & 1 != 0 || raw == "000000000000" {
        return Err("A device MAC address must be a non-zero unicast address.");
    }
    Ok((0..12)
        .step_by(2)
        .map(|i| &raw[i..i + 2])
        .collect::<Vec<_>>()
        .join(":"))
}

pub fn normalize_fingerprint(value: &str) -> Result<Option<String>, &'static str> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let value = value
        .strip_prefix("sha256:")
        .or_else(|| value.strip_prefix("SHA256:"))
        .unwrap_or(value);
    let raw: String = value
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | ' '))
        .collect();
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Enter the PortGlass probe's SHA-256 fingerprint (64 hexadecimal digits).");
    }
    Ok(Some(raw.to_ascii_lowercase()))
}

pub fn fresh(collected: OffsetDateTime, now: OffsetDateTime, interval_secs: i32) -> bool {
    now - collected <= time::Duration::seconds(i64::from(interval_secs) * 3 + 60)
        && collected <= now + time::Duration::minutes(5)
}

pub fn web_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_and_observations_are_constrained() {
        let range = NetworkRange::parse("192.168.1.9/24").unwrap();
        assert_eq!(range.canonical(), "192.168.1.0/24");
        assert!(!range.contains("192.168.2.1".parse().unwrap()));
        for bad in ["0.0.0.0/0", "10.0.0.0/15", "::1/128", "10.0.0.0/33"] {
            assert!(NetworkRange::parse(bad).is_err());
        }
        let now = OffsetDateTime::now_utc();
        let mut o = NetworkObservation {
            ip: "192.168.1.20".into(),
            hostname: "Printer".into(),
            mac: "02-AA-BB-CC-DD-EE".into(),
            vendor: String::new(),
            device_type: String::new(),
            status: "up".into(),
            open_ports: vec![443, 80, 443],
            collected_at: now,
        };
        assert_eq!(o.normalize(range, now).unwrap(), "mac:02:aa:bb:cc:dd:ee");
        assert_eq!(o.open_ports, [80, 443]);
        o.ip = "192.168.2.20".into();
        assert!(o.normalize(range, now).is_err());
        o.ip = "192.168.1.20".into();
        o.collected_at = now + time::Duration::hours(1);
        assert!(o.normalize(range, now).is_err());
        assert!(!fresh(now - time::Duration::hours(1), now, 60));
        assert!(fresh(now, now, 60));
        assert!(normalize_mac("ff:ff:ff:ff:ff:ff").is_err());
        assert!(normalize_mac("00:00:00:00:00:00").is_err());
        assert!(normalize_fingerprint("wrong").is_err());
    }
}
