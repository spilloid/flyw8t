//! Agent configuration and state directory layout.
//!
//! ```text
//! <state_dir>/
//!   agent.json      server URL, optional pinned CA, device id once enrolled
//!   device.key      Ed25519 private key (PKCS#8). Never leaves the device.
//!   journal/        one file per job; see journal.rs
//! ```

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// `https://flyw8t.example.com`. `http://` is accepted only for loopback hosts.
    pub server_url: String,
    /// Extra CA certificate (PEM) to trust, for servers using a private CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Uuid>,
    #[serde(skip)]
    pub state_dir: PathBuf,
}

impl AgentConfig {
    pub fn load(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join("agent.json");
        let raw = std::fs::read_to_string(&path).with_context(|| {
            format!("reading {} (has this agent been enrolled?)", path.display())
        })?;
        let mut cfg: AgentConfig =
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        cfg.state_dir = state_dir.to_path_buf();
        ws_url(&cfg.server_url)?;
        Ok(cfg)
    }

    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir)?;
        write_atomic(
            &self.state_dir.join("agent.json"),
            &serde_json::to_vec_pretty(self)?,
        )
    }

    pub fn key_path(&self) -> PathBuf {
        self.state_dir.join("device.key")
    }

    pub fn journal_dir(&self) -> PathBuf {
        self.state_dir.join("journal")
    }

    pub fn ws_url(&self) -> Result<String> {
        ws_url(&self.server_url)
    }
}

pub fn default_state_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("flyw8t").join("agent")
    } else {
        PathBuf::from("/var/lib/flyw8t-agent")
    }
}

/// Derive the agent WebSocket URL, refusing plaintext to anything but loopback. This is a
/// code rule, not a setting: there is no flag that allows plaintext to a remote server.
pub fn ws_url(server_url: &str) -> Result<String> {
    let trimmed = server_url.trim().trim_end_matches('/');
    let (scheme, rest) = trimmed
        .split_once("://")
        .context("server URL must start with https://")?;
    let host = host_of(rest);
    let ws_scheme = match scheme {
        "https" => "wss",
        "http" if is_loopback_host(host) => "ws",
        "http" => bail!("refusing plaintext http:// to non-loopback host {host:?}; use https://"),
        other => bail!("unsupported URL scheme {other:?}; use https://"),
    };
    if host.is_empty() {
        bail!("server URL has no host");
    }
    Ok(format!("{ws_scheme}://{rest}/api/agent/ws"))
}

fn host_of(authority_and_path: &str) -> &str {
    let authority = authority_and_path.split('/').next().unwrap_or("");
    if let Some(stripped) = authority.strip_prefix('[') {
        return stripped.split(']').next().unwrap_or("");
    }
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Write a file so that a crash leaves either the old or the new contents, never a mix.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    // Make the rename itself durable. On Unix that needs an fsync of the directory. On
    // Windows, NTFS journals the rename but does not promise it is on disk before returning;
    // MoveFileEx with MOVEFILE_WRITE_THROUGH would, and is an open item (docs/reliability.md).
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_only_to_loopback() {
        assert_eq!(
            ws_url("https://rmm.example.com").unwrap(),
            "wss://rmm.example.com/api/agent/ws"
        );
        assert_eq!(
            ws_url("https://rmm.example.com:8443/").unwrap(),
            "wss://rmm.example.com:8443/api/agent/ws"
        );
        assert_eq!(
            ws_url("http://127.0.0.1:8080").unwrap(),
            "ws://127.0.0.1:8080/api/agent/ws"
        );
        assert_eq!(
            ws_url("http://localhost:8080").unwrap(),
            "ws://localhost:8080/api/agent/ws"
        );
        assert_eq!(
            ws_url("http://[::1]:8080").unwrap(),
            "ws://[::1]:8080/api/agent/ws"
        );
        assert!(ws_url("http://rmm.example.com").is_err());
        assert!(ws_url("http://10.0.0.5:8080").is_err());
        assert!(ws_url("http://localhost.evil.com").is_err());
        assert!(ws_url("ftp://x").is_err());
        assert!(ws_url("rmm.example.com").is_err());
    }
}
