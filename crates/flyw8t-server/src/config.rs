//! Server configuration, read from the environment and validated at startup.

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,
    /// The URL technicians and agents use to reach this server.
    pub public_url: String,
    /// Native TLS (PEM chain, PEM key). Omit when a reverse proxy terminates TLS.
    pub tls: Option<(PathBuf, PathBuf)>,
    pub bootstrap_admin: Option<(String, String)>,
    pub heartbeat_secs: u32,
    /// How often the sweeper resolves deadlines and retries queued work.
    pub sweep_interval: Duration,
    /// Extra time beyond a job's own limit before silence makes its outcome unknown.
    pub silence_grace: Duration,
    /// How long a job may wait for its device to connect before it expires unsent.
    pub delivery_window: Duration,
    /// How long an offer may go unacknowledged on one connection before it is offered again.
    pub redelivery_after: Duration,
    /// How long an attended-support invitation (code and link) stays valid.
    pub support_invite_ttl: Duration,
    /// WebRTC ICE servers for attended support, as a JSON array of RTCIceServer objects.
    /// Empty by default: LAN only, and no third party is contacted.
    pub ice_servers: String,
    pub session_ttl: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let database_url = var("FLYW8T_DATABASE_URL")
            .or_else(|| var("DATABASE_URL"))
            .context("FLYW8T_DATABASE_URL is required")?;
        let bind = var("FLYW8T_BIND")
            .unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse()
            .context("FLYW8T_BIND must be host:port")?;
        let public_url = var("FLYW8T_PUBLIC_URL")
            .context("FLYW8T_PUBLIC_URL is required (e.g. https://rmm.example.com)")?;
        let tls = match (var("FLYW8T_TLS_CERT"), var("FLYW8T_TLS_KEY")) {
            (Some(c), Some(k)) => Some((c.into(), k.into())),
            (None, None) => None,
            _ => bail!("set both FLYW8T_TLS_CERT and FLYW8T_TLS_KEY, or neither"),
        };
        let bootstrap_admin = match (var("FLYW8T_BOOTSTRAP_ADMIN_EMAIL"), var("FLYW8T_BOOTSTRAP_ADMIN_PASSWORD")) {
            (Some(e), Some(p)) => Some((e, p)),
            (None, None) => None,
            _ => bail!("set both FLYW8T_BOOTSTRAP_ADMIN_EMAIL and FLYW8T_BOOTSTRAP_ADMIN_PASSWORD, or neither"),
        };
        let cfg = Self {
            database_url,
            bind,
            public_url: public_url.trim_end_matches('/').to_string(),
            tls,
            bootstrap_admin,
            ice_servers: var("FLYW8T_ICE_SERVERS").unwrap_or_else(|| "[]".into()),
            ..Self::defaults()
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Defaults for everything but the required fields; used by tests.
    pub fn defaults() -> Self {
        Self {
            database_url: String::new(),
            bind: "127.0.0.1:0".parse().unwrap(),
            public_url: "http://127.0.0.1".into(),
            tls: None,
            bootstrap_admin: None,
            heartbeat_secs: 30,
            sweep_interval: Duration::from_secs(5),
            silence_grace: Duration::from_secs(60),
            delivery_window: Duration::from_secs(15 * 60),
            redelivery_after: Duration::from_secs(60),
            support_invite_ttl: Duration::from_secs(10 * 60),
            ice_servers: "[]".into(),
            session_ttl: Duration::from_secs(12 * 60 * 60),
        }
    }

    /// Plaintext is allowed only when the public URL is loopback. A deployment reachable
    /// from anywhere else must present HTTPS, natively or through a proxy.
    pub fn validate(&self) -> Result<()> {
        let ice: serde_json::Value =
            serde_json::from_str(&self.ice_servers).context("FLYW8T_ICE_SERVERS must be JSON")?;
        anyhow::ensure!(
            ice.is_array(),
            "FLYW8T_ICE_SERVERS must be a JSON array of RTCIceServer objects"
        );
        let (scheme, rest) = self
            .public_url
            .split_once("://")
            .context("FLYW8T_PUBLIC_URL must include a scheme")?;
        let authority = rest.split('/').next().unwrap_or("");
        let host = if let Some(h) = authority.strip_prefix('[') {
            h.split(']').next().unwrap_or("")
        } else {
            authority.rsplit_once(':').map_or(authority, |(h, _)| h)
        };
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        match scheme {
            "https" => Ok(()),
            "http" if loopback => Ok(()),
            "http" => bail!("FLYW8T_PUBLIC_URL is plaintext http:// to non-loopback host {host:?}; use https://"),
            other => bail!("unsupported scheme {other:?} in FLYW8T_PUBLIC_URL"),
        }
    }

    /// Session cookies are `Secure` whenever the public URL is HTTPS.
    pub fn secure_cookies(&self) -> bool {
        self.public_url.starts_with("https://")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_url(u: &str) -> Config {
        Config {
            public_url: u.into(),
            ..Config::defaults()
        }
    }

    #[test]
    fn plaintext_only_on_loopback() {
        assert!(with_url("https://rmm.example.com").validate().is_ok());
        assert!(with_url("http://localhost:8080").validate().is_ok());
        assert!(with_url("http://127.0.0.1:8080").validate().is_ok());
        assert!(with_url("http://rmm.example.com").validate().is_err());
        assert!(with_url("http://192.168.1.10:8080").validate().is_err());
        assert!(with_url("http://localhost.example.com").validate().is_err());
        assert!(!with_url("http://localhost:8080").secure_cookies());
        assert!(with_url("https://x").secure_cookies());
    }
}
