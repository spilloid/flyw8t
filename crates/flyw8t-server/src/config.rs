//! Server configuration, read from the environment and validated at startup.

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

pub use flyw8t_web::model::FamilyLink;

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
    /// Every console user must set up a second factor before reaching the console.
    pub require_mfa: bool,
    /// The signed `flyw8t-helper.exe` offered to participants of control sessions. Without it,
    /// the server says remote control is not available.
    pub helper_path: Option<PathBuf>,
    /// Reverse proxies (Cloudflare Tunnel, nginx) whose forwarded client address is believed.
    /// Empty by default: the socket address is used and forwarding headers are ignored.
    pub trusted_proxies: Vec<crate::client_ip::Cidr>,
    /// The header a trusted proxy puts the client address in.
    pub client_ip_header: String,
    /// Encrypts secret custom-field values at rest (AES-256-GCM). 32 bytes, base64. Without it, secret fields can be
    /// defined but no secret value can be stored.
    pub field_key: Option<[u8; 32]>,
    /// Check script syntax on save with the languages' own parsers, when installed (ADR-0014). `FLYW8T_SCRIPT_CHECKS=off`
    /// turns it off; every revision then says it was not checked.
    pub script_checks: bool,
    /// Links to the operator's other products, shown in the console frame (`FLYW8T_FAMILY_LINKS`). Links only:
    /// nothing is fetched from them and no sign-in is shared.
    pub family_links: Vec<FamilyLink>,
}

/// `host`, `host:port` or `[v6]:port`, with no user name: what may follow `https://` in a family link.
fn authority_ok(authority: &str) -> bool {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((v6, after)) = rest.split_once(']') else {
            return false;
        };
        if v6.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        match after.strip_prefix(':') {
            Some(port) => (None, Some(port)),
            None if after.is_empty() => (None, None),
            None => return false,
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (Some(host), Some(port)),
            None => (Some(authority), None),
        }
    };
    let host_ok = host.is_none_or(|h| {
        !h.is_empty()
            && h.len() <= 253
            && h.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
            // Browsers read a host whose last label is a number as an IPv4 address, and refuse it if it is not one.
            && (!h
                .rsplit('.')
                .next()
                .is_some_and(|last| last.chars().all(|c| c.is_ascii_digit()))
                || h.parse::<std::net::Ipv4Addr>().is_ok())
    });
    let port_ok = port.is_none_or(|p| {
        !p.is_empty()
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|n| n > 0)
    });
    host_ok && port_ok
}

/// `Label=https://url, Label=https://url`: at most 8 links, each an absolute http(s) URL.
pub fn parse_family_links(raw: &str) -> Result<Vec<FamilyLink>> {
    let mut out = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (label, url) = entry
            .split_once('=')
            .with_context(|| format!("FLYW8T_FAMILY_LINKS: {entry:?} is not Label=URL"))?;
        let (label, url) = (label.trim(), url.trim());
        let count = label.chars().count();
        if count == 0 || count > 40 || label.chars().any(char::is_control) {
            bail!("FLYW8T_FAMILY_LINKS: the label in {entry:?} must be 1 to 40 characters");
        }
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .with_context(|| {
                format!("FLYW8T_FAMILY_LINKS: {url:?} must start with https:// or http://")
            })?;
        if !authority_ok(rest.split(['/', '?', '#']).next().unwrap_or(""))
            || url.len() > 500
            || url.chars().any(|c| {
                c.is_control() || c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '\\')
            })
        {
            bail!("FLYW8T_FAMILY_LINKS: {url:?} is not a usable URL");
        }
        out.push(FamilyLink {
            label: label.to_string(),
            url: url.to_string(),
        });
    }
    if out.len() > 8 {
        bail!("FLYW8T_FAMILY_LINKS: at most 8 links");
    }
    Ok(out)
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
            helper_path: var("FLYW8T_HELPER_PATH").map(PathBuf::from),
            field_key: match var("FLYW8T_FIELD_KEY") {
                None => None,
                Some(k) => {
                    use base64::Engine;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(k.trim())
                        .or_else(|_| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(k.trim())
                        })
                        .context("FLYW8T_FIELD_KEY must be base64")?;
                    Some(
                        bytes
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("FLYW8T_FIELD_KEY must be 32 bytes"))?,
                    )
                }
            },
            script_checks: match var("FLYW8T_SCRIPT_CHECKS").as_deref() {
                None | Some("on") => true,
                Some("off") => false,
                Some(_) => anyhow::bail!("FLYW8T_SCRIPT_CHECKS must be on or off"),
            },
            trusted_proxies: match var("FLYW8T_TRUSTED_PROXIES") {
                None => Vec::new(),
                Some(v) => v
                    .split(',')
                    .map(|s| {
                        crate::client_ip::Cidr::parse(s).with_context(|| {
                            format!(
                                "FLYW8T_TRUSTED_PROXIES: {s:?} is not an address or address/prefix"
                            )
                        })
                    })
                    .collect::<Result<_>>()?,
            },
            client_ip_header: var("FLYW8T_CLIENT_IP_HEADER")
                .unwrap_or_else(|| "cf-connecting-ip".into())
                .to_ascii_lowercase(),
            require_mfa: match var("FLYW8T_REQUIRE_MFA").as_deref() {
                None | Some("true") => true,
                Some("false") => false,
                Some(other) => bail!("FLYW8T_REQUIRE_MFA must be true or false, not {other:?}"),
            },
            family_links: match var("FLYW8T_FAMILY_LINKS") {
                None => Vec::new(),
                Some(v) => parse_family_links(&v)?,
            },
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
            require_mfa: true,
            helper_path: None,
            trusted_proxies: Vec::new(),
            client_ip_header: "cf-connecting-ip".into(),
            field_key: None,
            script_checks: true,
            family_links: Vec::new(),
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

    #[test]
    fn family_links_are_labelled_absolute_web_addresses() {
        let links = parse_family_links(
            " AnchorDesk = https://desk.example.com/ , PortGlass=http://localhost:7443/a?b=c ",
        )
        .unwrap();
        assert_eq!(
            links,
            vec![
                FamilyLink {
                    label: "AnchorDesk".into(),
                    url: "https://desk.example.com/".into()
                },
                FamilyLink {
                    label: "PortGlass".into(),
                    url: "http://localhost:7443/a?b=c".into()
                },
            ]
        );
        assert!(parse_family_links("").unwrap().is_empty());
        for good in [
            "A=https://desk.example.com",
            "A=https://desk.example.com:8443/path?q=1#top",
            "A=http://[::1]:7443/",
            "A=https://[2001:db8::1]",
            "A=http://192.168.1.10:8080",
            "A=https://desk",
        ] {
            assert!(parse_family_links(good).is_ok(), "{good:?} was refused");
        }
        for bad in [
            "AnchorDesk",
            "=https://desk.example.com",
            "Desk=javascript:alert(1)",
            "Desk=//desk.example.com",
            "Desk=https://",
            "Desk=https:///path",
            "Desk=https://desk.example.com/\"onmouseover=x",
            "Desk=https://desk.example.com/ two",
            "Desk=data:text/html,x",
            "Desk=desk.example.com:8080",
            "Desk=mailto:8080",
            "Desk=https://[",
            "Desk=https://[::1",
            "Desk=https://[zz]/",
            "Desk=https://desk.example:banana",
            "Desk=https://desk.example:0",
            "Desk=https://desk.example:65536",
            "Desk=https://desk.example:",
            "Desk=https://user@desk.example/",
            "Desk=https://desk..example/",
            "Desk=https://-desk.example/",
            "Desk=https://desk_one.example/",
            "Desk=https://999.999.999.999/",
            "Desk=https://desk.123/",
            "Desk=https://1.2.3/",
        ] {
            assert!(parse_family_links(bad).is_err(), "{bad:?} was accepted");
        }
        let nine = (0..9)
            .map(|i| format!("P{i}=https://p{i}.example.com"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_family_links(&nine).is_err());
    }
}
