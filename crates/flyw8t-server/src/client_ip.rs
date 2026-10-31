//! The client's address, as seen through a trusted reverse proxy.
//!
//! Behind Cloudflare Tunnel (or any reverse proxy) every request arrives from the proxy, so the
//! socket address alone would put every user and device behind one IP for rate limits and
//! audit. When, and only when, the direct peer is inside `FLYW8T_TRUSTED_PROXIES`, the address
//! in `FLYW8T_CLIENT_IP_HEADER` (default `CF-Connecting-IP`) is used instead. A request that
//! does not come from a trusted proxy cannot choose its own address by sending that header.

use crate::Shared;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

/// An address range, `addr/prefix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a.parse::<IpAddr>().ok()?, p.parse::<u8>().ok()?),
            None => {
                let a = s.parse::<IpAddr>().ok()?;
                (a, if a.is_ipv4() { 32 } else { 128 })
            }
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        match (canonical(self.addr), ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) as plain IPv4, so one rule covers both forms.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// The address to attribute a request to.
pub fn resolve(peer: IpAddr, headers: &HeaderMap, trusted: &[Cidr], header: &str) -> IpAddr {
    if !trusted.iter().any(|c| c.contains(peer)) {
        return canonical(peer);
    }
    // The proxy appends; with a comma-separated list, the last entry is the one it added.
    headers
        .get(header)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .map_or(canonical(peer), canonical)
}

/// Extractor: the client's address (see the module docs).
pub struct ClientIp(pub String);

impl FromRequestParts<Shared> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::from([0, 0, 0, 0]), |c| c.0.ip());
        let ip = resolve(
            peer,
            &parts.headers,
            &state.config.trusted_proxies,
            &state.config.client_ip_header,
        );
        Ok(ClientIp(ip.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, v: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
        m
    }

    #[test]
    fn cidr_matching() {
        let c = Cidr::parse("172.16.0.0/12").unwrap();
        assert!(c.contains("172.20.1.2".parse().unwrap()));
        assert!(!c.contains("172.32.0.1".parse().unwrap()));
        assert!(
            c.contains("::ffff:172.20.1.2".parse().unwrap()),
            "IPv4-mapped counts"
        );
        let one = Cidr::parse("127.0.0.1").unwrap();
        assert!(one.contains("127.0.0.1".parse().unwrap()));
        assert!(!one.contains("127.0.0.2".parse().unwrap()));
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("fe80::1".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        assert_eq!(Cidr::parse("10.0.0.0/33"), None);
        assert_eq!(Cidr::parse("nonsense"), None);
    }

    #[test]
    fn headers_count_only_from_trusted_proxies() {
        let trusted = [Cidr::parse("172.16.0.0/12").unwrap()];
        let header = "cf-connecting-ip";
        let proxy: IpAddr = "172.18.0.5".parse().unwrap();
        let stranger: IpAddr = "203.0.113.9".parse().unwrap();
        let fwd = h(header, "198.51.100.7");
        assert_eq!(
            resolve(proxy, &fwd, &trusted, header).to_string(),
            "198.51.100.7"
        );
        assert_eq!(
            resolve(stranger, &fwd, &trusted, header),
            stranger,
            "a spoofed header is ignored"
        );
        assert_eq!(
            resolve(proxy, &HeaderMap::new(), &trusted, header),
            proxy,
            "no header: the peer"
        );
        assert_eq!(
            resolve(proxy, &h(header, "not-an-ip"), &trusted, header),
            proxy
        );
        assert_eq!(
            resolve(proxy, &fwd, &[], header),
            proxy,
            "nothing trusted by default"
        );
        let xff = h("x-forwarded-for", "10.9.9.9, 198.51.100.8");
        assert_eq!(
            resolve(proxy, &xff, &trusted, "x-forwarded-for").to_string(),
            "198.51.100.8"
        );
    }
}
