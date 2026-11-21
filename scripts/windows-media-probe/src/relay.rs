//! Authenticated single-address IPv4 UDP TURN for native media.
use super::Result;
use rtc::peer_connection::configuration::{
    RTCConfiguration, RTCConfigurationBuilder, RTCIceServer, RTCIceTransportPolicy,
};
use rtc::peer_connection::transport::{RTCIceCandidatePair, RTCIceCandidateType, RTCIceProtocol};

use serde::Deserialize;
use std::net::Ipv4Addr;

#[derive(Clone, Copy)]
pub enum Scope {
    Private,
    #[cfg(feature = "attended-picker")]
    Attended,
}

impl Scope {
    fn allows(self, ip: Ipv4Addr) -> bool {
        match self {
            Self::Private => ip.is_private() || ip == Ipv4Addr::LOCALHOST,
            #[cfg(feature = "attended-picker")]
            Self::Attended => {
                let first = ip.octets()[0];
                first > 0 && first < 224 && !ip.is_loopback() && !ip.is_link_local()
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub bind: Ipv4Addr,
    server: Ipv4Addr,
    allocation: Ipv4Addr,
    port: u16,
    username: String,
    credential: String,
}

impl Settings {
    pub fn parse(line: &[u8], scope: Scope) -> Result<Self> {
        if line.len() > 4096 || !line.ends_with(b"\n") {
            return Err("invalid relay message length".into());
        }
        let settings: Self = serde_json::from_slice(line).map_err(|_| "invalid relay settings")?;
        if !scope.allows(settings.bind)
            || !scope.allows(settings.server)
            || !scope.allows(settings.allocation)
            || settings.port == 0
            || settings.username.is_empty()
            || settings.credential.is_empty()
        {
            return Err("expected an allowed IPv4 relay, interface and credentials".into());
        }
        Ok(settings)
    }

    pub fn configuration(&self) -> RTCConfiguration {
        RTCConfigurationBuilder::new()
            .with_ice_servers(vec![RTCIceServer {
                urls: vec![format!("turn:{}:{}?transport=udp", self.server, self.port)],
                username: self.username.clone(),
                credential: self.credential.clone(),
            }])
            .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
            .build()
    }

    pub fn check_sdp(&self, sdp: &str) -> Result<()> {
        let mut count = 0;
        for candidate in sdp.lines().filter(|line| line.starts_with("a=candidate:")) {
            let fields: Vec<_> = candidate.split_ascii_whitespace().collect();
            if fields.len() < 8
                || !fields[2].eq_ignore_ascii_case("udp")
                || fields[4].parse::<Ipv4Addr>().ok() != Some(self.allocation)
                || fields[6] != "typ"
                || fields[7] != "relay"
            {
                return Err(
                    "expected only candidates allocated on the configured UDP relay".into(),
                );
            }
            count += 1;
        }
        if count == 0 {
            return Err("no authenticated UDP relay candidate was gathered".into());
        }
        Ok(())
    }

    pub fn check_selected(&self, pair: &RTCIceCandidatePair) -> Result<()> {
        for candidate in [pair.local(), pair.remote()] {
            if candidate.typ != RTCIceCandidateType::Relay
                || candidate.protocol != RTCIceProtocol::Udp
                || candidate.address.parse::<Ipv4Addr>().ok() != Some(self.allocation)
            {
                return Err("the selected native pair did not use the configured relay".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "attended-picker")]
    #[test]
    fn attended_and_fixture_address_scopes_are_distinct() {
        let external = Ipv4Addr::new(198, 51, 100, 42);
        assert!(Scope::Attended.allows(external));
        assert!(!Scope::Private.allows(external));
        assert!(Scope::Private.allows(Ipv4Addr::LOCALHOST));
        for ip in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            assert!(!Scope::Attended.allows(ip));
        }
    }

    #[test]
    fn requires_only_candidates_from_the_configured_relay() {
        let settings = Settings::parse(b"{\"bind\":\"127.0.0.1\",\"server\":\"127.0.0.1\",\"allocation\":\"127.0.0.1\",\"port\":3478,\"username\":\"a\",\"credential\":\"b\"}\n", Scope::Private).unwrap();
        let relay = "a=candidate:1 1 UDP 1 127.0.0.1 40000 typ relay";
        assert!(settings.check_sdp(relay).is_ok());
        for invalid in [
            "".to_owned(),
            relay.replace("relay", "host"),
            relay.replace("UDP", "TCP"),
            relay.replace("127.0.0.1", "127.0.0.2"),
        ] {
            assert!(settings.check_sdp(&invalid).is_err());
        }
        assert!(settings
            .check_sdp(&format!("{relay}\r\n{}", relay.replace("relay", "host")))
            .is_err());
    }
}
