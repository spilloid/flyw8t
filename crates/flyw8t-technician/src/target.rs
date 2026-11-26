use std::fmt;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const RDP_PORT: u16 = 3389;
const CONNECT_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn parse(raw: &str) -> Result<Self, String> {
        Self::parse_with_port(raw, RDP_PORT)
    }

    pub fn parse_with_port(raw: &str, default_port: u16) -> Result<Self, String> {
        let address = raw.trim();
        let invalid =
            || "Enter a computer name or IP address, optionally followed by a port.".to_owned();
        if address.is_empty() || address.len() > 260 {
            return Err(invalid());
        }
        if let Ok(ip) = address.parse::<IpAddr>() {
            return Ok(Self {
                host: ip.to_string(),
                port: default_port,
            });
        }
        if let Some(bracketed) = address.strip_prefix('[') {
            let (host, suffix) = bracketed.split_once(']').ok_or_else(invalid)?;
            let ip = host.parse::<std::net::Ipv6Addr>().map_err(|_| invalid())?;
            let port = if suffix.is_empty() {
                default_port
            } else {
                parse_port(suffix.strip_prefix(':').ok_or_else(invalid)?)?
            };
            return Ok(Self {
                host: ip.to_string(),
                port,
            });
        }
        let (host, port) = match address.split_once(':') {
            Some((host, port)) => (host, parse_port(port)?),
            None => (address, default_port),
        };
        let labels = host.strip_suffix('.').unwrap_or(host);
        if labels.is_empty()
            || labels.len() > 253
            || labels.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(invalid());
        }
        // Reject ambiguous legacy numbers such as 127.1 and 010.0.0.1.
        if labels.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            && host.parse::<IpAddr>().is_err()
        {
            return Err(invalid());
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

fn parse_port(raw: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .ok()
        .filter(|&port| port != 0 && raw.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| "Use a port between 1 and 65535.".to_owned())
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

fn resolve(target: &Target, budget: Duration) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, target.port)]);
    }
    let target = target.clone();
    let host = target.host.clone();
    let (send, receive) = mpsc::channel();
    // The OS resolver has its own timeout. Stop waiting at our deadline; a late
    // DNS result never starts a connection.
    thread::Builder::new()
        .name("rdp-dns".into())
        .spawn(move || {
            let result = (target.host.as_str(), target.port)
                .to_socket_addrs()
                .map(|addresses| addresses.collect::<Vec<_>>());
            let _ = send.send(result);
        })
        .map_err(|e| format!("Could not start the address lookup ({e})."))?;
    match receive.recv_timeout(budget) {
        Ok(Ok(list)) if !list.is_empty() => Ok(list),
        Ok(Ok(_)) => Err(format!(
            "No address found for {host}. Check the name or VPN."
        )),
        Ok(Err(e)) => Err(format!(
            "Could not look up {host}. Check the name or VPN. ({e})"
        )),
        Err(_) => Err(format!(
            "Address lookup for {host} did not finish. Check DNS or VPN."
        )),
    }
}

/// A successful probe establishes TCP reachability only. Windows provides the
/// subsequent RDP, certificate and logon events.
pub fn probe(target: &Target) -> Result<(), String> {
    let start = Instant::now();
    let addresses = resolve(target, CONNECT_BUDGET)?;
    let mut results = Vec::new();
    for (index, address) in addresses.iter().enumerate() {
        let remaining = CONNECT_BUDGET.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }
        let share = remaining / (addresses.len() - index) as u32;
        match TcpStream::connect_timeout(address, share.max(Duration::from_millis(1))) {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(error) => results.push(error),
        }
    }
    Err(describe_failure(target, &results, addresses.len()))
}

fn describe_failure(target: &Target, errors: &[io::Error], addresses: usize) -> String {
    let all = |kind| errors.len() == addresses && errors.iter().all(|e| e.kind() == kind);
    if all(ErrorKind::ConnectionRefused) {
        format!("{target} refused the connection. Check Remote Desktop and the port on that PC.")
    } else if all(ErrorKind::PermissionDenied) {
        format!("Windows blocked the connection to {target}. Check the local network policy.")
    } else if errors.len() < addresses || errors.iter().any(|e| e.kind() == ErrorKind::TimedOut) {
        format!(
            "{target} did not answer within five seconds. Check its network, VPN, and firewall."
        )
    } else {
        let reason = errors
            .last()
            .map(ToString::to_string)
            .unwrap_or_else(|| "No usable address".into());
        format!("Could not reach {target}. {reason}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_hosts_and_explicit_ports() {
        for (input, expected) in [
            ("  ws-01.lab  ", "ws-01.lab:3389"),
            ("pc.lab.:3390", "pc.lab.:3390"),
            ("192.0.2.1", "192.0.2.1:3389"),
            ("192.0.2.1:42", "192.0.2.1:42"),
            ("2001:db8::1", "[2001:db8::1]:3389"),
            ("[::1]:3391", "[::1]:3391"),
        ] {
            assert_eq!(Target::parse(input).unwrap().to_string(), expected);
        }
    }

    #[test]
    fn rejects_profiles_credentials_and_malformed_hosts() {
        for raw in [
            "",
            "user@host",
            "rdp://host",
            "host/profile",
            "host\nport",
            "host:0",
            "host:65536",
            "host:+42",
            "host:",
            "127.1",
            "010.0.0.1",
            "[pc]:3",
            "pc..lab",
            "-x",
            "server name",
            "host:3389?password=x",
            "example.com\0junk",
        ] {
            assert!(Target::parse(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn distinguishes_refusal_timeout_and_local_policy() {
        let target = Target::parse("test.example:3310").unwrap();
        let message = |kind| describe_failure(&target, &[io::Error::from(kind)], 1);
        assert!(message(ErrorKind::ConnectionRefused).contains("refused"));
        assert!(message(ErrorKind::TimedOut).contains("did not answer"));
        assert!(message(ErrorKind::PermissionDenied).contains("blocked"));
        assert!(
            !describe_failure(&target, &[io::Error::from(ErrorKind::ConnectionRefused)], 2)
                .contains("refused")
        );
    }

    #[test]
    fn accepts_a_real_loopback_listener_without_sending_data() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let target = Target::parse(&listener.local_addr().unwrap().to_string()).unwrap();
        probe(&target).unwrap();
        use std::io::Read;
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
    }
}
