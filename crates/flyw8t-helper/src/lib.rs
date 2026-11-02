//! The flyw8t helper: a small program the person being helped runs from the support page, so
//! a technician can (in later steps) see and control their screen (ADR-0012).
//!
//! This step pairs and asks for consent. The helper learns its one-time launch token and its
//! server from its own file name, connects to the server's helper socket with that token,
//! shows the person who is asking, and answers Allow or Decline. Nothing flows before Allow,
//! and the helper installs and stores nothing.

use anyhow::{bail, Context, Result};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

/// What the helper's own file name says: `flyw8t-helper-<token>.<base64url(server URL)>.exe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub token: String,
    pub server_url: String,
}

impl Launch {
    /// The host the helper will actually connect to: what the consent window must name.
    /// Taken from the file name, never from anything the server says about itself.
    pub fn server_host(&self) -> &str {
        let rest = self
            .server_url
            .split_once("://")
            .map_or(self.server_url.as_str(), |(_, r)| r);
        rest.split('/').next().unwrap_or(rest)
    }

    /// Check the address before use: the host shown must be the host connected to.
    pub fn check(&self) -> Result<()> {
        check_server_url(&self.server_url)
    }

    fn socket_url(&self) -> String {
        let base = self.server_url.trim_end_matches('/');
        let ws = if let Some(rest) = base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            base.to_string()
        };
        format!("{ws}/api/support/helper/ws")
    }
}

/// Read the launch details from the helper's file name. Browsers rename repeat downloads to
/// `name (1).exe`; that suffix is ignored.
pub fn launch_from_file_name(file_name: &str) -> Result<Launch> {
    let stem = file_name
        .strip_suffix(".exe")
        .or_else(|| file_name.strip_suffix(".EXE"))
        .unwrap_or(file_name);
    // `flyw8t-helper-…exe (1)` never happens; the counter goes before the extension.
    let stem = match stem.rfind(" (") {
        Some(i) if stem.ends_with(')') => &stem[..i],
        _ => stem,
    };
    let Some(rest) = stem.strip_prefix("flyw8t-helper-") else {
        bail!("this file is not named like a downloaded flyw8t helper");
    };
    let Some((token, server)) = rest.split_once('.') else {
        bail!("the file name does not say which server it belongs to");
    };
    let valid = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if !valid(token) || token.len() > 100 || !valid(server) {
        bail!("the file name has been changed");
    }
    let server_url = String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(server)
            .context("the file name has been changed")?,
    )
    .context("the file name has been changed")?;
    check_server_url(&server_url)?;
    Ok(Launch {
        token: token.to_string(),
        server_url,
    })
}

/// HTTPS, or plaintext only to this machine (the same rule as the server and the agent). The
/// address must be plain enough that what the consent window shows is exactly where the helper
/// connects: a DNS name or an IP address, an optional valid port, an optional path, nothing else.
fn check_server_url(url: &str) -> Result<()> {
    let (scheme, rest) = url
        .split_once("://")
        .context("no scheme in the server address")?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let plain_path = path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._~/".contains(&b));
    if !plain_path {
        bail!("the server address is not valid");
    }
    let (host, port) = if let Some(h) = authority.strip_prefix('[') {
        let (h, after) = h
            .split_once(']')
            .context("the server address is not valid")?;
        if h.parse::<std::net::Ipv6Addr>().is_err() {
            bail!("the server address is not valid");
        }
        let port = match after {
            "" => None,
            p => Some(
                p.strip_prefix(':')
                    .context("the server address is not valid")?,
            ),
        };
        (h, port)
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let dns_name = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !dns_name && host.parse::<std::net::Ipv6Addr>().is_err() {
        bail!("the server address is not valid");
    }
    // A port the connection library cannot read would silently become the default one.
    if let Some(p) = port {
        let valid = !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|n| n != 0);
        if !valid {
            bail!("the server address has an invalid port");
        }
    }
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match scheme {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => bail!("the server address must use https"),
    }
}

/// Text from the server, made safe to show: no control or invisible formatting characters
/// (a NUL would end the dialog's text early; a line break or a direction override could fake
/// the lines that follow), and no longer than `max` characters.
fn shown(text: &str, max: usize) -> String {
    let invisible = |c: char| {
        c.is_control()
            || matches!(c, '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}')
    };
    let clean = text
        .chars()
        .map(|c| if invisible(c) { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if clean.chars().count() > max {
        let mut cut: String = clean.chars().take(max).collect();
        cut.push('…');
        cut
    } else {
        clean
    }
}

/// Everything the person is shown before deciding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRequest {
    pub technician_name: String,
    pub technician_email: String,
    pub organization: String,
    /// From the helper's own launch details, not from the server.
    pub server_host: String,
    pub control: bool,
}

impl ConsentRequest {
    /// The dialog's title and text. What the helper knows for itself (the server it connected
    /// to, what is being asked) comes first; what the server says about its technician follows.
    pub fn dialog(&self) -> (String, String) {
        let what = if self.control {
            "see your screen and use your mouse and keyboard"
        } else {
            "see your screen"
        };
        let org = if self.organization.is_empty() {
            String::new()
        } else {
            format!("\nOrganization: {}", self.organization)
        };
        let text = format!(
            "The server {host} asks to {what}.\n\n\
             Only allow it if you were expecting help from {host}.\n\n\
             The server says the technician is:\n\
             {name} ({email}){org}\n\n\
             You can stop at any time. Nothing is installed.\n\n\
             Allow?",
            host = self.server_host,
            name = self.technician_name,
            email = self.technician_email,
        );
        (format!("flyw8t: allow {}?", self.server_host), text)
    }
}

/// The person's decision. The Windows build shows a dialog; tests answer directly.
pub trait Consent: Send + Sync + 'static {
    /// Blocks until the person decides. `true` is Allow.
    fn ask(&self, request: &ConsentRequest) -> bool;
    /// The session ended while the question was open: take it away. `ask` may then return
    /// anything; its answer is ignored.
    fn cancel(&self) {}
}

/// How a helper session finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The person declined in the helper.
    Declined,
    /// The session ended, for the reason the server gave.
    Ended { state: String, label: String },
    /// The connection to the server was lost; the helper stopped everything.
    Lost,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
    Hello {
        technician_name: String,
        technician_email: String,
        organization: String,
        #[allow(dead_code)]
        server_host: String,
        capabilities: Vec<String>,
    },
    Ended {
        state: String,
        label: String,
    },
    #[serde(other)]
    Other,
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("TLS protocol versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Pair with the server, ask the person, and follow the session until it ends.
pub async fn run(launch: &Launch, consent: Arc<dyn Consent>) -> Result<Outcome> {
    launch.check()?;
    let mut request = launch
        .socket_url()
        .into_client_request()
        .context("server address")?;
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", launch.token)
            .parse()
            .context("launch token")?,
    );
    let connector = tokio_tungstenite::Connector::Rustls(tls_config()?);
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(20),
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector)),
    )
    .await
    .context("the server did not answer")?
    .context(
        "the server refused this helper (the download may have expired or been used already)",
    )?;
    let (mut tx, rx) = ws.split();
    let mut incoming = messages(rx);

    // The server introduces the session first.
    let hello = loop {
        match incoming.next().await {
            Some(ServerMsg::Hello {
                technician_name,
                technician_email,
                organization,
                capabilities,
                ..
            }) => {
                break ConsentRequest {
                    technician_name: shown(&technician_name, 80),
                    technician_email: shown(&technician_email, 120),
                    organization: shown(&organization, 80),
                    server_host: launch.server_host().to_string(),
                    control: capabilities.iter().any(|c| c == "control_input"),
                }
            }
            Some(ServerMsg::Ended { state, label }) => return Ok(Outcome::Ended { state, label }),
            Some(_) => continue,
            None => return Ok(Outcome::Lost),
        }
    };

    // Ask, while still listening: if the session ends while the question is open, the
    // question is taken away and nothing is sent.
    let asking = {
        let consent = consent.clone();
        let hello = hello.clone();
        tokio::task::spawn_blocking(move || consent.ask(&hello))
    };
    let allowed = match decide(&mut incoming, async { asking.await.unwrap_or(false) }).await {
        Decision::Answer(allowed) => allowed,
        Decision::Finished(outcome) => {
            consent.cancel();
            return Ok(outcome);
        }
    };
    let answer = if allowed { "approve" } else { "decline" };
    tx.send(Message::text(json!({ "type": answer }).to_string()))
        .await
        .context("sending the answer")?;
    if !allowed {
        let _ = tx.close().await;
        return Ok(Outcome::Declined);
    }

    // Allowed. Media and input arrive in later steps; until then, follow the session.
    loop {
        match incoming.next().await {
            Some(ServerMsg::Ended { state, label }) => return Ok(Outcome::Ended { state, label }),
            Some(_) => {}
            None => return Ok(Outcome::Lost),
        }
    }
}

/// The server's messages, ending when the connection does.
fn messages<S>(rx: S) -> impl futures_util::Stream<Item = ServerMsg> + Unpin
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    rx.take_while(|m| std::future::ready(matches!(m, Ok(m) if !m.is_close())))
        .filter_map(|m| {
            std::future::ready(match m {
                Ok(Message::Text(t)) => {
                    Some(serde_json::from_str(t.as_str()).unwrap_or(ServerMsg::Other))
                }
                _ => None,
            })
        })
}

enum Decision {
    Answer(bool),
    Finished(Outcome),
}

/// Wait for the person's answer unless the session finishes first. When both are ready at
/// once, the session's end wins: an answer to a question that no longer stands is not sent.
async fn decide<S, F>(incoming: &mut S, answer: F) -> Decision
where
    S: futures_util::Stream<Item = ServerMsg> + Unpin,
    F: std::future::Future<Output = bool>,
{
    tokio::pin!(answer);
    loop {
        tokio::select! {
            biased;
            msg = incoming.next() => match msg {
                Some(ServerMsg::Ended { state, label }) => {
                    return Decision::Finished(Outcome::Ended { state, label })
                }
                Some(_) => {}
                None => return Decision::Finished(Outcome::Lost),
            },
            allowed = &mut answer => return Decision::Answer(allowed),
        }
    }
}

/// The file name the server gives a download for `token` from `server_url` (for tests and
/// for checking the two sides agree).
pub fn file_name_for(token: &str, server_url: &str) -> String {
    let server = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_url);
    format!("flyw8t-helper-{token}.{server}.exe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_token_and_server_from_its_name() {
        let name = file_name_for("Ab_c-12", "https://rmm.example.com");
        let l = launch_from_file_name(&name).unwrap();
        assert_eq!(l.token, "Ab_c-12");
        assert_eq!(l.server_url, "https://rmm.example.com");
        assert_eq!(l.server_host(), "rmm.example.com");
        assert_eq!(
            l.socket_url(),
            "wss://rmm.example.com/api/support/helper/ws"
        );
        // A second download of the same file, renamed by the browser.
        let again = name.replace(".exe", " (1).exe");
        assert_eq!(launch_from_file_name(&again).unwrap(), l);
    }

    #[test]
    fn refuses_names_it_cannot_trust() {
        assert!(launch_from_file_name("setup.exe").is_err());
        assert!(
            launch_from_file_name("flyw8t-helper-abc.exe").is_err(),
            "no server"
        );
        assert!(launch_from_file_name("flyw8t-helper-a b.c.exe").is_err());
        assert!(launch_from_file_name("flyw8t-helper-abc.!!!.exe").is_err());
        // Plaintext to anything but this machine is refused, as the server and agent refuse it.
        let plain = file_name_for("abc", "http://rmm.example.com");
        assert!(launch_from_file_name(&plain).is_err());
        let local = file_name_for("abc", "http://127.0.0.1:8080");
        assert_eq!(
            launch_from_file_name(&local).unwrap().socket_url(),
            "ws://127.0.0.1:8080/api/support/helper/ws"
        );
        let userinfo = file_name_for("abc", "https://evil@rmm.example.com");
        assert!(launch_from_file_name(&userinfo).is_err());
        // What is shown must be where it connects: no port the connector would read as the
        // default, no characters a parser could split differently.
        for bad in [
            "https://rmm.example.com:65536",
            "https://rmm.example.com:0",
            "https://rmm.example.com:44x",
            "https://rmm.example.com:",
            r"https://evil.example\.rmm.example.com",
            "https://evil.example%2frmm.example.com",
            "https://rmm.example.com?x=1",
            "https://rmm.example.com/#x",
            "https://-rmm.example.com",
            "https://[::1",
            "https://[nope]",
        ] {
            assert!(
                launch_from_file_name(&file_name_for("abc", bad)).is_err(),
                "{bad}"
            );
        }
        for good in [
            "https://rmm.example.com:8443",
            "https://rmm.example.com/flyw8t",
            "https://[2001:db8::1]:443",
            "http://[::1]:8080",
            "http://localhost:3000",
        ] {
            assert!(
                launch_from_file_name(&file_name_for("abc", good)).is_ok(),
                "{good}"
            );
        }
    }

    #[test]
    fn server_text_cannot_hide_or_fake_the_server_line() {
        let r = ConsentRequest {
            technician_name: shown(
                "Contoso IT\nServer: support.contoso.com\nAllow?\u{0}\u{202E}moc.live",
                80,
            ),
            technician_email: shown(&"a".repeat(500), 120),
            organization: shown("Contoso\r\n\u{200B}Dental", 80),
            server_host: "evil.example".into(),
            control: true,
        };
        assert_eq!(
            r.technician_name,
            "Contoso IT Server: support.contoso.com Allow? moc.live"
        );
        assert_eq!(r.technician_email.chars().count(), 121);
        assert_eq!(r.organization, "Contoso Dental");
        let (title, text) = r.dialog();
        assert!(title.contains("evil.example"));
        assert!(!text.contains('\0'));
        assert!(
            text.starts_with("The server evil.example asks to see your screen and use your mouse"),
            "{text}"
        );
        // The server's words come after the server line, on lines of their own.
        assert!(text.lines().any(|l| l.starts_with("Contoso IT Server:")));
    }

    #[tokio::test]
    async fn an_ending_already_received_beats_an_answer_given_at_the_same_moment() {
        // Both ready at once, many times over: the ending must win every time.
        for _ in 0..64 {
            let mut incoming = futures_util::stream::iter(vec![
                ServerMsg::Other,
                ServerMsg::Ended {
                    state: "revoked".into(),
                    label: "ended".into(),
                },
            ]);
            let d = decide(&mut incoming, std::future::ready(true)).await;
            assert!(matches!(d, Decision::Finished(Outcome::Ended { .. })));
        }
        // With nothing from the server, the answer stands.
        let mut quiet = futures_util::stream::pending();
        assert!(matches!(
            decide(&mut quiet, std::future::ready(true)).await,
            Decision::Answer(true)
        ));
    }
}
