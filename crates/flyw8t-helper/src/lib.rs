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

/// HTTPS, or plaintext only to this machine (the same rule as the server and the agent).
fn check_server_url(url: &str) -> Result<()> {
    let (scheme, rest) = url
        .split_once("://")
        .context("no scheme in the server address")?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        bail!("the server address is not valid");
    }
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
        _ => bail!("the server address must use https"),
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

/// The person's decision. The Windows build shows a dialog; tests answer directly.
pub trait Consent: Send + Sync + 'static {
    /// Blocks until the person decides. `true` is Allow.
    fn ask(&self, request: &ConsentRequest) -> bool;
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
    let (mut ws, _) = tokio::time::timeout(
        Duration::from_secs(20),
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector)),
    )
    .await
    .context("the server did not answer")?
    .context(
        "the server refused this helper (the download may have expired or been used already)",
    )?;

    // The server introduces the session first.
    let hello = loop {
        match next(&mut ws).await? {
            Some(ServerMsg::Hello {
                technician_name,
                technician_email,
                organization,
                capabilities,
                ..
            }) => {
                break ConsentRequest {
                    technician_name,
                    technician_email,
                    organization,
                    server_host: launch.server_host().to_string(),
                    control: capabilities.iter().any(|c| c == "control_input"),
                }
            }
            Some(ServerMsg::Ended { state, label }) => return Ok(Outcome::Ended { state, label }),
            Some(_) => continue,
            None => return Ok(Outcome::Lost),
        }
    };

    // Ask, while still listening: if the session ends while the question is open, the answer
    // no longer matters and nothing is sent.
    let asking = {
        let consent = consent.clone();
        let hello = hello.clone();
        tokio::task::spawn_blocking(move || consent.ask(&hello))
    };
    tokio::pin!(asking);
    let allowed = loop {
        tokio::select! {
            answer = &mut asking => break answer.unwrap_or(false),
            msg = next(&mut ws) => match msg? {
                Some(ServerMsg::Ended { state, label }) => return Ok(Outcome::Ended { state, label }),
                Some(_) => {}
                None => return Ok(Outcome::Lost),
            },
        }
    };
    let answer = if allowed { "approve" } else { "decline" };
    ws.send(Message::text(json!({ "type": answer }).to_string()))
        .await
        .context("sending the answer")?;
    if !allowed {
        let _ = ws.close(None).await;
        return Ok(Outcome::Declined);
    }

    // Allowed. Media and input arrive in later steps; until then, follow the session.
    loop {
        match next(&mut ws).await? {
            Some(ServerMsg::Ended { state, label }) => return Ok(Outcome::Ended { state, label }),
            Some(_) => {}
            None => return Ok(Outcome::Lost),
        }
    }
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The next message from the server; `None` once the connection is gone.
async fn next(ws: &mut Socket) -> Result<Option<ServerMsg>> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => {
                return Ok(Some(
                    serde_json::from_str(t.as_str()).unwrap_or(ServerMsg::Other),
                ))
            }
            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return Ok(None),
            Some(Ok(_)) => continue,
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
    }
}
