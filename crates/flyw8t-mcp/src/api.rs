use std::{env, fs::File, io::Read, net::IpAddr, path::Path, time::Duration};

use anyhow::{anyhow, bail, ensure, Context, Result};
use futures_util::StreamExt;
use reqwest::{
    header::{HeaderValue, AUTHORIZATION},
    redirect, Client, RequestBuilder, Response, StatusCode, Url,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};

use crate::frame::{Arguments, Envelope, RequestKey, MAX_PNG};
use clap::Parser;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    version,
    about = "Connect an MCP client to the Flyw8t technician API over stdio"
)]
pub struct Settings {
    /// Console HTTPS origin (loopback HTTP is supported for local testing).
    #[arg(long, env = "FLYW8T_SERVER_URL")]
    server: Option<String>,
    /// Private file containing the technician API token.
    #[arg(long, env = "FLYW8T_MCP_TOKEN_FILE")]
    token_file: Option<PathBuf>,
    /// Additional trusted certificate authority in PEM format.
    #[arg(long, env = "FLYW8T_MCP_CA_FILE")]
    ca_cert: Option<PathBuf>,
    /// Enable the device list and the built-in system.info diagnostic tools.
    #[arg(long, env = "FLYW8T_MCP_DEVICE_DIAGNOSTICS")]
    device_diagnostics: bool,
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;

const MAX_ENVELOPE_JSON: usize = (MAX_PNG + 32).div_ceil(3) * 4 + 2048;

pub struct Api {
    client: Client,
    origin: Url,
    bearer: HeaderValue,
    pub(crate) device_diagnostics: bool,
}

#[derive(Default, Deserialize)]
pub struct Capabilities {
    pub support_screenshot: bool,
    #[serde(default)]
    pub support_session_status: bool,
}

#[derive(Deserialize, serde::Serialize)]
struct SessionStatus {
    session_id: Uuid,
    state: String,
    screenshot_access: String,
}

fn local_origin(url: &Url) -> bool {
    url.host_str().is_some_and(|h| {
        h.trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    })
}

fn parse_origin(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).map_err(|_| anyhow!("FLYW8T_SERVER_URL must be an HTTPS origin."))?;
    ensure!(
        url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "Configure a server origin without a path, credentials, query, or fragment."
    );
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && local_origin(&url)),
        "Use HTTPS for the flyw8t server. Local fixtures may use HTTP at a loopback IP."
    );
    Ok(url)
}

fn read_file(path: &Path, limit: usize, name: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take((limit + 1) as u64).read_to_end(&mut bytes))
        .map_err(|_| anyhow!("Could not read {name}."))?;
    ensure!(bytes.len() <= limit, "{name} is too large.");
    Ok(bytes)
}

impl Api {
    pub fn from_settings(settings: Settings) -> Result<Self> {
        let origin = parse_origin(
            settings
                .server
                .as_deref()
                .context("Set --server or FLYW8T_SERVER_URL.")?,
        )?;
        let secret = match (env::var("FLYW8T_MCP_TOKEN").ok(), settings.token_file) {
            (Some(token), None) => token,
            (None, Some(path)) => {
                String::from_utf8(read_file(path.as_ref(), 4096, "FLYW8T_MCP_TOKEN_FILE")?)
                    .map_err(|_| anyhow!("Token file must contain UTF-8 text."))?
            }
            _ => bail!("Select exactly one credential source: --token-file (FLYW8T_MCP_TOKEN_FILE) or FLYW8T_MCP_TOKEN."),
        };
        let secret = secret.trim();
        ensure!(
            !secret.is_empty()
                && secret.len() <= 4096
                && secret.bytes().all(|b| b.is_ascii_graphic()),
            "Invalid MCP credential."
        );
        let mut bearer = HeaderValue::from_str(&format!("Bearer {secret}"))
            .map_err(|_| anyhow!("Invalid MCP credential."))?;
        bearer.set_sensitive(true);
        let mut builder = Client::builder()
            .redirect(redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30));
        if local_origin(&origin) {
            builder = builder.no_proxy();
        }
        if let Some(path) = settings.ca_cert {
            let pem = read_file(path.as_ref(), 1024 * 1024, "FLYW8T_MCP_CA_FILE")?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .context("Invalid PEM in FLYW8T_MCP_CA_FILE.")?;
            ensure!(
                !certs.is_empty(),
                "FLYW8T_MCP_CA_FILE contains no certificates."
            );
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        Ok(Self {
            client: builder
                .build()
                .map_err(|_| anyhow!("Could not initialize HTTPS."))?,
            origin,
            bearer,
            device_diagnostics: settings.device_diagnostics,
        })
    }

    fn url(&self, path: &str) -> Url {
        let mut url = self.origin.clone();
        url.set_path(path);
        url
    }

    pub async fn capabilities(&self) -> Result<Capabilities> {
        let response = self
            .client
            .get(self.url("/api/v1/mcp/capabilities"))
            .timeout(Duration::from_secs(8))
            .header(AUTHORIZATION, self.bearer.clone())
            .send()
            .await
            .map_err(transport_error)?;
        if self.device_diagnostics && response.status() == StatusCode::NOT_FOUND {
            return Ok(Capabilities::default());
        }
        read_response(response, 4096).await
    }

    pub(crate) fn diagnostic_request(&self, method: reqwest::Method, path: &str) -> RequestBuilder {
        self.client
            .request(method, self.url(path))
            .timeout(Duration::from_secs(8))
            .header(AUTHORIZATION, self.bearer.clone())
    }

    pub async fn session_status(&self, session: Uuid) -> Result<Value> {
        let path = format!("/api/v1/support/{session}/status");
        let response = self
            .client
            .get(self.url(&path))
            .timeout(Duration::from_secs(8))
            .header(AUTHORIZATION, self.bearer.clone())
            .send()
            .await
            .map_err(|err| {
                if err.is_timeout() {
                    anyhow!("The server took too long to report session status.")
                } else {
                    transport_error(err)
                }
            })?;
        let status: SessionStatus = read_response(response, 4096).await?;
        ensure!(
            status.session_id == session
                && matches!(
                    status.state.as_str(),
                    "created"
                        | "waiting"
                        | "authorizing"
                        | "awaiting_helper"
                        | "connecting"
                        | "connected"
                        | "disconnecting"
                        | "closed"
                        | "expired"
                        | "rejected"
                        | "connection_failed"
                        | "revoked"
                )
                && matches!(
                    status.screenshot_access.as_str(),
                    "unavailable" | "consent_required" | "consent_pending" | "allowed" | "revoked"
                ),
            "The server returned invalid session status."
        );
        let data = serde_json::to_value(status)?;
        Ok(json!({
            "content":[{"type":"text","text":data.to_string()}],
            "structuredContent":data,
            "isError":false
        }))
    }

    pub async fn screenshot(&self, args: &Arguments) -> Result<Value> {
        let key = RequestKey::generate()?;
        let mut body = json!({"request_id": args.request_id, "public_key": key.public_key()?});
        if let Some(crop) = &args.crop {
            body["crop"] = serde_json::to_value(crop)?;
        }
        let path = format!("/api/v1/support/{}/screenshot", args.session_id);
        let response = self
            .client
            .post(self.url(&path))
            .header(AUTHORIZATION, self.bearer.clone())
            .json(&body)
            .send()
            .await
            .map_err(transport_error)?;
        let envelope: Envelope = read_response(response, MAX_ENVELOPE_JSON).await?;
        let frame = key.open(envelope, args)?;
        let metadata = json!({"session_id": args.session_id, "request_id": args.request_id,
            "width": frame.width, "height":frame.height, "observed_at_unix_ms":frame.observed_at_ms});
        Ok(
            json!({"content":[{"type":"image","mimeType":"image/png","data":frame.png},
            {"type":"text","text": metadata.to_string()}], "structuredContent": metadata, "isError":false}),
        )
    }
}

fn transport_error(err: reqwest::Error) -> anyhow::Error {
    if err.is_timeout() {
        anyhow!("The server took too long. Reuse the same request ID when checking this capture.")
    } else {
        anyhow!("Cannot reach the configured flyw8t server. Check the server address, network, and certificate.")
    }
}

async fn read_response<T: DeserializeOwned>(response: Response, success_limit: usize) -> Result<T> {
    read_reply(response, success_limit, refusal).await
}

pub(crate) async fn read_reply<T: DeserializeOwned>(
    response: Response,
    success_limit: usize,
    refusal: fn(StatusCode, &str) -> &'static str,
) -> Result<T> {
    let status = response.status();
    let limit = if status.is_success() {
        success_limit
    } else {
        4096
    };
    ensure!(
        response
            .content_length()
            .is_none_or(|len| len <= limit as u64),
        "Server response exceeds the delivery limit."
    );
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|_| anyhow!("The server did not finish delivering its response."))?;
        ensure!(
            chunk.len() <= limit - bytes.len(),
            "Server response exceeds the delivery limit."
        );
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let code = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default();
        bail!("{}", refusal(status, code));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("The server returned an invalid API response."))
}

// Give the client actionable states without forwarding arbitrary response text.
fn refusal(status: StatusCode, code: &str) -> &'static str {
    match code {
        "consent_required" => "The participant has been asked to allow screenshots for this AI client. After they allow, reuse the same request ID.",
        "screenshot_declined" => "The participant declined screenshots for this client.",
        "screenshot_revoked" => "The participant or viewer revoked screenshot access.",
        "session_unavailable" => "Open the attended viewer and check that the participant is sharing a screen.",
        "another_recipient" => "Another AI client is selected for this session.",
        "capture_in_progress" => "A capture is in progress. Wait for its existing request to finish.",
        "already_requested" => "This request ID was already used. It cannot capture a second frame.",
        "capture_expired" => "The viewer did not deliver a frame before this request expired.",
        "no_fresh_frame" => "The viewer has no fresh frame from the shared screen.",
        "source_changed" => "The shared source changed. Ask the participant to confirm the new source.",
        "image_too_large" => "The selected image exceeds the limit. Request a smaller crop.",
        "capture_failed" => "The viewer could not capture the selected shared screen.",
        _ => match status {
            StatusCode::UNAUTHORIZED => "The flyw8t credential expired or was revoked. Reauthorize the MCP profile.",
            StatusCode::FORBIDDEN => "This technician credential does not permit screenshots.",
            StatusCode::NOT_FOUND => "The session or API route is unavailable to this technician.",
            StatusCode::TOO_MANY_REQUESTS => "Too many requests. Wait before requesting another frame.",
            s if s.is_redirection() => "The configured server redirected the request. Configure its final HTTPS origin.",
            _ => "The server refused the request. Check the current support session and server configuration.",
        },
    }
}
