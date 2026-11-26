use crate::{error::AppError, Shared};
use anyhow::{anyhow, ensure, Context, Result};
use flyw8t_protocol::enrollment_package::is_template;
use std::time::Duration;

const MAX_AGENT_BYTES: usize = 32 * 1024 * 1024;

pub async fn template(state: &Shared) -> Result<&[u8], AppError> {
    state
        .windows_agent_template
        .get_or_try_init(fetch_template)
        .await
        .map(Vec::as_slice)
        .map_err(|error| {
            tracing::warn!(%error, "Windows installer download unavailable");
            AppError::BadRequest("The Windows installer is unavailable for this server release. Return to the enrollment page and choose Create manual token to use the signed agent and setup commands.".into())
        })
}

async fn fetch_template() -> Result<Vec<u8>> {
    let version = env!("CARGO_PKG_VERSION");
    let release = format!("https://github.com/spilloid/flyw8t/releases/download/v{version}");
    let filename = format!("flyw8t-agent-v{version}-x86_64-pc-windows-msvc.exe");
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    let client = reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() < 4
                && matches!(
                    attempt.url().host_str(),
                    Some("github.com" | "release-assets.githubusercontent.com")
                )
            {
                attempt.follow()
            } else {
                attempt.error("unexpected release redirect")
            }
        }))
        .build()?;
    let sums = download(&client, &format!("{release}/SHA256SUMS"), 16 * 1024).await?;
    let expected = std::str::from_utf8(&sums)?
        .lines()
        .filter_map(|line| line.split_once("  "))
        .find_map(|(digest, name)| (name == filename).then_some(digest))
        .ok_or_else(|| anyhow!("release checksums do not include the Windows agent"))?;
    let agent = download(&client, &format!("{release}/{filename}"), MAX_AGENT_BYTES).await?;
    let actual = ring::digest::digest(&ring::digest::SHA256, &agent);
    ensure!(
        hex::encode(actual.as_ref()).eq_ignore_ascii_case(expected),
        "Windows agent checksum mismatch"
    );
    ensure!(
        is_template(&agent),
        "release agent does not support enrollment packages"
    );
    Ok(agent)
}

async fn download(client: &reqwest::Client, url: &str, limit: usize) -> Result<Vec<u8>> {
    let mut reply = client.get(url).send().await?.error_for_status()?;
    ensure!(
        reply.content_length().unwrap_or(0) <= limit as u64,
        "release asset is too large"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = reply.chunk().await.context("reading release asset")? {
        ensure!(
            chunk.len() <= limit - bytes.len(),
            "release asset is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
