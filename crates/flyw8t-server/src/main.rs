use tokio_util::sync::CancellationToken;

fn main() -> anyhow::Result<()> {
    // `flyw8t-server healthcheck`: exit 0 if this host's server reports ready. Used by the
    // container HEALTHCHECK so the image needs no curl.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck();
    }
    tokio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .with_ansi(false)
        .init();
    let config = flyw8t_server::config::Config::from_env()?;
    let state = flyw8t_server::init(config).await?;
    let shutdown = CancellationToken::new();
    let s = shutdown.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutting down");
        s.cancel();
    });
    flyw8t_server::serve(state, shutdown, None).await
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn healthcheck() -> anyhow::Result<()> {
    use std::io::{Read, Write};
    let bind = std::env::var("FLYW8T_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let port = bind.rsplit_once(':').map_or("8080", |(_, p)| p);
    let mut s = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))?;
    if std::env::var("FLYW8T_TLS_CERT").is_ok_and(|v| !v.trim().is_empty()) {
        // Native TLS: this probe has no TLS client, so it can only prove the listener is up,
        // not that the database answers. External monitoring should probe /readyz over HTTPS.
        return Ok(());
    }
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    s.write_all(b"GET /readyz HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    let mut buf = String::new();
    s.read_to_string(&mut buf)?;
    anyhow::ensure!(
        buf.starts_with("HTTP/1.0 200") || buf.starts_with("HTTP/1.1 200"),
        "not ready: {}",
        buf.lines().next().unwrap_or("")
    );
    Ok(())
}
