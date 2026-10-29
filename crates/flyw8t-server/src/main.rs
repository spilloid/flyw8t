use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        s.cancel();
    });
    flyw8t_server::serve(state, shutdown, None).await
}
