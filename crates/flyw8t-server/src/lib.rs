//! flyw8t control plane.
//!
//! One process: the agent gateway (`/api/agent/ws`), the job orchestrator and its deadline
//! sweeper, the server-rendered web console, and the JSON API. PostgreSQL is the record of
//! truth; the only in-memory state is the registry of live connections and rate-limit windows,
//! both of which are safe to lose on restart. See `docs/architecture.md`.

// SQL rows are decoded into tuples next to the query that defines them; naming every
// tuple type would move the column list away from the SELECT it must match.
#![allow(clippy::type_complexity)]

pub mod api;
pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod gateway;
pub mod jobs;
pub mod metrics;
pub mod queries;
pub mod ratelimit;
pub mod registry;
pub mod remote_access;
pub mod web;

use anyhow::Context;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use config::Config;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub registry: registry::Registry,
    pub limiter: ratelimit::RateLimiter,
    pub remote_access: Box<dyn remote_access::RemoteAccessProvider>,
    pub started_unix: u64,
}

pub type Shared = Arc<AppState>;

/// Connect, migrate, bootstrap the first administrator if configured.
pub async fn init(config: Config) -> anyhow::Result<Shared> {
    let db = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(&config.database_url)
        .await
        .context("connecting to PostgreSQL")?;
    MIGRATOR.run(&db).await.context("applying migrations")?;
    let state = Arc::new(AppState {
        db,
        config,
        registry: Default::default(),
        limiter: Default::default(),
        remote_access: Box::new(remote_access::NotConfigured),
        started_unix: time::OffsetDateTime::now_utc().unix_timestamp() as u64,
    });
    bootstrap_admin(&state).await?;
    Ok(state)
}

/// Create the first administrator from configuration, only when no users exist. There is no
/// "first visitor becomes admin" path.
async fn bootstrap_admin(state: &Shared) -> anyhow::Result<()> {
    let Some((email, password)) = state.config.bootstrap_admin.clone() else {
        return Ok(());
    };
    let (none,): (bool,) = sqlx::query_as("SELECT NOT EXISTS (SELECT 1 FROM users)")
        .fetch_one(&state.db)
        .await?;
    if !none {
        return Ok(());
    }
    anyhow::ensure!(
        password.chars().count() >= auth::MIN_PASSWORD_LEN,
        "FLYW8T_BOOTSTRAP_ADMIN_PASSWORD must be at least {} characters",
        auth::MIN_PASSWORD_LEN
    );
    let email = email.trim().to_lowercase();
    let (id,): (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO users (email, display_name, password_hash, role) VALUES ($1, 'Administrator', $2, 'admin') RETURNING id",
    )
    .bind(&email)
    .bind(auth::hash_password(&password)?)
    .fetch_one(&state.db)
    .await?;
    audit::Audit::system("user.bootstrap_admin")
        .target("user", id)
        .detail(serde_json::json!({ "email": email }))
        .record(&state.db)
        .await?;
    tracing::info!(%email, "created bootstrap administrator");
    Ok(())
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/login", get(web::login_form).post(web::login))
        .route("/logout", post(web::logout))
        .route("/", get(web::overview))
        .route("/devices", get(web::devices))
        .route("/devices/{id}", get(web::device))
        .route("/devices/{id}/jobs", post(web::run_job))
        .route("/devices/{id}/revoke", post(web::revoke_device))
        .route("/jobs", get(web::jobs_list))
        .route("/jobs/{id}", get(web::job))
        .route("/jobs/{id}/cancel", post(web::cancel_job))
        .route(
            "/organizations",
            get(web::organizations).post(web::create_org),
        )
        .route("/organizations/{id}", get(web::organization))
        .route("/organizations/{id}/sites", post(web::add_site))
        .route(
            "/organizations/{id}/enrollment-tokens",
            post(web::create_enrollment_token),
        )
        .route(
            "/organizations/{id}/enrollment-tokens/{token}/revoke",
            post(web::revoke_enrollment_token),
        )
        .route("/audit", get(web::audit))
        .route("/admin", get(web::admin))
        .route("/admin/users", post(web::create_user))
        .route("/admin/tokens", post(web::create_api_token))
        .route("/admin/tokens/{id}/revoke", post(web::revoke_api_token))
        .route("/static/app.css", get(stylesheet))
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .route("/api/agent/ws", get(gateway::agent_ws))
        .route("/api/v1/catalog", get(api::catalog))
        .route("/api/v1/devices", get(api::devices))
        .route("/api/v1/devices/{id}", get(api::device))
        .route(
            "/api/v1/devices/{id}/jobs",
            get(api::device_jobs).post(api::create_job),
        )
        .route("/api/v1/jobs/{id}", get(api::job))
        .route("/api/v1/jobs/{id}/cancel", post(api::cancel_job))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

async fn stylesheet() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "max-age=300"),
        ],
        flyw8t_web::STYLESHEET,
    )
        .into_response()
}

/// Ready means the database answers; liveness (`/healthz`) means only that the process does.
async fn readyz(State(state): State<Shared>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => "ready".into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable").into_response()
        }
    }
}

async fn metrics_handler(State(state): State<Shared>) -> Response {
    match metrics::render(&state).await {
        Ok(body) => ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response(),
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "metrics unavailable");
            (StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable").into_response()
        }
    }
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: header::HeaderName, v: &'static str| {
        h.entry(k).or_insert(HeaderValue::from_static(v));
    };
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(
        h,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    set(h, header::CACHE_CONTROL, "no-store");
    resp
}

/// Periodic deadline resolution and retry, until `shutdown`.
pub async fn run_sweeper(state: Shared, shutdown: CancellationToken) {
    let mut tick = tokio::time::interval(state.config.sweep_interval);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tick.tick() => match jobs::sweep(&state).await {
                Ok(()) => metrics::SWEEPS_OK.inc(),
                Err(e) => {
                    metrics::SWEEPS_FAILED.inc();
                    tracing::error!(error = %format!("{e:#}"), "sweep failed");
                }
            },
        }
    }
}

/// Serve until `shutdown`. Returns the bound address through `bound` once listening.
pub async fn serve(
    state: Shared,
    shutdown: CancellationToken,
    bound: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) -> anyhow::Result<()> {
    let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(run_sweeper(state.clone(), shutdown.clone()));
    let handle = axum_server::Handle::new();
    let h2 = handle.clone();
    let s2 = shutdown.clone();
    tokio::spawn(async move {
        s2.cancelled().await;
        h2.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
    });
    if let Some(tx) = bound {
        let h3 = handle.clone();
        tokio::spawn(async move {
            if let Some(addr) = h3.listening().await {
                let _ = tx.send(addr);
            }
        });
    }
    match &state.config.tls {
        Some((cert, key)) => {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let _ = rustls::crypto::CryptoProvider::install_default((*provider).clone());
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .context("loading TLS certificate and key")?;
            tracing::info!(addr = %state.config.bind, "listening (TLS)");
            axum_server::bind_rustls(state.config.bind, tls)
                .handle(handle)
                .serve(app)
                .await?;
        }
        None => {
            tracing::info!(addr = %state.config.bind, "listening (plaintext; TLS must be terminated in front of this server unless the public URL is loopback)");
            axum_server::bind(state.config.bind)
                .handle(handle)
                .serve(app)
                .await?;
        }
    }
    Ok(())
}
