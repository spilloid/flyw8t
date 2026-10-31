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
pub mod client_ip;
pub mod config;
pub mod error;
pub mod gateway;
pub mod jobs;
pub mod metrics;
pub mod mfa;
pub mod queries;
pub mod ratelimit;
pub mod registry;
pub mod remote_access;
pub mod support;
pub mod totp;
pub mod web;

use anyhow::Context;
use axum::extract::{Path, Request, State};
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
    pub support: support::SupportHub,
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
        support: Default::default(),
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
        .route("/login/mfa", get(mfa::challenge_form).post(mfa::challenge))
        .route("/account", get(mfa::account))
        .route("/account/mfa", get(mfa::setup_form).post(mfa::setup))
        .route("/account/mfa/recovery-codes", post(mfa::regenerate_codes))
        .route("/account/mfa/disable", post(mfa::disable))
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
        .route("/admin/users/{id}/mfa/reset", post(mfa::admin_reset))
        .route("/admin/tokens", post(web::create_api_token))
        .route("/admin/tokens/{id}/revoke", post(web::revoke_api_token))
        .route(
            "/support",
            get(support::list_page).post(support::create_handler),
        )
        .route("/support/{id}", get(support::session_page))
        .route("/support/{id}/end", post(support::end_handler))
        .route("/api/support/{id}/ws", get(support::technician_ws))
        .route("/api/support/participant/ws", get(support::participant_ws))
        .route("/api/support/helper/ws", get(support::helper_ws))
        .route("/s/helper/{file}", get(support::helper_download))
        .route("/s", get(support::entry_page).post(support::enter_code))
        .route(
            "/s/{invite}",
            get(support::open_invite).post(support::spend_invite),
        )
        .route("/static/support.js", get(support_script))
        .route("/static/app.css", get(stylesheet))
        .route("/static/icon.svg", get(icon))
        .route("/static/icons/{name}", get(app_icon))
        .route("/manifest.webmanifest", get(manifest))
        .route("/favicon.ico", get(icon))
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
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}

async fn icon() -> Response {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "max-age=86400"),
        ],
        flyw8t_web::ICON_SVG,
    )
        .into_response()
}

async fn app_icon(Path(name): Path<String>) -> Response {
    match flyw8t_web::APP_ICONS.iter().find(|(n, _, _)| *n == name) {
        Some((_, ty, bytes)) => (
            [
                (header::CONTENT_TYPE, *ty),
                (header::CACHE_CONTROL, "max-age=86400"),
            ],
            *bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn manifest() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/manifest+json"),
            (header::CACHE_CONTROL, "max-age=3600"),
        ],
        flyw8t_web::MANIFEST,
    )
        .into_response()
}

async fn support_script() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        flyw8t_web::SUPPORT_JS,
    )
        .into_response()
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

async fn security_headers(State(state): State<Shared>, req: Request, next: Next) -> Response {
    if is_cross_origin_write(&state.config, &req) {
        return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: header::HeaderName, v: &'static str| {
        h.entry(k).or_insert(HeaderValue::from_static(v));
    };
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    // Not `no-referrer`: under it, browsers send `Origin: null` on same-origin form posts,
    // which the cross-origin check above must refuse. `same-origin` keeps referrers inside
    // this site and lets same-origin posts carry their real Origin.
    set(h, header::REFERRER_POLICY, "same-origin");
    set(
        h,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; style-src 'self'; img-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
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
            _ = tick.tick() => match async { jobs::sweep(&state).await?; support::sweep(&state).await }.await {
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

/// A state-changing request whose `Origin` names a different site. Browsers always send
/// `Origin` on cross-site POSTs, so this refuses login CSRF and is defense in depth behind
/// the per-session CSRF token everywhere else. Requests without `Origin` (API clients,
/// agents) are not affected; the JSON API accepts only bearer tokens anyway.
fn is_cross_origin_write(config: &config::Config, req: &Request) -> bool {
    use axum::http::Method;
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    origin_is_self(config, req.headers()) == Some(false)
}

/// Whether the request's `Origin` is this server: the public URL's scheme with the requested
/// host and port. `None` when there is no `Origin` header. Comparing the scheme too means an
/// `http://` page on the same host name is a different origin from an HTTPS deployment.
pub(crate) fn origin_is_self(
    config: &config::Config,
    headers: &axum::http::HeaderMap,
) -> Option<bool> {
    let origin = headers.get(header::ORIGIN)?.to_str().ok();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let Some(origin) = origin.and_then(canonical_origin) else {
        return Some(false);
    };
    let scheme = config
        .public_url
        .split_once("://")
        .map_or("https", |(s, _)| s);
    // The configured public origin always counts, so a reverse proxy that rewrites `Host`
    // (to 127.0.0.1:8080, say) does not turn every browser request into a cross-origin one.
    let public = canonical_origin(&config.public_url);
    let by_host = host.and_then(|h| canonical_origin(&format!("{scheme}://{h}")));
    Some(public.as_ref() == Some(&origin) || by_host.as_ref() == Some(&origin))
}

/// An origin as browsers serialize it: `scheme://host[:port]`, lowercase, without a path,
/// and without the scheme's default port (443 for https, 80 for http).
fn canonical_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let default = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => return None,
    };
    let authority = authority.strip_suffix(default).unwrap_or(&authority);
    Some(format!("{scheme}://{authority}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers(host: &str, origin: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, host.parse().unwrap());
        if let Some(o) = origin {
            h.insert(header::ORIGIN, o.parse().unwrap());
        }
        h
    }

    #[test]
    fn origin_must_match_scheme_host_and_port() {
        let https = config::Config {
            public_url: "https://rmm.example.com".into(),
            ..config::Config::defaults()
        };
        let h = |o| headers("rmm.example.com", Some(o));
        assert_eq!(
            origin_is_self(&https, &h("https://rmm.example.com")),
            Some(true)
        );
        assert_eq!(
            origin_is_self(&https, &h("HTTPS://RMM.example.com")),
            Some(true)
        );
        assert_eq!(
            origin_is_self(&https, &h("http://rmm.example.com")),
            Some(false),
            "scheme differs"
        );
        assert_eq!(
            origin_is_self(&https, &h("https://rmm.example.com:8443")),
            Some(false),
            "port differs"
        );
        assert_eq!(
            origin_is_self(&https, &h("https://evil.example")),
            Some(false)
        );
        assert_eq!(origin_is_self(&https, &h("null")), Some(false));
        assert_eq!(
            origin_is_self(&https, &headers("rmm.example.com", None)),
            None
        );
        // Behind a proxy that rewrites Host, the configured public origin still matches.
        let proxied = |o| headers("127.0.0.1:8080", Some(o));
        assert_eq!(
            origin_is_self(&https, &proxied("https://rmm.example.com")),
            Some(true)
        );
        assert_eq!(
            origin_is_self(&https, &proxied("http://rmm.example.com")),
            Some(false)
        );
        assert_eq!(
            origin_is_self(&https, &proxied("https://evil.example")),
            Some(false)
        );
        // An explicit default port in the configuration matches the browser's serialization.
        let explicit = config::Config {
            public_url: "https://RMM.example.com:443/".into(),
            ..config::Config::defaults()
        };
        assert_eq!(
            origin_is_self(&explicit, &proxied("https://rmm.example.com")),
            Some(true)
        );
        assert_eq!(
            origin_is_self(&explicit, &h("https://rmm.example.com")),
            Some(true)
        );
        assert_eq!(
            origin_is_self(&explicit, &proxied("https://rmm.example.com:8443")),
            Some(false)
        );
        assert_eq!(
            canonical_origin("http://host:80"),
            Some("http://host".into())
        );
        assert_eq!(
            canonical_origin("http://host:8080/x"),
            Some("http://host:8080".into())
        );
        assert_eq!(canonical_origin("null"), None);
    }
}
