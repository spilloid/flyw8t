//! Test harness: a real server on a fresh PostgreSQL database, a cookie-carrying "browser"
//! that drives the console through the router, and helpers to enroll and run real agents.
//!
//! These tests need PostgreSQL. Set `FLYW8T_TEST_DATABASE_URL` to a URL whose user may
//! `CREATE DATABASE` (e.g. `postgres://flyw8t:devpass@127.0.0.1:55432/postgres`) and run
//! `cargo test -p flyw8t-server -- --ignored`. Each test gets its own database.

#![allow(dead_code)]

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use flyw8t_agent::{Agent, AgentConfig};
use flyw8t_server::config::Config;
use flyw8t_server::Shared;
use sqlx::postgres::PgPoolOptions;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use uuid::Uuid;

pub const ADMIN_EMAIL: &str = "admin@example.test";
pub const ADMIN_PASSWORD: &str = "correct-horse-battery";

pub fn admin_url() -> String {
    std::env::var("FLYW8T_TEST_DATABASE_URL")
        .expect("FLYW8T_TEST_DATABASE_URL must point at a PostgreSQL server for --ignored tests")
}

/// Create an empty database for one test and return its URL.
pub async fn fresh_database() -> String {
    let admin = admin_url();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin)
        .await
        .expect("connect to test PostgreSQL");
    let name = format!("flyw8t_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let (base, _) = admin.rsplit_once('/').unwrap();
    format!("{base}/{name}")
}

pub struct TestServer {
    pub state: Shared,
    pub addr: SocketAddr,
    pub shutdown: CancellationToken,
    pub task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

pub fn test_config(database_url: &str) -> Config {
    Config {
        database_url: database_url.to_string(),
        bootstrap_admin: Some((ADMIN_EMAIL.into(), ADMIN_PASSWORD.into())),
        heartbeat_secs: 5,
        sweep_interval: Duration::from_millis(200),
        silence_grace: Duration::from_secs(1),
        ..Config::defaults()
    }
}

pub async fn start(config: Config) -> TestServer {
    let state = flyw8t_server::init(config).await.expect("server init");
    let shutdown = CancellationToken::new();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(flyw8t_server::serve(
        state.clone(),
        shutdown.clone(),
        Some(tx),
    ));
    let addr = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .expect("server bind timed out")
        .unwrap();
    TestServer {
        state,
        addr,
        shutdown,
        task,
    }
}

pub async fn start_fresh() -> TestServer {
    start(test_config(&fresh_database().await)).await
}

impl TestServer {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub async fn stop(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(15), self.task).await;
        self.state.db.close().await;
    }

    /// Send a request through the router, as if from 127.0.0.1.
    pub async fn request(&self, req: Request<Body>) -> Response {
        let mut req = req;
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50000))));
        let resp = flyw8t_server::router(self.state.clone())
            .oneshot(req)
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        Response {
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    }

    pub async fn login(&self, email: &str, password: &str) -> Browser {
        let body = form(&[("email", email), ("password", password)]);
        let resp = self
            .request(
                Request::post("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await;
        assert_eq!(
            resp.status,
            StatusCode::SEE_OTHER,
            "login failed: {}",
            resp.body
        );
        let cookie = resp.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let mut b = Browser {
            server_state: self.state.clone(),
            cookie,
            csrf: String::new(),
        };
        let home = b.get(self, "/").await;
        assert_eq!(home.status, StatusCode::OK);
        b.csrf = extract(&home.body, r#"name="csrf" value="([^"]+)""#).expect("csrf token on page");
        b
    }

    pub async fn admin(&self) -> Browser {
        self.login(ADMIN_EMAIL, ADMIN_PASSWORD).await
    }

    pub async fn api(
        &self,
        method: Method,
        path: &str,
        token: &str,
        json: Option<serde_json::Value>,
        idem: Option<&str>,
    ) -> Response {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(k) = idem {
            req = req.header("idempotency-key", k);
        }
        let body = match json {
            Some(j) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(j.to_string())
            }
            None => Body::empty(),
        };
        self.request(req.body(body).unwrap()).await
    }
}

pub struct Response {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    pub body: String,
}

impl Response {
    pub fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default()
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }
}

pub fn form(fields: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish()
}

pub fn extract(haystack: &str, pattern: &str) -> Option<String> {
    regex_lite::Regex::new(pattern)
        .unwrap()
        .captures(haystack)
        .map(|c| c[1].to_string())
}

/// A signed-in technician's browser.
pub struct Browser {
    server_state: Shared,
    pub cookie: String,
    pub csrf: String,
}

impl Browser {
    pub async fn get(&self, server: &TestServer, path: &str) -> Response {
        server
            .request(
                Request::get(path)
                    .header(header::COOKIE, &self.cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
    }

    pub async fn post(&self, server: &TestServer, path: &str, fields: &[(&str, &str)]) -> Response {
        let mut all = vec![("csrf", self.csrf.as_str())];
        all.extend_from_slice(fields);
        server
            .request(
                Request::post(path)
                    .header(header::COOKIE, &self.cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form(&all)))
                    .unwrap(),
            )
            .await
    }

    /// Create an organization; returns its id.
    pub async fn create_org(&self, server: &TestServer, name: &str) -> Uuid {
        let r = self.post(server, "/organizations", &[("name", name)]).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
        extract(&r.location(), r"/organizations/([0-9a-f-]{36})")
            .unwrap()
            .parse()
            .unwrap()
    }

    /// Create an enrollment token; returns the secret shown once.
    pub async fn enrollment_token(
        &self,
        server: &TestServer,
        org: Uuid,
        ttl_minutes: &str,
        max_uses: &str,
    ) -> String {
        let r = self
            .post(
                server,
                &format!("/organizations/{org}/enrollment-tokens"),
                &[
                    ("ttl_minutes", ttl_minutes),
                    ("max_uses", max_uses),
                    ("site", ""),
                ],
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        extract(&r.body, r"(fw8e_[A-Za-z0-9_-]{43})").expect("token shown once on the page")
    }

    /// Run a diagnostic from the device page; returns the job id.
    pub async fn run(&self, server: &TestServer, device: Uuid, fields: &[(&str, &str)]) -> Uuid {
        let r = self
            .post(server, &format!("/devices/{device}/jobs"), fields)
            .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
        extract(&r.location(), r"/jobs/([0-9a-f-]{36})")
            .unwrap()
            .parse()
            .unwrap()
    }

    pub fn state(&self) -> &Shared {
        &self.server_state
    }
}

/// An enrolled agent with its own state directory.
#[derive(Debug)]
pub struct TestAgent {
    pub dir: tempfile::TempDir,
    pub device_id: Uuid,
}

impl TestAgent {
    pub async fn enroll(server_url: &str, token: &str) -> anyhow::Result<TestAgent> {
        let dir = tempfile::tempdir()?;
        let cfg = AgentConfig {
            server_url: server_url.into(),
            ca_cert_pem: None,
            device_id: None,
            state_dir: dir.path().to_path_buf(),
        };
        let (device_id, _) = flyw8t_agent::enroll(cfg, token).await?;
        Ok(TestAgent { dir, device_id })
    }

    /// Load the agent from its state directory (as a restarted process would), pointing at `server_url`.
    pub fn load(&self, server_url: &str) -> Arc<Agent> {
        let mut cfg = AgentConfig::load(self.dir.path()).unwrap();
        cfg.server_url = server_url.into();
        cfg.save().unwrap();
        Agent::new(AgentConfig::load(self.dir.path()).unwrap()).unwrap()
    }

    /// Start one session in the background; cancel the token to disconnect.
    pub fn connect(
        &self,
        server_url: &str,
    ) -> (
        Arc<Agent>,
        CancellationToken,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let agent = self.load(server_url);
        let stop = CancellationToken::new();
        let (a, s) = (agent.clone(), stop.clone());
        let task = tokio::spawn(async move { a.run_session(&s).await });
        (agent, stop, task)
    }
}

/// An agent running on its own runtime, like a separate process: `crash` drops every task
/// at once (session, job, child process via kill-on-drop) with no orderly shutdown.
pub struct AgentProcess {
    rt: Option<tokio::runtime::Runtime>,
}

impl TestAgent {
    pub fn spawn_process(&self, server_url: &str) -> AgentProcess {
        let agent = self.load(server_url);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.spawn(async move { agent.run(CancellationToken::new()).await });
        AgentProcess { rt: Some(rt) }
    }
}

impl AgentProcess {
    pub fn crash(mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

pub async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timed out after {timeout:?} waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn wait_connected(server: &TestServer, device: Uuid) {
    let st = server.state.clone();
    wait_for("agent to connect", Duration::from_secs(15), move || {
        let st = st.clone();
        async move { st.registry.connected_since(device).is_some() }
    })
    .await;
}

pub async fn job_state(server: &TestServer, job: Uuid) -> (String, String) {
    sqlx::query_as("SELECT state, verification FROM jobs WHERE id = $1")
        .bind(job)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
}

pub async fn wait_state(server: &TestServer, job: Uuid, want: &str, timeout: Duration) {
    let db = server.state.db.clone();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let (s,): (String,) = sqlx::query_as("SELECT state FROM jobs WHERE id = $1")
            .bind(job)
            .fetch_one(&db)
            .await
            .unwrap();
        if s == want {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            let last = s;
            let events: Vec<(String, Option<String>)> = sqlx::query_as(
                "SELECT kind, to_state FROM job_events WHERE job_id = $1 ORDER BY id",
            )
            .bind(job)
            .fetch_all(&db)
            .await
            .unwrap();
            panic!("job {job} stuck in {last:?}, wanted {want:?}; events: {events:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn event_kinds(server: &TestServer, job: Uuid) -> Vec<String> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT kind FROM job_events WHERE job_id = $1 ORDER BY id")
            .bind(job)
            .fetch_all(&server.state.db)
            .await
            .unwrap();
    rows.into_iter().map(|r| r.0).collect()
}

/// Admin signs in, creates an organization and token, and an agent enrolls and connects.
pub async fn enrolled(server: &TestServer) -> (Browser, Uuid, TestAgent) {
    let admin = server.admin().await;
    let org = admin
        .create_org(server, &format!("Org {}", Uuid::new_v4().simple()))
        .await;
    let token = admin.enrollment_token(server, org, "60", "1").await;
    let agent = TestAgent::enroll(&server.url(), &token)
        .await
        .expect("enrollment");
    (admin, org, agent)
}
