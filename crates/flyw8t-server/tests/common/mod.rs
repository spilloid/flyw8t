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
    /// The administrator's passkey, once `admin_sudo` has registered one.
    pub admin_key: std::sync::Mutex<Option<SoftKey>>,
}

pub fn test_config(database_url: &str) -> Config {
    Config {
        database_url: database_url.to_string(),
        bootstrap_admin: Some((ADMIN_EMAIL.into(), ADMIN_PASSWORD.into())),
        heartbeat_secs: 5,
        sweep_interval: Duration::from_millis(200),
        silence_grace: Duration::from_secs(1),
        // MFA has its own suite (tests/mfa.rs); the rest sign in with a password alone.
        require_mfa: false,
        // A host name, not 127.0.0.1: browsers refuse passkeys for an IP address (sudo mode needs one).
        public_url: "http://localhost".into(),
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
        admin_key: Default::default(),
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

    /// Open the sign-in page: its login CSRF cookie (`name=value`) and the token its form carries.
    pub async fn login_token(&self) -> (String, String) {
        let page = self
            .request(Request::get("/login").body(Body::empty()).unwrap())
            .await;
        let cookie = page.cookie().expect("sign-in cookie");
        let token = extract(&page.body, r#"name="login_csrf" value="([^"]+)""#)
            .expect("login token on the sign-in page");
        (cookie, token)
    }

    /// A sign-in form post, as the sign-in page would send it.
    pub async fn login_request(&self, email: &str, password: &str) -> Request<Body> {
        let (cookie, token) = self.login_token().await;
        Request::post("/login")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form(&[
                ("login_csrf", token.as_str()),
                ("email", email),
                ("password", password),
            ])))
            .unwrap()
    }

    pub async fn login(&self, email: &str, password: &str) -> Browser {
        let resp = self
            .request(self.login_request(email, password).await)
            .await;
        assert_eq!(
            resp.status,
            StatusCode::SEE_OTHER,
            "login failed: {}",
            resp.body
        );
        self.browser(resp.cookie().expect("session cookie")).await
    }

    /// A browser holding `cookie`, which must be a full session: the console must load.
    pub async fn browser(&self, cookie: String) -> Browser {
        let mut b = Browser {
            server_state: self.state.clone(),
            cookie,
            csrf: String::new(),
        };
        let home = b.get(self, "/").await;
        assert_eq!(
            home.status,
            StatusCode::OK,
            "console did not load: {}",
            home.location()
        );
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
    /// The `name=value` part of the `Set-Cookie` header, if any.
    pub fn cookie(&self) -> Option<String> {
        self.headers
            .get(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
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

    /// Start one session in the background; cancel the token to disconnect. The session task
    /// owns the agent, so once it (and any job it started) finishes, the agent's state-directory
    /// lock is released and the next `connect` can load it again, as a restarted process would.
    pub fn connect(
        &self,
        server_url: &str,
    ) -> (
        CancellationToken,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let agent = self.load(server_url);
        let stop = CancellationToken::new();
        let s = stop.clone();
        let task = tokio::spawn(async move { agent.run_session(&s).await });
        (stop, task)
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
    let admin = server.admin_sudo().await;
    let org = admin
        .create_org(server, &format!("Org {}", Uuid::new_v4().simple()))
        .await;
    let token = admin.enrollment_token(server, org, "60", "1").await;
    let agent = TestAgent::enroll(&server.url(), &token)
        .await
        .expect("enrollment");
    (admin, org, agent)
}

// ---------------------------------------------------------------------------------------
// Passkeys: a software authenticator, and sudo mode (ADR-0014)

/// A passkey in software: an ES256 key that answers WebAuthn ceremonies the way a browser and authenticator would.
pub struct SoftKey {
    pair: ring::signature::EcdsaKeyPair,
    pub id: Vec<u8>,
    pub rp_id: String,
    pub origin: String,
    /// The signature counter it reports next; 0 behaves like a synced passkey.
    pub counter: u32,
    /// Flags it sets: user present and verified, unless a test says otherwise.
    pub flags: u8,
}

fn cbor_head(major: u8, n: usize, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        _ => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
    }
}

fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len(), out);
    out.extend_from_slice(b);
}

fn cbor_text(t: &str, out: &mut Vec<u8>) {
    cbor_head(3, t.len(), out);
    out.extend_from_slice(t.as_bytes());
}

/// The options a ceremony page gives the browser (its `data-options`), as JSON.
pub fn ceremony_options(html: &str) -> serde_json::Value {
    let raw = extract(html, r#"data-options="([^"]+)""#).expect("a WebAuthn ceremony on the page");
    let json = raw
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    serde_json::from_str(&json).unwrap()
}

pub fn ceremony_challenge(html: &str) -> Vec<u8> {
    let o = ceremony_options(html);
    flyw8t_protocol::webauthn::from_b64url(o["publicKey"]["challenge"].as_str().unwrap()).unwrap()
}

impl SoftKey {
    pub fn new(server: &TestServer) -> Self {
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let (origin, rp_id) =
            flyw8t_protocol::webauthn::origin_and_rp_id(&server.state.config.public_url).unwrap();
        SoftKey {
            pair,
            id: Uuid::new_v4().as_bytes().to_vec(),
            rp_id,
            origin,
            counter: 0,
            flags: flyw8t_protocol::webauthn::FLAG_UP | flyw8t_protocol::webauthn::FLAG_UV,
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        use ring::signature::KeyPair;
        self.pair.public_key().as_ref().to_vec()
    }

    fn auth_data(&self, extra: u8) -> Vec<u8> {
        let mut d = ring::digest::digest(&ring::digest::SHA256, self.rp_id.as_bytes())
            .as_ref()
            .to_vec();
        d.push(self.flags | extra);
        d.extend(self.counter.to_be_bytes());
        d
    }

    pub fn client_data(&self, kind: &str, challenge: &[u8]) -> Vec<u8> {
        serde_json::json!({
            "type": kind,
            "challenge": flyw8t_protocol::webauthn::b64url(challenge),
            "origin": self.origin,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes()
    }

    /// `navigator.credentials.create`: the attestation object (format "none") and client data.
    pub fn register(&self, challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pk = self.public_key();
        let mut auth = self.auth_data(flyw8t_protocol::webauthn::FLAG_AT);
        auth.extend([0u8; 16]); // AAGUID
        auth.extend((self.id.len() as u16).to_be_bytes());
        auth.extend_from_slice(&self.id);
        // COSE key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        auth.extend([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]);
        cbor_bytes(&pk[1..33], &mut auth);
        auth.push(0x22);
        cbor_bytes(&pk[33..], &mut auth);
        let mut att = vec![0xa3];
        cbor_text("fmt", &mut att);
        cbor_text("none", &mut att);
        cbor_text("attStmt", &mut att);
        att.push(0xa0);
        cbor_text("authData", &mut att);
        cbor_bytes(&auth, &mut att);
        (att, self.client_data("webauthn.create", challenge))
    }

    /// `navigator.credentials.get`: authenticator data, client data and signature. Moves the counter on if it keeps one.
    pub fn assert(&mut self, challenge: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        if self.counter > 0 {
            self.counter += 1;
        }
        let auth = self.auth_data(0);
        let client = self.client_data("webauthn.get", challenge);
        let mut signed = auth.clone();
        signed.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, &client).as_ref());
        let sig = self
            .pair
            .sign(&ring::rand::SystemRandom::new(), &signed)
            .unwrap()
            .as_ref()
            .to_vec();
        (auth, client, sig)
    }
}

impl Browser {
    /// Register `key` from the account page. `fields` carries the password (and code) for a first key.
    pub async fn add_passkey(
        &self,
        server: &TestServer,
        key: &SoftKey,
        fields: &[(&str, &str)],
    ) -> Response {
        let page = self.get(server, "/account/passkeys/new").await;
        assert_eq!(
            page.status,
            StatusCode::OK,
            "{} {}",
            page.location(),
            page.body
        );
        let (att, client) = key.register(&ceremony_challenge(&page.body));
        let (att, client) = (
            flyw8t_protocol::webauthn::b64url(&att),
            flyw8t_protocol::webauthn::b64url(&client),
        );
        let mut all = vec![
            ("name", "test key"),
            ("attestation_object", att.as_str()),
            ("client_data_json", client.as_str()),
        ];
        all.extend_from_slice(fields);
        self.post(server, "/account/passkeys", &all).await
    }

    /// Answer the sudo page with `key`; returns the response to the answer.
    pub async fn confirm_sudo(
        &self,
        server: &TestServer,
        key: &mut SoftKey,
        next: &str,
    ) -> Response {
        let page = self.get(server, &format!("/sudo?next={next}")).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let (auth, client, sig) = key.assert(&ceremony_challenge(&page.body));
        let b = flyw8t_protocol::webauthn::b64url;
        self.post(
            server,
            "/sudo",
            &[
                ("next", next),
                ("credential_id", &b(&key.id)),
                ("authenticator_data", &b(&auth)),
                ("client_data_json", &b(&client)),
                ("signature", &b(&sig)),
            ],
        )
        .await
    }

    /// Add a first passkey (with `password`) and enter sudo mode with it.
    pub async fn sudo(&self, server: &TestServer, password: &str) -> SoftKey {
        let mut key = SoftKey::new(server);
        let r = self
            .add_passkey(server, &key, &[("password", password)])
            .await;
        assert_eq!(r.location(), "/account?m=passkey-added", "{}", r.body);
        let r = self.confirm_sudo(server, &mut key, "/account").await;
        assert_eq!(r.location(), "/account", "{}", r.body);
        key
    }
}

impl TestServer {
    /// The administrator, in sudo mode (for changes to field definitions, users and tokens).
    /// The first call registers the administrator's passkey; later ones (other sessions) confirm with it.
    pub async fn admin_sudo(&self) -> Browser {
        let b = self.admin().await;
        let existing = self.admin_key.lock().unwrap().take();
        let key = match existing {
            Some(mut key) => {
                let r = b.confirm_sudo(self, &mut key, "/account").await;
                assert_eq!(r.location(), "/account", "{}", r.body);
                key
            }
            None => b.sudo(self, ADMIN_PASSWORD).await,
        };
        *self.admin_key.lock().unwrap() = Some(key);
        b
    }
}
