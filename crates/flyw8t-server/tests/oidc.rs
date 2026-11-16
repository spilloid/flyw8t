//! Real code/PKCE exchange against an in-process provider, and directory revocation races.
mod common;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use common::*;
use flyw8t_server::{directory, oidc::OidcConfig};
use openidconnect::core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::{JsonWebKeyId, PrivateSigningKey};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
struct Provider {
    issuer: String,
    rsa: CoreRsaPrivateSigningKey,
    ec: EcdsaKeyPair,
    expected: Mutex<(String, String)>,
    calls: std::sync::atomic::AtomicUsize,
    flows: std::sync::atomic::AtomicUsize,
    discovery_mode: Mutex<String>,
}
struct Fake {
    state: Arc<Provider>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fake {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fake {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let rng = ring::rand::SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let state = Arc::new(Provider {
            issuer,
            rsa: CoreRsaPrivateSigningKey::from_pem(
                include_str!("fixtures/oidc-test-rsa.txt"),
                Some(JsonWebKeyId::new("rsa".into())),
            )
            .unwrap(),
            ec: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), &rng)
                .unwrap(),
            expected: Mutex::new((String::new(), String::new())),
            calls: Default::default(),
            flows: Default::default(),
            discovery_mode: Default::default(),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .route("/authorize", get(authorize))
            .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { state, task }
    }
    async fn server(&self) -> TestServer {
        let mut cfg = test_config(&fresh_database().await);
        let port_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        cfg.bind = port_probe.local_addr().unwrap();
        cfg.public_url = format!("http://localhost:{}", cfg.bind.port());
        drop(port_probe);
        cfg.trusted_proxies = vec![flyw8t_server::client_ip::Cidr::parse("127.0.0.1/32").unwrap()];
        cfg.client_ip_header = "x-test-client-ip".into();
        cfg.oidc = Some(OidcConfig {
            issuer: self.state.issuer.clone(),
            client_id: "flyw8t".into(),
            client_secret: "test-client-secret".into(),
        });
        start(cfg).await
    }
    async fn flow(&self, server: &TestServer) -> (String, String) {
        let r = server
            .request(
                Request::get("/login/oidc")
                    .header(
                        "x-test-client-ip",
                        format!(
                            "127.0.0.{}",
                            self.state
                                .flows
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                                % 250
                                + 2
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
        let cookie = r.cookie().unwrap();
        assert!(r.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("SameSite=Lax"));
        let url = reqwest::Url::parse(&r.location()).unwrap();
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["max_age"], "300");
        assert!(q["scope"].split(' ').any(|s| s == "openid"));
        *self.state.expected.lock().unwrap() = (q["nonce"].clone(), q["code_challenge"].clone());
        (cookie, q["state"].clone())
    }
    async fn finish(&self, server: &TestServer, code: &str) -> common::Response {
        let (cookie, state) = self.flow(server).await;
        callback(server, &cookie, &state, code).await
    }
}
async fn authorize(
    State(p): State<Arc<Provider>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Html<String> {
    *p.expected.lock().unwrap() = (q["nonce"].clone(), q["code_challenge"].clone());
    axum::response::Html(format!(
        r#"<!doctype html><html><body><h1>Fake provider</h1><a id="provider-continue" href="{}?state={}&amp;code=valid">Complete provider sign-in</a></body></html>"#,
        q["redirect_uri"], q["state"]
    ))
}
async fn discovery(State(p): State<Arc<Provider>>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mode = p.discovery_mode.lock().unwrap().clone();
    if mode == "redirect" {
        return (
            StatusCode::FOUND,
            [(header::LOCATION, format!("{}/jwks", p.issuer))],
        )
            .into_response();
    }
    if mode == "slow" {
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
    if mode == "oversize_chunked" {
        return axum::response::Response::new(Body::from_stream(futures_util::stream::iter(
            (0..1100).map(|_| Ok::<_, std::io::Error>(vec![b'x'; 1024])),
        )));
    }
    if mode == "oversize" {
        return "x".repeat(1024 * 1024 + 1).into_response();
    }
    let token = if mode == "foreign_endpoint" {
        "https://foreign.example/token".into()
    } else {
        format!("{}/token", p.issuer)
    };
    Json(json!({"issuer":p.issuer,"authorization_endpoint":format!("{}/authorize",p.issuer),"token_endpoint":token,"jwks_uri":format!("{}/jwks",p.issuer),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256","ES256"],"token_endpoint_auth_methods_supported":["client_secret_basic"],"code_challenge_methods_supported":["S256"]})).into_response()
}
async fn jwks(State(p): State<Arc<Provider>>) -> Json<Value> {
    let public = p.ec.public_key().as_ref();
    Json(
        json!({"keys":[p.rsa.as_verification_key(),{"kty":"EC","crv":"P-256","x":b64(&public[1..33]),"y":b64(&public[33..65]),"kid":"ec","use":"sig","alg":"ES256"}]}),
    )
}
async fn token(
    State(p): State<Arc<Provider>>,
    headers: axum::http::HeaderMap,
    axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    p.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let expected = p.expected.lock().unwrap().clone();
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    let challenge = b64(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
    if challenge != expected.1
        || form.get("grant_type").map(String::as_str) != Some("authorization_code")
        || headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            != Some("Basic Zmx5dzh0OnRlc3QtY2xpZW50LXNlY3JldA==")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant"})),
        );
    }
    let mode = form.get("code").map(String::as_str).unwrap_or("");
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut claims = json!({"iss":p.issuer,"sub":"immutable-subject","aud":"flyw8t","exp":now+300,"iat":now,"auth_time":now,"nonce":expected.0,"email":"directory@example.test","email_verified":true,"name":"Directory Person","groups":["operators"]});
    match mode {
        "nonce" => claims["nonce"] = json!("different"),
        "issuer" => claims["iss"] = json!("https://wrong.example/"),
        "audience" => claims["aud"] = json!("wrong"),
        "expired" => claims["exp"] = json!(now - 60),
        "future" => claims["iat"] = json!(now + 3600),
        "azp" => claims["azp"] = json!("other-client"),
        "hash" => claims["at_hash"] = json!("invalid"),
        "stale_auth" => claims["auth_time"] = json!(now - 600),
        "future_auth" => claims["auth_time"] = json!(now + 3600),
        "no_auth" => {
            claims.as_object_mut().unwrap().remove("auth_time");
        }
        "no_groups" => claims["groups"] = json!([]),
        "bad_groups" => claims["groups"] = json!("operators"),
        "local_collision" => claims["email"] = json!(ADMIN_EMAIL),
        "renamed" => claims["email"] = json!("renamed@example.test"),
        _ => {}
    }
    let alg = match mode {
        "es256" => "ES256",
        "none" => "none",
        "hs256" => "HS256",
        _ => "RS256",
    };
    let header = json!({"alg":alg,"kid":if alg=="ES256"{"ec"}else{"rsa"}});
    let message = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let signature = if alg == "none" {
        Vec::new()
    } else if alg == "HS256" {
        ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test-client-secret"),
            message.as_bytes(),
        )
        .as_ref()
        .to_vec()
    } else if alg == "ES256" {
        p.ec.sign(&ring::rand::SystemRandom::new(), message.as_bytes())
            .unwrap()
            .as_ref()
            .to_vec()
    } else {
        p.rsa
            .sign(
                &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                message.as_bytes(),
            )
            .unwrap()
    };
    let signature = if mode == "signature" {
        vec![0; 256]
    } else {
        signature
    };
    (
        StatusCode::OK,
        Json(
            json!({"access_token":"provider-access-token","token_type":"Bearer","id_token":format!("{message}.{}",b64(&signature))}),
        ),
    )
}
async fn callback(server: &TestServer, cookie: &str, state: &str, code: &str) -> common::Response {
    server
        .request(
            Request::get(format!("/login/oidc/callback?state={state}&code={code}"))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
}
async fn mapping(server: &TestServer, issuer: &str, role: &str) -> Uuid {
    let admin = server.admin_sudo().await;
    let org = admin.create_org(server, "Directory organization").await;
    let r = admin
        .post(
            server,
            "/admin/directory/mappings",
            &[
                ("group_key", "operators"),
                ("role", role),
                ("org", &org.to_string()),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{issuer}: {}", r.body);
    org
}
async fn directory_id(server: &TestServer) -> Uuid {
    sqlx::query_as::<_, (Uuid,)>("SELECT user_id FROM directory_users")
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn oidc_validates_rs256_and_es256_and_keeps_identity_stable_without_local_linking() {
    let fake = Fake::start().await;
    let server = fake.server().await;
    mapping(&server, &fake.state.issuer, "technician").await;
    let r = fake.finish(&server, "valid").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let browser = server.browser(r.cookie().unwrap()).await;
    let first = directory_id(&server).await;
    let stage: (String, String, Option<time::OffsetDateTime>) =
        sqlx::query_as("SELECT stage,auth_method,sudo_until FROM sessions WHERE user_id=$1")
            .bind(first)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(stage, ("full".into(), "oidc".into(), None));
    assert!(browser
        .get(&server, "/account")
        .await
        .body
        .contains("managed by your organization"));
    assert_eq!(fake.finish(&server, "es256").await.status, StatusCode::OK);
    assert_eq!(fake.finish(&server, "renamed").await.status, StatusCode::OK);
    assert_eq!(first, directory_id(&server).await);
    assert_eq!(
        fake.finish(&server, "local_collision").await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        server
            .request(
                server
                    .login_request("renamed@example.test", "anything")
                    .await
            )
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server.admin().await.get(&server, "/").await.status,
        StatusCode::OK
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn invalid_tokens_and_browser_state_never_create_a_session() {
    let fake = Fake::start().await;
    let server = fake.server().await;
    mapping(&server, &fake.state.issuer, "readonly").await;
    for mode in [
        "nonce",
        "issuer",
        "audience",
        "expired",
        "future",
        "azp",
        "hash",
        "bad_groups",
        "none",
        "hs256",
        "signature",
    ] {
        let r = fake.finish(&server, mode).await;
        assert!(
            matches!(
                r.status,
                StatusCode::UNAUTHORIZED | StatusCode::UNPROCESSABLE_ENTITY
            ),
            "{mode} returned {}: {}",
            r.status,
            r.body
        );
        assert!(r.cookie().is_none(), "{mode} set a session cookie");
        assert_eq!(r.headers[header::REFERRER_POLICY], "no-referrer");
    }
    assert_eq!(
        sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM directory_users")
            .fetch_one(&server.state.db)
            .await
            .unwrap()
            .0,
        0
    );
    let (cookie, state) = fake.flow(&server).await;
    let before = fake.state.calls.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        callback(&server, "flyw8t_oidc=wrong", &state, "valid")
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        callback(&server, &cookie, "wrong", "valid").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fake.state.calls.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
    let first = callback(&server, &cookie, &state, "valid").await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(
        callback(&server, &cookie, &state, "valid").await.status,
        StatusCode::UNAUTHORIZED
    );
    for mode in [
        "redirect",
        "oversize",
        "oversize_chunked",
        "foreign_endpoint",
    ] {
        *fake.state.discovery_mode.lock().unwrap() = mode.into();
        let r = server
            .request(Request::get("/login/oidc").body(Body::empty()).unwrap())
            .await;
        assert_ne!(r.status, StatusCode::SEE_OTHER, "{mode} allowed");
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn only_recent_provider_authentication_bootstraps_a_directory_sudo_key() {
    let fake = Fake::start().await;
    let server = fake.server().await;
    mapping(&server, &fake.state.issuer, "admin").await;
    for mode in ["stale_auth", "future_auth", "no_auth"] {
        let r = fake.finish(&server, mode).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let browser = server.browser(r.cookie().unwrap()).await;
        assert_eq!(
            browser.get(&server, "/account/passkeys/new").await.status,
            StatusCode::CONFLICT,
            "{mode}"
        );
        let key = SoftKey::new(&server);
        let (att, client) = key.register(&[0; 32]);
        let r = browser
            .post(
                &server,
                "/account/passkeys",
                &[
                    ("name", "stolen"),
                    ("attestation_object", &b64(&att)),
                    ("client_data_json", &b64(&client)),
                ],
            )
            .await;
        assert_ne!(
            r.status,
            StatusCode::SEE_OTHER,
            "{mode} registration allowed"
        );
    }
    let r = fake.finish(&server, "valid").await;
    let browser = server.browser(r.cookie().unwrap()).await;
    let mut key = SoftKey::new(&server);
    let r = browser.add_passkey(&server, &key, &[]).await;
    assert_eq!(r.location(), "/account?m=passkey-added", "{}", r.body);
    assert!(browser.get(&server, "/sudo").await.body.contains("Confirm"));
    let r = browser
        .post(
            &server,
            "/admin/directory/mappings",
            &[("group_key", "unauthorized"), ("role", "admin")],
        )
        .await;
    assert!(r.location().starts_with("/sudo"));
    assert_eq!(
        browser
            .confirm_sudo(&server, &mut key, "/admin/directory")
            .await
            .location(),
        "/admin/directory"
    );
    let id = directory_id(&server).await;
    sqlx::query("UPDATE directory_users SET active=false WHERE user_id=$1")
        .bind(id)
        .execute(&server.state.db)
        .await
        .unwrap();
    let mut tx = server.state.db.begin().await.unwrap();
    directory::lock_all(&mut tx).await.unwrap();
    assert!(directory::reconcile(&mut tx, id).await.unwrap());
    tx.commit().await.unwrap();
    directory::finish_revocations(&server.state, vec![id])
        .await
        .unwrap();
    assert_eq!(
        browser.get(&server, "/").await.status,
        StatusCode::SEE_OTHER
    );
    // Retained local key must not become an IdP bypass, even if provisioning later restores the account.
    sqlx::query("UPDATE directory_users SET active=true WHERE user_id=$1")
        .bind(id)
        .execute(&server.state.db)
        .await
        .unwrap();
    let mut tx = server.state.db.begin().await.unwrap();
    directory::lock_all(&mut tx).await.unwrap();
    directory::reconcile(&mut tx, id).await.unwrap();
    tx.commit().await.unwrap();
    let login = server
        .request(Request::get("/login/passkey").body(Body::empty()).unwrap())
        .await;
    let cookie = login.cookie().unwrap();
    let csrf = extract(&login.body, r#"name="csrf" value="([^"]+)""#).unwrap();
    let challenge = ceremony_challenge(&login.body);
    let (auth, client, sig) = key.assert(&challenge);
    let response = server
        .request(
            Request::post("/login/passkey")
                .header(header::COOKIE, cookie)
                .body(Body::from(form(&[
                    ("csrf", &csrf),
                    ("credential_id", &b64(&key.id)),
                    ("authenticator_data", &b64(&auth)),
                    ("client_data_json", &b64(&client)),
                    ("signature", &b64(&sig)),
                ])))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn mapping_loss_and_manual_disable_are_authoritative_at_later_sign_in() {
    let fake = Fake::start().await;
    let server = fake.server().await;
    mapping(&server, &fake.state.issuer, "technician").await;
    let r = fake.finish(&server, "valid").await;
    let browser = server.browser(r.cookie().unwrap()).await;
    let id = directory_id(&server).await;
    assert_eq!(
        fake.finish(&server, "no_groups").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        browser.get(&server, "/").await.status,
        StatusCode::SEE_OTHER
    );
    let admin = server.admin_sudo().await;
    assert_eq!(
        admin
            .post(&server, &format!("/admin/users/{id}/disable"), &[])
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        fake.finish(&server, "valid").await.status,
        StatusCode::UNAUTHORIZED,
        "manual disable cannot be restored by directory"
    );
    assert_eq!(
        admin
            .post(&server, &format!("/admin/users/{id}/enable"), &[])
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(fake.finish(&server, "valid").await.status, StatusCode::OK);
    sqlx::query("UPDATE directory_users SET managed=true,groups='{}' WHERE user_id=$1")
        .bind(id)
        .execute(&server.state.db)
        .await
        .unwrap();
    assert_eq!(
        fake.finish(&server, "valid").await.status,
        StatusCode::UNAUTHORIZED,
        "OIDC must not overwrite SCIM memberships"
    );
    sqlx::query("UPDATE directory_users SET managed=true,active=false WHERE user_id=$1")
        .bind(id)
        .execute(&server.state.db)
        .await
        .unwrap();
    assert_eq!(
        fake.finish(&server, "valid").await.status,
        StatusCode::UNAUTHORIZED,
        "OIDC must not restore SCIM active=false"
    );
    server.stop().await;
}

use futures_util::{SinkExt, StreamExt};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
struct Cdp {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next: u64,
    errors: Vec<String>,
}

impl Cdp {
    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        self.ws
            .send(Message::text(
                json!({"id": id, "method": method, "params": params}).to_string(),
            ))
            .await
            .unwrap();
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(20), self.ws.next())
                .await
                .expect("CDP timeout")
                .unwrap()
                .unwrap();
            let v: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
            match v["method"].as_str() {
                Some("Runtime.exceptionThrown") => self
                    .errors
                    .push(v["params"]["exceptionDetails"].to_string()),
                Some("Runtime.consoleAPICalled") if v["params"]["type"] == "error" => {
                    self.errors.push(v["params"]["args"].to_string())
                }
                Some("Log.entryAdded") if v["params"]["entry"]["level"] == "error" => {
                    self.errors.push(v["params"]["entry"]["text"].to_string())
                }
                _ => {}
            }
            if v["id"] == id {
                return v["result"].clone();
            }
        }
    }

    async fn eval(&mut self, expr: &str) -> Value {
        self.call(
            "Runtime.evaluate",
            json!({"expression": expr, "returnByValue": true, "awaitPromise": true}),
        )
        .await["result"]["value"]
            .clone()
    }
}

async fn http_json(port: u16, path: &str) -> Value {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    text.split_once("\r\n\r\n")
        .and_then(|(_, b)| serde_json::from_str(b).ok())
        .unwrap_or(Value::Null)
}

fn find_chrome() -> PathBuf {
    let candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ];
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("Google Chrome")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL and Google Chrome"]
async fn a_cross_site_browser_sign_in_commits_strict_cookie_and_directory_pages_fit() {
    let fake = Fake::start().await;
    let server = fake.server().await;
    mapping(&server, &fake.state.issuer, "admin").await;
    let profile = tempfile::tempdir().unwrap();
    let mut chrome = tokio::process::Command::new(find_chrome())
        .arg("--headless=new")
        .arg("--remote-debugging-port=0")
        .arg("--hide-scrollbars")
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("about:blank")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut port = None;
    for _ in 0..100 {
        if let Ok(text) = std::fs::read_to_string(profile.path().join("DevToolsActivePort")) {
            port = text.lines().next().and_then(|p| p.parse::<u16>().ok());
            if port.is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let port = port.expect("Chrome debugging port");
    let tabs = http_json(port, "/json/list").await;
    let url = tabs
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["type"] == "page")
        .unwrap()["webSocketDebuggerUrl"]
        .as_str()
        .unwrap();
    let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let mut cdp = Cdp {
        ws,
        next: 0,
        errors: Vec::new(),
    };
    for command in [
        "Runtime.enable",
        "Log.enable",
        "Page.enable",
        "Network.enable",
    ] {
        cdp.call(command, json!({})).await;
    }
    let base = &server.state.config.public_url;
    // localhost console and 127.0.0.1 provider are different sites, not merely different ports.
    cdp.call("Page.navigate", json!({"url":format!("{base}/login/oidc")}))
        .await;
    browser_wait(
        &mut cdp,
        "document.querySelector('#provider-continue') !== null",
    )
    .await;
    assert_eq!(cdp.eval("location.hostname").await, "127.0.0.1");
    cdp.eval("document.querySelector('#provider-continue').click(); true")
        .await;
    browser_wait(
        &mut cdp,
        "document.body.innerText.includes('Sign-in complete')",
    )
    .await;
    assert_eq!(cdp.eval("location.hostname").await, "localhost");
    cdp.eval("document.querySelector('a[href=\"/\"]').click(); true")
        .await;
    browser_wait(
        &mut cdp,
        "document.body.innerText.includes('Directory Person') && location.pathname === '/'",
    )
    .await;
    assert_eq!(cdp.eval("document.referrer").await, "");
    // Inspect new pages at every supported width/theme; screenshots stay in ignored target/.
    let output =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ui-capture-directory");
    std::fs::create_dir_all(&output).unwrap();
    let pages = [
        ("/admin/directory", "directory"),
        ("/account", "directory-account"),
        ("/account/passkeys/new", "directory-passkey"),
    ];
    for (path, name) in pages {
        for (width, height, size) in [
            (1280, 860, "desktop"),
            (820, 1100, "tablet"),
            (390, 844, "phone"),
        ] {
            for theme in ["light", "dark"] {
                cdp.call(
                    "Emulation.setDeviceMetricsOverride",
                    json!({"width":width,"height":height,"deviceScaleFactor":1,"mobile":width<600}),
                )
                .await;
                cdp.call(
                    "Emulation.setEmulatedMedia",
                    json!({"features":[{"name":"prefers-color-scheme","value":theme}]}),
                )
                .await;
                cdp.call("Page.navigate", json!({"url":format!("{base}{path}")}))
                    .await;
                browser_wait(&mut cdp, "document.readyState === 'complete'").await;
                assert_eq!(
                    cdp.eval("document.documentElement.scrollWidth > innerWidth")
                        .await,
                    false,
                    "{name} {size} {theme}"
                );
                let png = cdp
                    .call("Page.captureScreenshot", json!({"format":"png"}))
                    .await;
                std::fs::write(
                    output.join(format!("{name}-{size}-{theme}.png")),
                    base64::engine::general_purpose::STANDARD
                        .decode(png["data"].as_str().unwrap())
                        .unwrap(),
                )
                .unwrap();
            }
        }
    }
    // The test user proves a local passkey, then rotates the actual UI credential. Capture
    // the one-time response without navigating away (the next GET must not reveal it).
    let cookies = cdp.call("Network.getCookies", json!({"urls":[base]})).await;
    let session = cookies["cookies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "flyw8t_session")
        .unwrap();
    let browser = server
        .browser(format!(
            "flyw8t_session={}",
            session["value"].as_str().unwrap()
        ))
        .await;
    let mut local_key = SoftKey::new(&server);
    assert_eq!(
        browser
            .add_passkey(&server, &local_key, &[])
            .await
            .location(),
        "/account?m=passkey-added"
    );
    assert_eq!(
        browser
            .confirm_sudo(&server, &mut local_key, "/admin/directory")
            .await
            .location(),
        "/admin/directory"
    );
    cdp.call(
        "Page.navigate",
        json!({"url":format!("{base}/admin/directory")}),
    )
    .await;
    browser_wait(
        &mut cdp,
        "document.querySelector('form[action=\"/admin/directory/credentials\"]') !== null",
    )
    .await;
    cdp.eval(
        "document.querySelector('form[action=\"/admin/directory/credentials\"]').submit(); true",
    )
    .await;
    browser_wait(
        &mut cdp,
        "document.body.innerText.includes('SCIM credential: copy now')",
    )
    .await;
    for (width, height, size) in [
        (1280, 860, "desktop"),
        (820, 1100, "tablet"),
        (390, 844, "phone"),
    ] {
        for theme in ["light", "dark"] {
            cdp.call(
                "Emulation.setDeviceMetricsOverride",
                json!({"width":width,"height":height,"deviceScaleFactor":1,"mobile":width<600}),
            )
            .await;
            cdp.call(
                "Emulation.setEmulatedMedia",
                json!({"features":[{"name":"prefers-color-scheme","value":theme}]}),
            )
            .await;
            assert_eq!(
                cdp.eval("document.documentElement.scrollWidth > innerWidth")
                    .await,
                false,
                "credential {size} {theme}"
            );
            let png = cdp
                .call("Page.captureScreenshot", json!({"format":"png"}))
                .await;
            std::fs::write(
                output.join(format!("directory-credential-{size}-{theme}.png")),
                base64::engine::general_purpose::STANDARD
                    .decode(png["data"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
        }
    }
    cdp.call(
        "Page.navigate",
        json!({"url":format!("{base}/admin/directory")}),
    )
    .await;
    browser_wait(&mut cdp, "document.readyState === 'complete'").await;
    assert_eq!(
        cdp.eval("document.body.innerText.includes('SCIM credential: copy now')")
            .await,
        false
    );
    assert!(cdp.errors.is_empty(), "{:?}", cdp.errors);
    let _ = chrome.kill().await;
    server.stop().await;
}
async fn browser_wait(cdp: &mut Cdp, expression: &str) {
    for _ in 0..100 {
        if cdp.eval(expression).await == true {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "Browser never reached {expression}: {}",
        cdp.eval("document.body.innerText").await
    );
}
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_sign_in_waiting_for_sync_cannot_restore_removed_memberships_or_deprovisioning() {
    let fake = Fake::start().await;
    let server = fake.server().await;
    mapping(&server, &fake.state.issuer, "admin").await;
    assert_eq!(fake.finish(&server, "valid").await.status, StatusCode::OK);
    let id = directory_id(&server).await;
    for deprovision in [false, true] {
        sqlx::query("UPDATE directory_users SET managed=true,active=true,groups=ARRAY['operators'] WHERE user_id=$1").bind(id).execute(&server.state.db).await.unwrap();
        let mut held = server.state.db.begin().await.unwrap();
        directory::lock_all(&mut held).await.unwrap();
        let (cookie, state) = fake.flow(&server).await;
        let pending = callback(&server, &cookie, &state, "valid");
        let sync = async {
            wait_for("OIDC callback waiting for directory synchronization",Duration::from_secs(10),||async {
                sqlx::query_as::<_,(bool,)>("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock%')").fetch_one(&server.state.db).await.unwrap().0
            }).await;
            sqlx::query("UPDATE directory_users SET groups='{}',active=$2 WHERE user_id=$1")
                .bind(id)
                .bind(!deprovision)
                .execute(&mut *held)
                .await
                .unwrap();
            directory::reconcile(&mut held, id).await.unwrap();
            held.commit().await.unwrap();
        };
        let (response, ()) = tokio::join!(pending, sync);
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "deprovision={deprovision}: {}",
            response.body
        );
        let (groups, active): (Vec<String>, bool) =
            sqlx::query_as("SELECT groups,active FROM directory_users WHERE user_id=$1")
                .bind(id)
                .fetch_one(&server.state.db)
                .await
                .unwrap();
        assert!(groups.is_empty());
        assert_eq!(active, !deprovision);
    }
    server.stop().await;
}
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn oidc_transport_enforces_a_total_request_deadline() {
    let fake = Fake::start().await;
    let server = fake.server().await;
    *fake.state.discovery_mode.lock().unwrap() = "slow".into();
    let start = std::time::Instant::now();
    let response = server
        .request(Request::get("/login/oidc").body(Body::empty()).unwrap())
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "provider exceeded transport's10second total deadline"
    );
    server.stop().await;
}
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn directory_sign_in_cannot_claim_the_empty_instance_before_local_bootstrap() {
    let fake = Fake::start().await;
    let mut config = test_config(&fresh_database().await);
    config.bootstrap_admin = None;
    config.oidc = Some(OidcConfig {
        issuer: fake.state.issuer.clone(),
        client_id: "flyw8t".into(),
        client_secret: "test-client-secret".into(),
    });
    let server = start(config.clone()).await;
    assert_eq!(
        fake.finish(&server, "valid").await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM users")
            .fetch_one(&server.state.db)
            .await
            .unwrap()
            .0,
        0
    );
    server.stop().await;
    config.bootstrap_admin = Some((ADMIN_EMAIL.into(), ADMIN_PASSWORD.into()));
    let server = start(config).await;
    assert_eq!(
        server.admin().await.get(&server, "/").await.status,
        StatusCode::OK
    );
    server.stop().await;
}
