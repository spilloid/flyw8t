//! The real helper library (`flyw8t-helper`) against a real server: pairing from the
//! downloaded file's name, the session introduction, and the helper's own consent.

mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::Engine;
use common::*;
use flyw8t_helper::{launch_from_file_name, Consent, ConsentRequest, Launch, Outcome};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Answers the consent question as a person would, and remembers what it was shown. When
/// `gate` is set, it waits for the test to release it before answering.
struct Person {
    allow: bool,
    shown: Mutex<Option<ConsentRequest>>,
    gate: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl Consent for Person {
    fn ask(&self, r: &ConsentRequest) -> bool {
        *self.shown.lock().unwrap() = Some(r.clone());
        let gate = self.gate.lock().unwrap().take();
        if let Some(gate) = gate {
            let _ = gate.recv();
        }
        self.allow
    }
}

impl Person {
    fn shown(&self) -> Option<ConsentRequest> {
        self.shown.lock().unwrap().clone()
    }
}

fn person(allow: bool) -> Arc<Person> {
    Arc::new(Person {
        allow,
        shown: Mutex::new(None),
        gate: Mutex::new(None),
    })
}

async fn ws(server: &TestServer, path: &str, cookie: &str) -> Ws {
    let mut req = format!("ws://{}{path}", server.addr)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    req.headers_mut().insert(
        header::ORIGIN,
        format!("http://{}", server.addr).parse().unwrap(),
    );
    tokio_tungstenite::connect_async(req).await.unwrap().0
}

async fn recv_kind(ws: &mut Ws, kind: &str) -> Value {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("message within 10 s");
        if let Some(Ok(Message::Text(t))) = m {
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            if v["type"] == kind {
                return v;
            }
        }
    }
}

async fn until_state(ws: &mut Ws, state: &str) {
    loop {
        let v = recv_kind(ws, "state").await;
        if v["state"] == state {
            return;
        }
    }
}

struct Ready {
    server: TestServer,
    _file: tempfile::NamedTempFile,
    session: Uuid,
    technician: Ws,
    launch: Launch,
}

/// A control session the participant allowed in the browser, and the helper they downloaded.
async fn downloaded_helper() -> Ready {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"MZ").unwrap();
    let mut cfg = test_config(&fresh_database().await);
    cfg.helper_path = Some(file.path().to_path_buf());
    let server = start(cfg).await;
    let admin = server.admin().await;
    let org = admin
        .create_org(&server, "Contoso Dental")
        .await
        .to_string();
    let r = admin
        .post(
            &server,
            "/support",
            &[("organization", org.as_str()), ("capability", "control")],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let code = extract(&r.body, r#"class="code-big">(\d{3} \d{3} \d{3})<"#)
        .unwrap()
        .replace(' ', "");
    let session: Uuid = extract(&r.body, r#"href="/support/([0-9a-f-]{36})""#)
        .unwrap()
        .parse()
        .unwrap();
    let mut technician = ws(
        &server,
        &format!("/api/support/{session}/ws"),
        &admin.cookie,
    )
    .await;
    let spent = server
        .request(
            Request::post("/s")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(&[("code", &code)])))
                .unwrap(),
        )
        .await;
    let cookie = spent.cookie().unwrap();
    let mut participant = ws(&server, "/api/support/participant/ws", &cookie).await;
    participant
        .send(Message::text(json!({"type": "approve"}).to_string()))
        .await
        .unwrap();
    until_state(&mut technician, "awaiting_helper").await;
    let file_response = server
        .request(
            Request::get("/s/helper/download")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let disposition = file_response.headers[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .to_string();
    let name = extract(&disposition, r#"filename="([^"]+)""#).unwrap();
    // The file name carries the server's configured public address. The test server's real
    // address has a random port the configuration cannot know, so the test connects there,
    // with the token the name carried.
    let segment = extract(
        &name,
        r"^flyw8t-helper-[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\.exe$",
    )
    .unwrap();
    let encoded = String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(encoded, server.state.config.public_url);
    let from_name = launch_from_file_name(&name).expect("the helper understands its own name");
    let launch = Launch {
        token: from_name.token,
        server_url: server.url(),
    };
    // Keep the participant's page connected: leaving it would end the session.
    std::mem::forget(participant);
    Ready {
        server,
        _file: file,
        session,
        technician,
        launch,
    }
}

async fn db_state(server: &TestServer, id: Uuid) -> String {
    sqlx::query_as::<_, (String,)>("SELECT state FROM support_sessions WHERE id = $1")
        .bind(id)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn the_helper_pairs_shows_who_is_asking_and_its_allow_starts_the_session() {
    let mut r = downloaded_helper().await;
    let p = person(true);
    let launch = r.launch.clone();
    let consent = p.clone();
    let helper = tokio::spawn(async move { flyw8t_helper::run(&launch, consent).await });

    until_state(&mut r.technician, "connecting").await;
    let shown = p.shown().unwrap();
    assert_eq!(shown.technician_name, "Administrator");
    assert_eq!(shown.technician_email, ADMIN_EMAIL);
    assert_eq!(shown.organization, "Contoso Dental");
    assert!(shown.control);
    assert_eq!(
        shown.server_host,
        format!("{}", r.server.addr),
        "the host the helper connected to, not one the server claims"
    );

    // The technician ends it; the helper hears why and finishes.
    r.technician
        .send(Message::text(json!({"type": "end"}).to_string()))
        .await
        .unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), helper)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        matches!(outcome, Outcome::Ended { ref state, .. } if state == "closed"),
        "{outcome:?}"
    );
    r.server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn declining_in_the_helper_ends_the_session_and_shares_nothing() {
    let mut r = downloaded_helper().await;
    let outcome = flyw8t_helper::run(&r.launch, person(false)).await.unwrap();
    assert_eq!(outcome, Outcome::Declined);
    assert_eq!(
        recv_kind(&mut r.technician, "ended").await["state"],
        "rejected"
    );
    assert_eq!(db_state(&r.server, r.session).await, "rejected");
    r.server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn an_allow_given_after_the_session_ended_does_nothing() {
    let mut r = downloaded_helper().await;
    let (release, gate) = std::sync::mpsc::channel();
    let p = Arc::new(Person {
        allow: true,
        shown: Mutex::new(None),
        gate: Mutex::new(Some(gate)),
    });
    let launch = r.launch.clone();
    let consent = p.clone();
    let helper = tokio::spawn(async move { flyw8t_helper::run(&launch, consent).await });
    // While the question is open, the technician ends the session.
    for _ in 0..100 {
        if p.shown().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(p.shown().is_some(), "the question was asked");
    r.technician
        .send(Message::text(json!({"type": "end"}).to_string()))
        .await
        .unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), helper)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(outcome, Outcome::Ended { .. }), "{outcome:?}");
    // The person clicks Allow afterwards: nothing changes.
    let _ = release.send(());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(db_state(&r.server, r.session).await, "revoked");
    r.server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_used_or_wrong_launch_token_is_refused() {
    let r = downloaded_helper().await;
    let wrong = Launch {
        token: "not-the-token".into(),
        server_url: r.server.url(),
    };
    assert!(flyw8t_helper::run(&wrong, person(true)).await.is_err());
    // The real one works once; a second run with the same token is refused.
    let launch = r.launch.clone();
    let first = tokio::spawn(async move { flyw8t_helper::run(&launch, person(true)).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(flyw8t_helper::run(&r.launch, person(true)).await.is_err());
    first.abort();
    r.server.stop().await;
}
