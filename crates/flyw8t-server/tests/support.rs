//! Attended support (Phase B) against a real server and PostgreSQL, with two raw WebSocket
//! clients standing in for the technician's and the participant's browsers.

mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use common::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Invite {
    session: Uuid,
    code: String,
    link_token: String,
}

async fn create_invite(server: &TestServer, b: &Browser) -> Invite {
    let r = b.post(server, "/support", &[("note", "Front desk")]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let code = extract(&r.body, r#"class="code-big">(\d{3} \d{3} \d{3})<"#)
        .expect("code shown once")
        .replace(' ', "");
    let link_token = extract(&r.body, r"/s/([A-Za-z0-9_-]{43})").expect("link shown once");
    let session = extract(&r.body, r#"href="/support/([0-9a-f-]{36})""#)
        .unwrap()
        .parse()
        .unwrap();
    Invite {
        session,
        code,
        link_token,
    }
}

/// Spend a code like a browser would; returns the participant cookie (`name=value`).
async fn spend_code(server: &TestServer, code: &str) -> Result<String, StatusCode> {
    let r = server
        .request(
            Request::post("/s")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(&[("code", code)])))
                .unwrap(),
        )
        .await;
    if r.status != StatusCode::SEE_OTHER {
        return Err(r.status);
    }
    assert_eq!(r.location(), "/s/session");
    Ok(r.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string())
}

async fn ws(
    server: &TestServer,
    path: &str,
    cookie: &str,
    origin: Option<String>,
) -> Result<Ws, String> {
    let mut req = format!("ws://{}{path}", server.addr)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    if let Some(o) = origin {
        req.headers_mut().insert(header::ORIGIN, o.parse().unwrap());
    }
    tokio_tungstenite::connect_async(req)
        .await
        .map(|(w, _)| w)
        .map_err(|e| e.to_string())
}

fn origin(server: &TestServer) -> Option<String> {
    Some(format!("http://{}", server.addr))
}

async fn recv(ws: &mut Ws) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("message within 10 s")
        {
            Some(Ok(Message::Text(t))) => return serde_json::from_str(t.as_str()).unwrap(),
            Some(Ok(_)) => continue,
            other => panic!("socket ended: {other:?}"),
        }
    }
}

/// Next message whose type is `kind`, skipping others (state updates arrive often).
async fn recv_kind(ws: &mut Ws, kind: &str) -> Value {
    loop {
        let m = recv(ws).await;
        if m["type"] == kind {
            return m;
        }
    }
}

async fn until_state(ws: &mut Ws, state: &str) {
    loop {
        let m = recv(ws).await;
        if m["type"] == "state" && m["state"] == state {
            return;
        }
        assert_ne!(
            m["type"], "ended",
            "session ended while waiting for {state}: {m}"
        );
    }
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
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
async fn consented_session_relays_signaling_and_ends_cleanly() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let inv = create_invite(&server, &admin).await;
    let mut tech = ws(
        &server,
        &format!("/api/support/{}/ws", inv.session),
        &admin.cookie,
        origin(&server),
    )
    .await
    .unwrap();
    until_state(&mut tech, "waiting").await;

    // Spend the code: single use, and the link dies with it.
    let participant_cookie = spend_code(&server, &inv.code).await.unwrap();
    assert_eq!(
        spend_code(&server, &inv.code).await,
        Err(StatusCode::NOT_FOUND)
    );
    let r = server
        .request(
            Request::get(format!("/s/{}", inv.link_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "the link is spent together with the code"
    );
    until_state(&mut tech, "authorizing").await;

    // The consent page names the requester and the capability, and loads only same-origin script.
    let page = server
        .request(
            Request::get("/s/session")
                .header(header::COOKIE, &participant_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("wants to see your screen"));
    assert!(page.body.contains("cannot click, type, or control"));
    let csp = page.headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'self'") && !csp.contains("unsafe-inline"));

    let mut part = ws(
        &server,
        "/api/support/participant/ws",
        &participant_cookie,
        origin(&server),
    )
    .await
    .unwrap();
    until_state(&mut part, "authorizing").await;

    // Before consent nothing is relayed, and the technician cannot consent on their behalf.
    send(
        &mut tech,
        json!({"type": "signal", "data": {"sdp": {"type": "offer", "sdp": "x"}}}),
    )
    .await;
    assert_eq!(
        recv_kind(&mut tech, "error").await["message"],
        "not allowed before consent"
    );
    send(&mut tech, json!({"type": "approve"})).await;
    recv_kind(&mut tech, "error").await;
    assert_eq!(db_state(&server, inv.session).await, "authorizing");

    send(&mut part, json!({"type": "approve"})).await;
    until_state(&mut part, "connecting").await;
    until_state(&mut tech, "connecting").await;
    // The first thing the participant hears from the technician is post-consent signaling,
    // never the offer attempted before consent.
    send(
        &mut tech,
        json!({"type": "signal", "data": {"candidate": {"candidate": "after"}}}),
    )
    .await;
    assert_eq!(
        recv_kind(&mut part, "signal").await["data"]["candidate"]["candidate"],
        "after"
    );
    send(
        &mut part,
        json!({"type": "signal", "data": {"sdp": {"type": "offer", "sdp": "v=0"}}}),
    )
    .await;
    assert_eq!(
        recv_kind(&mut tech, "signal").await["data"]["sdp"]["type"],
        "offer"
    );

    send(&mut tech, json!({"type": "media", "state": "connected"})).await;
    until_state(&mut part, "connected").await;

    send(&mut part, json!({"type": "end"})).await;
    assert_eq!(recv_kind(&mut tech, "ended").await["state"], "closed");
    assert_eq!(db_state(&server, inv.session).await, "closed");
    type Creds = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);
    let (p, c, i): Creds = sqlx::query_as(
        "SELECT participant_hash, code_hash, invite_hash FROM support_sessions WHERE id = $1",
    )
    .bind(inv.session)
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert!(
        p.is_none() && c.is_none() && i.is_none(),
        "every credential is cleared at the end"
    );

    // The participant's browser is no longer part of anything.
    let page = server
        .request(
            Request::get("/s/session")
                .header(header::COOKIE, &participant_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    assert!(ws(
        &server,
        "/api/support/participant/ws",
        &participant_cookie,
        origin(&server)
    )
    .await
    .is_err());

    let kinds: Vec<(String,)> =
        sqlx::query_as("SELECT kind FROM support_events WHERE session_id = $1 ORDER BY id")
            .bind(inv.session)
            .fetch_all(&server.state.db)
            .await
            .unwrap();
    let kinds: Vec<String> = kinds.into_iter().map(|k| k.0).collect();
    assert_eq!(
        kinds,
        [
            "invited",
            "opened",
            "consented",
            "media_connected",
            "ended",
            "ended"
        ],
        "{kinds:?}"
    );
    let audit = admin.get(&server, "/audit").await.body;
    for a in ["support.create", "support.open", "support.end"] {
        assert!(audit.contains(a), "audit missing {a}");
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn access_control_and_cross_site_sockets() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let inv = create_invite(&server, &admin).await;

    // Cross-site or Origin-less WebSocket handshakes are refused even with a valid cookie.
    assert!(ws(
        &server,
        &format!("/api/support/{}/ws", inv.session),
        &admin.cookie,
        Some("https://evil.example".into())
    )
    .await
    .is_err());
    assert!(ws(
        &server,
        &format!("/api/support/{}/ws", inv.session),
        &admin.cookie,
        None
    )
    .await
    .is_err());

    for (email, role) in [
        ("tech2@example.test", "technician"),
        ("ro@example.test", "readonly"),
    ] {
        admin
            .post(
                &server,
                "/admin/users",
                &[
                    ("email", email),
                    ("display_name", "X"),
                    ("password", "long-enough-password"),
                    ("role", role),
                ],
            )
            .await;
    }
    let other_tech = server
        .login("tech2@example.test", "long-enough-password")
        .await;
    assert_eq!(
        other_tech
            .get(&server, &format!("/support/{}", inv.session))
            .await
            .status,
        StatusCode::NOT_FOUND,
        "another technician's session is invisible"
    );
    assert!(ws(
        &server,
        &format!("/api/support/{}/ws", inv.session),
        &other_tech.cookie,
        origin(&server)
    )
    .await
    .is_err());
    let readonly = server
        .login("ro@example.test", "long-enough-password")
        .await;
    assert_eq!(
        readonly.get(&server, "/support").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        readonly.post(&server, "/support", &[]).await.status,
        StatusCode::FORBIDDEN
    );
    // CSRF applies to creating sessions too.
    let mut forged = server
        .login("tech2@example.test", "long-enough-password")
        .await;
    forged.csrf = "nope".into();
    assert_eq!(
        forged.post(&server, "/support", &[]).await.status,
        StatusCode::FORBIDDEN
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn invitations_expire_and_guessing_is_limited() {
    let mut cfg = test_config(&fresh_database().await);
    cfg.support_invite_ttl = Duration::from_secs(1);
    let server = start(cfg).await;
    let admin = server.admin().await;
    let inv = create_invite(&server, &admin).await;
    let db = server.state.db.clone();
    let id = inv.session;
    wait_for("invitation to expire", Duration::from_secs(10), || {
        let db = db.clone();
        async move {
            sqlx::query_as::<_, (String,)>("SELECT state FROM support_sessions WHERE id = $1")
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap()
                .0
                == "expired"
        }
    })
    .await;
    assert_eq!(
        spend_code(&server, &inv.code).await,
        Err(StatusCode::NOT_FOUND)
    );

    // Ten guesses per address per ten minutes, then nothing is even looked up.
    let mut statuses = vec![];
    for n in 0..11 {
        statuses.push(
            spend_code(&server, &format!("{:09}", 100_000_000 + n))
                .await
                .unwrap_err(),
        );
    }
    assert!(
        statuses[..9].iter().all(|s| *s == StatusCode::NOT_FOUND),
        "{statuses:?}"
    );
    assert_eq!(*statuses.last().unwrap(), StatusCode::TOO_MANY_REQUESTS);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn decline_and_technician_revocation() {
    let server = start_fresh().await;
    let admin = server.admin().await;

    // The participant declines.
    let inv = create_invite(&server, &admin).await;
    let cookie = spend_code(&server, &inv.code).await.unwrap();
    let mut part = ws(
        &server,
        "/api/support/participant/ws",
        &cookie,
        origin(&server),
    )
    .await
    .unwrap();
    until_state(&mut part, "authorizing").await;
    send(&mut part, json!({"type": "decline"})).await;
    assert_eq!(recv_kind(&mut part, "ended").await["state"], "rejected");
    assert_eq!(db_state(&server, inv.session).await, "rejected");

    // The technician ends a session while the participant is still deciding.
    let inv = create_invite(&server, &admin).await;
    let cookie = spend_code(&server, &inv.code).await.unwrap();
    let mut part = ws(
        &server,
        "/api/support/participant/ws",
        &cookie,
        origin(&server),
    )
    .await
    .unwrap();
    until_state(&mut part, "authorizing").await;
    let r = admin
        .post(&server, &format!("/support/{}/end", inv.session), &[])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(recv_kind(&mut part, "ended").await["state"], "revoked");
    // An approve that arrives after revocation does nothing.
    let _ = part
        .send(Message::text(json!({"type": "approve"}).to_string()))
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(db_state(&server, inv.session).await, "revoked");

    // Leaving mid-session ends it.
    let inv = create_invite(&server, &admin).await;
    let cookie = spend_code(&server, &inv.code).await.unwrap();
    let mut tech = ws(
        &server,
        &format!("/api/support/{}/ws", inv.session),
        &admin.cookie,
        origin(&server),
    )
    .await
    .unwrap();
    let mut part = ws(
        &server,
        "/api/support/participant/ws",
        &cookie,
        origin(&server),
    )
    .await
    .unwrap();
    until_state(&mut part, "authorizing").await;
    send(&mut part, json!({"type": "approve"})).await;
    until_state(&mut tech, "connecting").await;
    drop(part);
    assert_eq!(recv_kind(&mut tech, "ended").await["state"], "closed");
    server.stop().await;
}
