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
    let org = b
        .create_org(server, &format!("Org {}", Uuid::new_v4()))
        .await;
    create_invite_in(server, b, org).await
}

async fn create_invite_in(server: &TestServer, b: &Browser, org: Uuid) -> Invite {
    create_invite_with(server, b, org, "view").await
}

async fn create_invite_with(
    server: &TestServer,
    b: &Browser,
    org: Uuid,
    capability: &str,
) -> Invite {
    let org = org.to_string();
    let r = b
        .post(
            server,
            "/support",
            &[
                ("organization", org.as_str()),
                ("note", "Front desk"),
                ("capability", capability),
            ],
        )
        .await;
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
/// Spend a link: `POST /s/{token}` (a `GET` only shows a Continue button).
async fn spend_link(server: &TestServer, token: &str) -> Result<String, StatusCode> {
    let r = server
        .request(
            Request::post(format!("/s/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    if r.status != StatusCode::SEE_OTHER {
        return Err(r.status);
    }
    Ok(r.cookie().unwrap())
}

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
    assert_eq!(
        spend_link(&server, &inv.link_token).await,
        Err(StatusCode::NOT_FOUND),
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

    // Connected only once both browsers say media flows.
    send(&mut tech, json!({"type": "media", "state": "connected"})).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        db_state(&server, inv.session).await,
        "connecting",
        "one side alone cannot claim media"
    );
    send(&mut part, json!({"type": "media", "state": "connected"})).await;
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

async fn add_user(
    server: &TestServer,
    admin: &Browser,
    email: &str,
    role: &str,
    org: Option<Uuid>,
) -> Browser {
    let org = org.map(|o| o.to_string());
    let mut fields = vec![
        ("email", email),
        ("display_name", "Someone"),
        ("password", "long-enough-password"),
        ("role", role),
    ];
    if let Some(o) = &org {
        fields.push(("org", o.as_str()));
    }
    let r = admin.post(server, "/admin/users", &fields).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    server.login(email, "long-enough-password").await
}

async fn audit_rows(server: &TestServer, action: &str) -> Vec<(String, String, String)> {
    sqlx::query_as(
        "SELECT actor_type, outcome, detail::text FROM audit_events WHERE action = $1 ORDER BY id",
    )
    .bind(action)
    .fetch_all(&server.state.db)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn only_the_creator_attaches_and_sessions_are_scoped_to_organizations() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org_a = admin.create_org(&server, "Org A").await;
    let org_b = admin.create_org(&server, "Org B").await;
    let tech = add_user(
        &server,
        &admin,
        "tech@example.test",
        "technician",
        Some(org_a),
    )
    .await;

    // A technician cannot open a session in an organization they are not assigned to.
    let b = org_b.to_string();
    let r = tech
        .post(&server, "/support", &[("organization", b.as_str())])
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let inv = create_invite_in(&server, &tech, org_a).await;
    let tech_ws = format!("/api/support/{}/ws", inv.session);

    // An administrator sees the session and can end it, but cannot receive its signaling:
    // the participant consents to the technician they are shown, not to whoever attaches.
    let page = admin
        .get(&server, &format!("/support/{}", inv.session))
        .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page
        .body
        .contains("Only tech@example.test can view this session"));
    assert!(
        !page.body.contains("support.js"),
        "no signaling script for an observer"
    );
    assert!(ws(&server, &tech_ws, &admin.cookie, origin(&server))
        .await
        .is_err());
    let mut t = ws(&server, &tech_ws, &tech.cookie, origin(&server))
        .await
        .unwrap();
    until_state(&mut t, "waiting").await;

    // Losing the organization hides the session from the technician (404, not 403).
    sqlx::query("DELETE FROM user_organizations WHERE organization_id = $1")
        .bind(org_a)
        .execute(&server.state.db)
        .await
        .unwrap();
    assert_eq!(
        tech.get(&server, &format!("/support/{}", inv.session))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    let r = admin
        .post(&server, &format!("/support/{}/end", inv.session), &[])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(recv_kind(&mut t, "ended").await["state"], "revoked");
    let ends = audit_rows(&server, "support.end").await;
    assert!(
        ends.iter()
            .any(|(actor, _, d)| actor == "user" && d.contains("ended by administrator")),
        "the ending is attributed to the administrator: {ends:?}"
    );
    let attaches = audit_rows(&server, "support.attach").await;
    assert!(attaches
        .iter()
        .any(|(actor, _, d)| actor == "user" && d.contains("technician")));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn opening_a_link_spends_nothing_and_one_browser_holds_one_session() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let first = create_invite(&server, &admin).await;
    for _ in 0..3 {
        let r = server
            .request(
                Request::get(format!("/s/{}", first.link_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(
            r.headers.get(header::SET_COOKIE).is_none(),
            "a GET binds nothing"
        );
    }
    let cookie = spend_link(&server, &first.link_token).await.unwrap();

    // The same browser cannot be pulled into a second session while the first is live.
    let second = create_invite(&server, &admin).await;
    let r = server
        .request(
            Request::post(format!("/s/{}", second.link_token))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(
        db_state(&server, second.session).await,
        "waiting",
        "not spent"
    );
    assert_eq!(db_state(&server, first.session).await, "authorizing");

    // A guessed code is audited.
    assert_eq!(
        spend_code(&server, "000000001").await,
        Err(StatusCode::NOT_FOUND)
    );
    assert!(audit_rows(&server, "support.open")
        .await
        .iter()
        .any(|(_, o, d)| o == "denied" && d.contains("code")));

    // Stored codes are not a fast hash of the code.
    let (stored,): (Vec<u8>,) =
        sqlx::query_as("SELECT code_hash FROM support_sessions WHERE id = $1")
            .bind(second.session)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_ne!(stored, flyw8t_server::auth::digest(&second.code));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn sockets_check_the_scheme_and_floods_are_cut_off() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let inv = create_invite(&server, &admin).await;
    let path = format!("/api/support/{}/ws", inv.session);
    // Same host and port, different scheme: a different origin.
    let https = Some(format!("https://{}", server.addr));
    assert!(ws(&server, &path, &admin.cookie, https).await.is_err());

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
    for _ in 0..200 {
        if part.send(Message::text("{}")).await.is_err() {
            break;
        }
    }
    let mut cut_off = false;
    while let Ok(Some(Ok(m))) = tokio::time::timeout(Duration::from_secs(5), part.next()).await {
        if let Message::Text(t) = m {
            if t.as_str().contains("too many messages") {
                cut_off = true;
            }
        }
    }
    assert!(
        cut_off,
        "a flood is answered with an error and the socket closes"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn the_live_session_cap_holds_under_concurrent_creation() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Busy").await.to_string();
    let fields = [("organization", org.as_str())];
    let attempts = (0..10).map(|_| admin.post(&server, "/support", &fields));
    let statuses: Vec<StatusCode> = futures_util::future::join_all(attempts)
        .await
        .into_iter()
        .map(|r| r.status)
        .collect();
    let (live,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM support_sessions WHERE state = 'waiting'")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(live, 5, "{statuses:?}");
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::CONFLICT)
            .count(),
        5
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn resetting_a_technicians_sign_in_ends_their_live_sessions() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Org").await;
    let tech = add_user(
        &server,
        &admin,
        "tech@example.test",
        "technician",
        Some(org),
    )
    .await;
    let inv = create_invite_in(&server, &tech, org).await;
    let cookie = spend_code(&server, &inv.code).await.unwrap();
    let mut t = ws(
        &server,
        &format!("/api/support/{}/ws", inv.session),
        &tech.cookie,
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
    until_state(&mut t, "connecting").await;

    // The socket authenticated once, at its handshake; signing the technician out must
    // still cut it off.
    let (tech_id,): (Uuid,) =
        sqlx::query_as("SELECT id FROM users WHERE email = 'tech@example.test'")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    let r = admin
        .post(&server, &format!("/admin/users/{tech_id}/mfa/reset"), &[])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(recv_kind(&mut t, "ended").await["state"], "closed");
    assert_eq!(recv_kind(&mut part, "ended").await["state"], "closed");
    assert_eq!(db_state(&server, inv.session).await, "closed");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn signing_out_ends_the_sockets_that_session_opened() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let inv = create_invite(&server, &admin).await;
    let mut t = ws(
        &server,
        &format!("/api/support/{}/ws", inv.session),
        &admin.cookie,
        origin(&server),
    )
    .await
    .unwrap();
    until_state(&mut t, "waiting").await;
    // The socket authenticated once; signing that browser session out must still end it.
    let r = admin.post(&server, "/logout", &[]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(recv_kind(&mut t, "ended").await["state"], "revoked");
    assert_eq!(db_state(&server, inv.session).await, "revoked");
    let ends = audit_rows(&server, "support.end").await;
    assert!(
        ends.iter()
            .any(|(_, _, d)| d.contains("technician signed out")),
        "{ends:?}"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn disabling_an_account_ends_its_live_sockets() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Org").await;
    let tech = add_user(
        &server,
        &admin,
        "tech@example.test",
        "technician",
        Some(org),
    )
    .await;
    let inv = create_invite_in(&server, &tech, org).await;
    let mut t = ws(
        &server,
        &format!("/api/support/{}/ws", inv.session),
        &tech.cookie,
        origin(&server),
    )
    .await
    .unwrap();
    until_state(&mut t, "waiting").await;
    // The session row stays live; only the account is disabled. The socket must notice.
    let (id,): (Uuid,) = sqlx::query_as(
        "UPDATE users SET disabled_at = now() WHERE email = 'tech@example.test' RETURNING id",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    server.state.support.recheck_user(id);
    assert_eq!(recv_kind(&mut t, "ended").await["state"], "revoked");
    server.stop().await;
}

// ---------------------------------------------------------------------------------------
// Control sessions: the helper (ADR-0012)

/// The native helper's socket: a bearer launch token and no Origin, as a program sends it.
async fn helper_ws(server: &TestServer, token: &str) -> Result<Ws, String> {
    let mut req = format!("ws://{}/api/support/helper/ws", server.addr)
        .into_client_request()
        .unwrap();
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    tokio_tungstenite::connect_async(req)
        .await
        .map(|(w, _)| w)
        .map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn control_needs_the_helper_and_its_own_consent() {
    let helper_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(helper_file.path(), b"MZ test helper").unwrap();
    let mut cfg = test_config(&fresh_database().await);
    cfg.helper_path = Some(helper_file.path().to_path_buf());
    let server = start(cfg).await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Org").await;
    let inv = create_invite_with(&server, &admin, org, "control").await;
    let mut tech = ws(
        &server,
        &format!("/api/support/{}/ws", inv.session),
        &admin.cookie,
        origin(&server),
    )
    .await
    .unwrap();
    let cookie = spend_code(&server, &inv.code).await.unwrap();
    let page = server
        .request(
            Request::get("/s/session")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        page.body.contains("wants to see and control your screen"),
        "{}",
        page.body
    );
    assert!(page.body.contains(r#"data-control="1""#));
    let mut part = ws(
        &server,
        "/api/support/participant/ws",
        &cookie,
        origin(&server),
    )
    .await
    .unwrap();
    until_state(&mut part, "authorizing").await;

    // The browser's Allow does not start anything: it leads to the helper step.
    send(&mut part, json!({"type": "approve"})).await;
    let offer = recv_kind(&mut part, "helper").await;
    assert_eq!(db_state(&server, inv.session).await, "awaiting_helper");
    let download = offer["download"].as_str().unwrap().to_string();
    let token = extract(&download, r"/s/helper/flyw8t-helper-([A-Za-z0-9_-]+)\.exe").unwrap();
    until_state(&mut tech, "awaiting_helper").await;
    send(
        &mut tech,
        json!({"type": "signal", "data": {"candidate": {"candidate": "early"}}}),
    )
    .await;
    assert_eq!(
        recv_kind(&mut tech, "error").await["message"],
        "not allowed before consent"
    );

    // The download is for that browser only, and spends nothing.
    let get = |c: Option<&str>| {
        let mut r = Request::get(&download);
        if let Some(c) = c {
            r = r.header(header::COOKIE, c);
        }
        r.body(Body::empty()).unwrap()
    };
    assert_eq!(
        server.request(get(None)).await.status,
        StatusCode::NOT_FOUND
    );
    let file = server.request(get(Some(&cookie))).await;
    assert_eq!(file.status, StatusCode::OK);
    assert!(file.headers[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("flyw8t-helper-"));
    assert_eq!(file.body, "MZ test helper");

    // The launch token: wrong tokens refused, the right one works once.
    assert!(helper_ws(&server, "not-the-token").await.is_err());
    let mut helper = helper_ws(&server, &token).await.unwrap();
    assert!(
        helper_ws(&server, &token).await.is_err(),
        "a launch token works once"
    );
    until_state(&mut helper, "awaiting_helper").await;

    // Nothing flows until the helper's own Allow; the browser cannot give it.
    send(&mut part, json!({"type": "approve"})).await;
    recv_kind(&mut part, "error").await;
    assert_eq!(db_state(&server, inv.session).await, "awaiting_helper");
    send(&mut helper, json!({"type": "approve"})).await;
    until_state(&mut tech, "connecting").await;
    until_state(&mut helper, "connecting").await;

    // Signaling goes between the technician and the helper; the browser page has none.
    send(
        &mut tech,
        json!({"type": "signal", "data": {"commit": "c"}}),
    )
    .await;
    assert_eq!(
        recv_kind(&mut helper, "signal").await["data"]["commit"],
        "c"
    );
    send(
        &mut helper,
        json!({"type": "signal", "data": {"sdp": {"type": "offer", "sdp": "v=0"}}}),
    )
    .await;
    assert_eq!(
        recv_kind(&mut tech, "signal").await["data"]["sdp"]["type"],
        "offer"
    );
    send(
        &mut part,
        json!({"type": "signal", "data": {"sdp": {"type": "offer", "sdp": "x"}}}),
    )
    .await;
    assert_eq!(
        recv_kind(&mut part, "error").await["message"],
        "not allowed before consent"
    );

    // Connected needs the technician and the helper; the browser's report counts for nothing.
    send(&mut tech, json!({"type": "media", "state": "connected"})).await;
    send(&mut part, json!({"type": "media", "state": "connected"})).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(db_state(&server, inv.session).await, "connecting");
    send(&mut helper, json!({"type": "media", "state": "connected"})).await;
    until_state(&mut tech, "connected").await;

    // Ending in the helper ends it everywhere.
    send(&mut helper, json!({"type": "end"})).await;
    assert_eq!(recv_kind(&mut tech, "ended").await["state"], "closed");
    assert_eq!(recv_kind(&mut part, "ended").await["state"], "closed");
    let kinds: Vec<(String,)> =
        sqlx::query_as("SELECT kind FROM support_events WHERE session_id = $1 ORDER BY id")
            .bind(inv.session)
            .fetch_all(&server.state.db)
            .await
            .unwrap();
    let kinds: Vec<String> = kinds.into_iter().map(|k| k.0).collect();
    for k in [
        "consented",
        "helper_attached",
        "control_consented",
        "media_connected",
    ] {
        assert!(kinds.contains(&k.to_string()), "{k} missing from {kinds:?}");
    }
    for a in ["support.control.browser_consent", "support.helper.attach"] {
        assert!(
            !audit_rows(&server, a).await.is_empty(),
            "audit missing {a}"
        );
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn view_sessions_never_issue_a_helper_and_control_is_permissioned() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Org").await;
    let inv = create_invite_with(&server, &admin, org, "view").await;
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
    send(&mut part, json!({"type": "approve"})).await;
    until_state(&mut part, "connecting").await;
    let (token,): (Option<Vec<u8>>,) =
        sqlx::query_as("SELECT helper_token_hash FROM support_sessions WHERE id = $1")
            .bind(inv.session)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert!(token.is_none(), "a view session never gets a helper token");

    // Unknown capabilities are refused; read-only users can request neither.
    let o = org.to_string();
    let r = admin
        .post(
            &server,
            "/support",
            &[("organization", o.as_str()), ("capability", "run_shell")],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let ro = add_user(&server, &admin, "ro@example.test", "readonly", Some(org)).await;
    let r = ro
        .post(
            &server,
            "/support",
            &[("organization", o.as_str()), ("capability", "control")],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn helper_tokens_expire_and_unstarted_helpers_time_out() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Org").await;
    let inv = create_invite_with(&server, &admin, org, "control").await;
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
    send(&mut part, json!({"type": "approve"})).await;
    let offer = recv_kind(&mut part, "helper").await;
    let token = extract(
        offer["download"].as_str().unwrap(),
        r"flyw8t-helper-([A-Za-z0-9_-]+)\.exe",
    )
    .unwrap();

    // An expired token is refused even though the session still awaits its helper.
    sqlx::query("UPDATE support_sessions SET helper_token_expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(inv.session)
        .execute(&server.state.db)
        .await
        .unwrap();
    assert!(helper_ws(&server, &token).await.is_err());

    // A helper never started: the session expires on its own.
    sqlx::query(
        "UPDATE support_sessions SET awaiting_helper_at = now() - interval '1 hour' WHERE id = $1",
    )
    .bind(inv.session)
    .execute(&server.state.db)
    .await
    .unwrap();
    assert_eq!(recv_kind(&mut part, "ended").await["state"], "expired");
    server.stop().await;
}
