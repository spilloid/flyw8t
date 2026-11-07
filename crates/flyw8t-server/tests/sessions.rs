//! Login CSRF, the session list, and signing out elsewhere, through the real router and PostgreSQL.

mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use common::*;
use uuid::Uuid;

const TECH_EMAIL: &str = "tech@example.test";
const TECH_PASSWORD: &str = "a-technicians-password";

/// The id of the session a browser holds.
async fn session_id(server: &TestServer, b: &Browser) -> Uuid {
    let value = b.cookie.split_once('=').unwrap().1;
    sqlx::query_as::<_, (Uuid,)>("SELECT id FROM sessions WHERE token_hash = $1")
        .bind(flyw8t_server::auth::digest(value))
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

async fn signed_in(server: &TestServer, b: &Browser) -> bool {
    b.get(server, "/").await.status == StatusCode::OK
}

async fn live_sessions(server: &TestServer, email: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>(
        "SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE u.email = $1 AND s.revoked_at IS NULL AND s.expires_at > now()",
    )
    .bind(email)
    .fetch_one(&server.state.db)
    .await
    .unwrap()
    .0
}

async fn audited(server: &TestServer, action: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM audit_events WHERE action = $1")
        .bind(action)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

async fn add_technician(server: &TestServer) -> Uuid {
    let admin = server.admin_sudo().await;
    let r = admin
        .post(
            server,
            "/admin/users",
            &[
                ("email", TECH_EMAIL),
                ("display_name", "Tech"),
                ("password", TECH_PASSWORD),
                ("role", "technician"),
            ],
        )
        .await;
    assert_eq!(r.location(), "/admin?m=user-created", "{}", r.body);
    sqlx::query_as::<_, (Uuid,)>("SELECT id FROM users WHERE email = $1")
        .bind(TECH_EMAIL)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_sign_in_must_carry_the_token_its_page_set() {
    let server = start_fresh().await;
    let (cookie, token) = server.login_token().await;
    let (_, other_token) = server.login_token().await;
    let post = |cookie: Option<&str>, token: Option<&str>| {
        let mut fields = vec![("email", ADMIN_EMAIL), ("password", ADMIN_PASSWORD)];
        if let Some(t) = token {
            fields.push(("login_csrf", t));
        }
        let mut req = Request::post("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        req.body(Body::from(form(&fields))).unwrap()
    };
    let session_cookie = |r: &Response| {
        r.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("flyw8t_session="))
    };
    // A forged form (another site's page) has neither; a stale one has the wrong pair; a page
    // with its token but no cookie, or a cookie with no token, is not this browser's page.
    for (what, r) in [
        ("neither", server.request(post(None, None)).await),
        ("token only", server.request(post(None, Some(&token))).await),
        (
            "cookie only",
            server.request(post(Some(&cookie), None)).await,
        ),
        (
            "another page's token",
            server
                .request(post(Some(&cookie), Some(&other_token)))
                .await,
        ),
        (
            "an empty token",
            server.request(post(Some("flyw8t_login="), Some(""))).await,
        ),
    ] {
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{what}");
        assert!(!session_cookie(&r), "{what}: no session");
        assert!(r.body.contains("Sign in again"), "{what}");
        // The page it shows instead can be used: it sets a new token.
        assert!(r.cookie().unwrap().starts_with("flyw8t_login="), "{what}");
        assert!(r.body.contains(r#"name="login_csrf""#), "{what}");
    }
    // Refused before the password is checked: no sign-in attempt is recorded, and no rate-limit place is spent.
    assert_eq!(audited(&server, "user.login").await, 0);
    for _ in 0..30 {
        server.request(post(None, None)).await;
    }
    let ok = server.request(post(Some(&cookie), Some(&token))).await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER, "{}", ok.body);
    assert!(session_cookie(&ok));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn people_see_and_end_their_own_sessions() {
    let server = start_fresh().await;
    add_technician(&server).await;
    let here = server.admin().await;
    let there = server.admin().await;
    let third = server.admin().await;
    let tech = server.login(TECH_EMAIL, TECH_PASSWORD).await;
    let (here_id, there_id) = (
        session_id(&server, &here).await,
        session_id(&server, &there).await,
    );

    let page = here.get(&server, "/account").await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(page.body.matches("This browser").count(), 1);
    assert!(page
        .body
        .contains(&format!("/account/sessions/{there_id}/revoke")));
    assert!(page.body.contains("Sign out everywhere else"));
    // Only the person's own sessions are listed.
    let tech_id = session_id(&server, &tech).await;
    assert!(!page.body.contains(&tech_id.to_string()));

    // A sign-in that got only as far as the password is listed, and marked: it means the password is known.
    assert!(!tech
        .get(&server, "/account")
        .await
        .body
        .contains("Password only"));
    sqlx::query("UPDATE users SET totp_secret = $2, totp_enabled_at = now() WHERE email = $1")
        .bind(TECH_EMAIL)
        .bind(flyw8t_server::totp::new_secret())
        .execute(&server.state.db)
        .await
        .unwrap();
    let partial = server
        .request(server.login_request(TECH_EMAIL, TECH_PASSWORD).await)
        .await;
    assert_eq!(partial.location(), "/login/mfa");
    let listed = tech.get(&server, "/account").await.body;
    assert_eq!(listed.matches("Password only").count(), 1, "{listed}");

    // Nobody can sign out someone else's session: it is not found, and it stays signed in.
    let r = tech
        .post(
            &server,
            &format!("/account/sessions/{there_id}/revoke"),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(signed_in(&server, &there).await);
    // A post without this session's CSRF token changes nothing.
    let r = server
        .request(
            Request::post(format!("/account/sessions/{there_id}/revoke"))
                .header(header::COOKIE, &here.cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(&[("csrf", "wrong")])))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(signed_in(&server, &there).await);

    // One session, from another.
    let r = here
        .post(
            &server,
            &format!("/account/sessions/{there_id}/revoke"),
            &[],
        )
        .await;
    assert_eq!(r.location(), "/account?m=session-revoked", "{}", r.body);
    assert!(!signed_in(&server, &there).await);
    assert!(signed_in(&server, &here).await && signed_in(&server, &third).await);
    // Signed out already: a second time is not found.
    let r = here
        .post(
            &server,
            &format!("/account/sessions/{there_id}/revoke"),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Everywhere else: this browser stays, the others go, other people are untouched.
    let r = here
        .post(&server, "/account/sessions/revoke-others", &[])
        .await;
    assert_eq!(r.location(), "/account?m=sessions-revoked", "{}", r.body);
    assert!(signed_in(&server, &here).await);
    assert!(!signed_in(&server, &third).await);
    assert!(signed_in(&server, &tech).await);
    assert!(!here
        .get(&server, "/account")
        .await
        .body
        .contains("Sign out everywhere else"));

    // This browser's own row signs it out.
    let r = here
        .post(&server, &format!("/account/sessions/{here_id}/revoke"), &[])
        .await;
    assert_eq!(r.location(), "/login");
    assert!(r.cookie().unwrap().ends_with('='), "cookie cleared");
    assert!(!signed_in(&server, &here).await);

    assert_eq!(audited(&server, "user.session.revoke").await, 2);
    assert_eq!(audited(&server, "user.session.revoke_others").await, 1);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn an_administrator_signs_a_user_out_everywhere() {
    let server = start_fresh().await;
    let tech_user = add_technician(&server).await;
    let one = server.login(TECH_EMAIL, TECH_PASSWORD).await;
    let two = server.login(TECH_EMAIL, TECH_PASSWORD).await;
    // And a sign-in stopped at the second factor: it is signed out too, or it could still finish.
    sqlx::query("UPDATE users SET totp_secret = $2, totp_enabled_at = now() WHERE id = $1")
        .bind(tech_user)
        .bind(flyw8t_server::totp::new_secret())
        .execute(&server.state.db)
        .await
        .unwrap();
    let partial = server
        .request(server.login_request(TECH_EMAIL, TECH_PASSWORD).await)
        .await;
    assert_eq!(partial.location(), "/login/mfa");
    assert_eq!(live_sessions(&server, TECH_EMAIL).await, 3);
    let admin = server.admin().await;
    let url = format!("/admin/users/{tech_user}/sign-out");
    assert!(admin.get(&server, "/admin").await.body.contains(&url));

    // Only administrators may, and a technician cannot sign the administrator out.
    let admin_user: Uuid = sqlx::query_as::<_, (Uuid,)>("SELECT id FROM users WHERE email = $1")
        .bind(ADMIN_EMAIL)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0;
    let r = one
        .post(&server, &format!("/admin/users/{admin_user}/sign-out"), &[])
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(signed_in(&server, &admin).await);

    // Signing out takes access away, so it needs no sudo mode (this admin session has none).
    let r = admin.post(&server, &url, &[]).await;
    assert_eq!(r.location(), "/admin?m=user-signed-out", "{}", r.body);
    assert!(!signed_in(&server, &one).await && !signed_in(&server, &two).await);
    assert_eq!(live_sessions(&server, TECH_EMAIL).await, 0);
    assert!(
        signed_in(&server, &admin).await,
        "the administrator stays signed in"
    );
    let r = admin
        .post(
            &server,
            &format!("/admin/users/{}/sign-out", Uuid::new_v4()),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(audited(&server, "user.sessions.revoke").await, 1);

    // They can sign in again (this is not disabling the account).
    let again = server
        .request(server.login_request(TECH_EMAIL, TECH_PASSWORD).await)
        .await;
    assert_eq!(again.location(), "/login/mfa");

    // An administrator signing themselves out everywhere lands on the sign-in page.
    let r = admin
        .post(&server, &format!("/admin/users/{admin_user}/sign-out"), &[])
        .await;
    assert_eq!(r.location(), "/login");
    assert_eq!(live_sessions(&server, ADMIN_EMAIL).await, 0);
    server.stop().await;
}

#[test]
fn user_agents_are_named_briefly() {
    use flyw8t_web::browser_summary;
    let edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0";
    assert_eq!(browser_summary(edge), "Edge on Windows");
    let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1";
    assert_eq!(browser_summary(iphone), "Safari on iPhone");
    let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0";
    assert_eq!(browser_summary(firefox), "Firefox on Linux");
    assert_eq!(browser_summary(""), "Unknown browser");
    assert_eq!(browser_summary("curl/8.9"), "curl/8.9");
}

/// Start an administrator-creation request whose body arrives in two parts; between them, `meanwhile` runs. Returns
/// the response status and whether the account was created.
async fn stalled_create_user<F, Fut>(
    server: &TestServer,
    admin: &Browser,
    email: &str,
    meanwhile: F,
) -> (StatusCode, bool)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let body = form(&[
        ("csrf", admin.csrf.as_str()),
        ("email", email),
        ("display_name", "Late"),
        ("password", "a-long-enough-password"),
        ("role", "admin"),
    ]);
    let (first, rest) = body.split_at(body.len() / 2);
    let (tx, rx) = tokio::sync::mpsc::channel::<axum::body::Bytes>(2);
    // Told when the server has taken the first part. Without `whole_body` that happens in the handler, after the
    // session was checked, so what `meanwhile` changes comes strictly after that check.
    let (taken_tx, taken) = tokio::sync::oneshot::channel::<()>();
    let stream =
        futures_util::stream::unfold((rx, Some(taken_tx)), |(mut rx, mut taken)| async move {
            let b = rx.recv().await?;
            if let Some(t) = taken.take() {
                let _ = t.send(());
            }
            Some((Ok::<_, std::io::Error>(b), (rx, taken)))
        });
    let req = Request::post("/admin/users")
        .header(header::COOKIE, &admin.cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from_stream(stream))
        .unwrap();
    let pending =
        {
            let state = server.state.clone();
            tokio::spawn(async move {
                let mut req = req;
                req.extensions_mut().insert(axum::extract::ConnectInfo(
                    std::net::SocketAddr::from(([127, 0, 0, 1], 50000)),
                ));
                tower::ServiceExt::oneshot(flyw8t_server::router(state), req)
                    .await
                    .unwrap()
                    .status()
            })
        };
    tx.send(axum::body::Bytes::from(first.to_string()))
        .await
        .unwrap();
    taken.await.unwrap();
    // The server is now waiting for the rest of the body.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    meanwhile().await;
    tx.send(axum::body::Bytes::from(rest.to_string()))
        .await
        .unwrap();
    drop(tx);
    let status = pending.await.unwrap();
    let created: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)")
        .bind(email)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    (status, created)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_request_is_judged_by_the_session_as_it_is_when_the_request_is_complete() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let sudo = || async {
        sqlx::query("UPDATE sessions SET sudo_until = now() + interval '5 minutes' WHERE revoked_at IS NULL")
            .execute(&server.state.db)
            .await
            .unwrap();
    };

    // Control: in sudo mode throughout, the slow request makes its change.
    sudo().await;
    let (_, created) = stalled_create_user(&server, &admin, "slow@example.test", || async {}).await;
    assert!(created, "a slow but valid request still works");

    // Sudo mode ends while the body is still arriving: nothing is created.
    let (status, created) =
        stalled_create_user(&server, &admin, "expired@example.test", || async {
            sqlx::query("UPDATE sessions SET sudo_until = now() - interval '1 second'")
                .execute(&server.state.db)
                .await
                .unwrap();
        })
        .await;
    assert!(
        !created,
        "sudo mode that ended mid-request must not count ({status})"
    );

    // The session is signed out while the body is still arriving: nothing is created.
    sudo().await;
    let (status, created) =
        stalled_create_user(&server, &admin, "revoked@example.test", || async {
            sqlx::query("UPDATE sessions SET revoked_at = now()")
                .execute(&server.state.db)
                .await
                .unwrap();
        })
        .await;
    assert!(
        !created,
        "a session signed out mid-request must not count ({status})"
    );
    assert_eq!(status, StatusCode::SEE_OTHER, "sent to sign in");
    server.stop().await;
}

/// A POST whose body never finishes, from `ip`; returns its response once it has one.
fn stalled_post(
    server: &TestServer,
    ip: [u8; 4],
) -> (
    tokio::sync::mpsc::Sender<axum::body::Bytes>,
    tokio::task::JoinHandle<StatusCode>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel::<axum::body::Bytes>(1);
    let stream = futures_util::stream::unfold(rx, |mut rx| async {
        rx.recv().await.map(|b| (Ok::<_, std::io::Error>(b), rx))
    });
    let mut req = Request::post("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from_stream(stream))
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            ip, 50000,
        ))));
    let state = server.state.clone();
    let task = tokio::spawn(async move {
        tower::ServiceExt::oneshot(flyw8t_server::router(state), req)
            .await
            .unwrap()
            .status()
    });
    (tx, task)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn bodies_read_before_sign_in_are_bounded() {
    let server = start_fresh().await;

    // Too large for the route: refused while reading, before anything else.
    let big = "x".repeat(300 * 1024);
    let resp = server
        .request(
            Request::post("/admin/users")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("email={big}")))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);

    // One address may hold only so many unfinished bodies; others are not affected, and a slot frees when one ends.
    let held: Vec<_> = (0..flyw8t_server::BODIES_PER_ADDRESS)
        .map(|_| stalled_post(&server, [10, 0, 0, 1]))
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let (_tx, refused) = stalled_post(&server, [10, 0, 0, 1]);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), refused)
            .await
            .unwrap()
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let (other_tx, other) = stalled_post(&server, [10, 0, 0, 2]);
    drop(other_tx);
    assert_ne!(
        other.await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "another address still gets in"
    );
    let mut held = held.into_iter();
    let (first_tx, first) = held.next().unwrap();
    drop(first_tx);
    first.await.unwrap();
    let (again_tx, again) = stalled_post(&server, [10, 0, 0, 1]);
    drop(again_tx);
    assert_ne!(
        again.await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a finished body frees its slot"
    );
    drop(held);
    server.stop().await;
}
