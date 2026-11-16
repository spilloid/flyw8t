//! Regressions for authorization checked after a lock wait and provider proof checked on
//! the valid registration answer, rather than merely when its form was displayed.
mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use common::*;
use flyw8t_server::{auth, directory, oidc::OidcConfig};
use std::time::Duration;
use uuid::Uuid;

const ISSUER: &str = "https://identity.example.test/application/o/flyw8t/";

async fn setup() -> TestServer {
    let mut config = test_config(&fresh_database().await);
    config.oidc = Some(OidcConfig {
        issuer: ISSUER.into(),
        client_id: "test-client".into(),
        client_secret: "test-secret".into(),
    });
    start(config).await
}

async fn directory_account(server: &TestServer, subject: &str, role: &str) -> (Uuid, Uuid) {
    let mut tx = server.state.db.begin().await.unwrap();
    directory::lock_all(&mut tx).await.unwrap();
    let (org,): (Uuid,) = sqlx::query_as("INSERT INTO organizations(name) VALUES($1) RETURNING id")
        .bind(format!("Organization {subject}"))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let key = format!("group-{subject}");
    sqlx::query("INSERT INTO directory_mappings(issuer,group_key,role,organization_ids) VALUES($1,$2,$3,$4)")
        .bind(ISSUER).bind(&key).bind(role).bind(vec![org]).execute(&mut *tx).await.unwrap();
    let user = directory::ensure_identity(
        &mut tx,
        ISSUER,
        subject,
        &format!("{subject}@example.test"),
        "Directory Person",
        true,
    )
    .await
    .unwrap();
    let (group,): (Uuid,) = sqlx::query_as("INSERT INTO directory_groups(issuer,external_id,display_name) VALUES($1,$2,$2) RETURNING id")
        .bind(ISSUER).bind(key).fetch_one(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO directory_members(group_id,user_id) VALUES($1,$2)")
        .bind(group)
        .bind(user)
        .execute(&mut *tx)
        .await
        .unwrap();
    directory::refresh_scim_groups(&mut tx, &[user])
        .await
        .unwrap();
    directory::reconcile(&mut tx, user).await.unwrap();
    tx.commit().await.unwrap();
    (user, org)
}

async fn provider_browser(server: &TestServer, user: Uuid) -> Browser {
    let mut tx = server.state.db.begin().await.unwrap();
    let cookie = auth::create_session(
        &server.state,
        &mut tx,
        user,
        "127.0.0.1",
        "provider regression",
        auth::Stage::Full,
    )
    .await
    .unwrap();
    let raw = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
    sqlx::query("UPDATE sessions SET auth_method='oidc',provider_authenticated_at=clock_timestamp() WHERE token_hash=$1")
        .bind(auth::digest(raw)).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    server
        .browser(cookie.split(';').next().unwrap().to_string())
        .await
}

fn browser_hash(browser: &Browser) -> Vec<u8> {
    auth::digest(browser.cookie.split_once('=').unwrap().1)
}

fn registration_request(browser: &Browser, key: &SoftKey, challenge: &[u8]) -> Request<Body> {
    let (att, client) = key.register(challenge);
    let b64 = flyw8t_protocol::webauthn::b64url;
    Request::post("/account/passkeys")
        .header(header::COOKIE, &browser.cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form(&[
            ("csrf", &browser.csrf),
            ("name", "New regression key"),
            ("attestation_object", &b64(&att)),
            ("client_data_json", &b64(&client)),
        ])))
        .unwrap()
}

async fn keys(server: &TestServer, user: Uuid) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM webauthn_credentials WHERE user_id=$1")
        .bind(user)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

async fn until_user_lock(server: &TestServer) {
    wait_for("passkey request waiting on the user row", Duration::from_secs(10), || async {
        sqlx::query_as::<_, (bool,)>("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%SELECT totp_secret FROM users%FOR UPDATE%')")
            .fetch_one(&server.state.db).await.unwrap().0
    }).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_valid_first_key_answer_requires_provider_proof_that_is_still_recent() {
    let server = setup().await;
    let (user, _) = directory_account(&server, "first-key", "readonly").await;
    for change in [
        "provider_authenticated_at=clock_timestamp()-interval '6 minutes'",
        "provider_authenticated_at=NULL",
        "provider_authenticated_at=clock_timestamp()+interval '1 minute'",
        "auth_method='local'",
        "created_at=clock_timestamp()-interval '6 minutes'",
    ] {
        let browser = provider_browser(&server, user).await;
        let page = browser.get(&server, "/account/passkeys/new").await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let key = SoftKey::new(&server);
        let request = registration_request(&browser, &key, &ceremony_challenge(&page.body));
        // The answer is cryptographically valid for the real issued challenge. Only the
        // fresh-provider guard can reject it after the form was legitimately issued.
        sqlx::query(&format!("UPDATE sessions SET {change} WHERE token_hash=$1"))
            .bind(browser_hash(&browser))
            .execute(&server.state.db)
            .await
            .unwrap();
        let response = server.request(request).await;
        assert_ne!(
            response.status,
            StatusCode::SEE_OTHER,
            "{change}: {}",
            response.body
        );
        assert_eq!(
            keys(&server, user).await,
            0,
            "{change}: a stolen stale session registered a key"
        );
    }
    let browser = provider_browser(&server, user).await;
    let key = SoftKey::new(&server);
    assert_eq!(
        browser.add_passkey(&server, &key, &[]).await.location(),
        "/account?m=passkey-added"
    );
    assert_eq!(keys(&server, user).await, 1);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn later_key_addition_and_removal_recheck_session_and_sudo_after_waiting() {
    let server = setup().await;
    let (admin,): (Uuid,) = sqlx::query_as("SELECT id FROM users WHERE email=$1")
        .bind(ADMIN_EMAIL)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    // admin_sudo keeps its software key across fresh browser sessions.
    server.admin_sudo().await;
    for operation in ["add", "remove"] {
        for change in ["signout", "sudo expiry", "session expiry"] {
            let browser = server.admin_sudo().await;
            let request = if operation == "add" {
                let page = browser.get(&server, "/account/passkeys/new").await;
                assert_eq!(page.status, StatusCode::OK);
                registration_request(
                    &browser,
                    &SoftKey::new(&server),
                    &ceremony_challenge(&page.body),
                )
            } else {
                let (key,): (Uuid,) =
                    sqlx::query_as("SELECT id FROM webauthn_credentials WHERE user_id=$1")
                        .bind(admin)
                        .fetch_one(&server.state.db)
                        .await
                        .unwrap();
                Request::post(format!("/account/passkeys/{key}/remove"))
                    .header(header::COOKIE, &browser.cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form(&[("csrf", &browser.csrf)])))
                    .unwrap()
            };
            // Expiry happens naturally while the handler's transaction waits. Replacing
            // clock_timestamp() with transaction-frozen now() must make this regression fail.
            if change == "sudo expiry" {
                sqlx::query("UPDATE sessions SET sudo_until=clock_timestamp()+interval '3 seconds' WHERE token_hash=$1")
                    .bind(browser_hash(&browser)).execute(&server.state.db).await.unwrap();
            } else if change == "session expiry" {
                sqlx::query("UPDATE sessions SET expires_at=clock_timestamp()+interval '3 seconds' WHERE token_hash=$1")
                    .bind(browser_hash(&browser)).execute(&server.state.db).await.unwrap();
            }
            let mut held = server.state.db.begin().await.unwrap();
            sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
                .bind(admin)
                .fetch_one(&mut *held)
                .await
                .unwrap();
            let pending = server.request(request);
            let release = async {
                until_user_lock(&server).await;
                if change == "signout" {
                    sqlx::query(
                        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1",
                    )
                    .bind(browser_hash(&browser))
                    .execute(&mut *held)
                    .await
                    .unwrap();
                } else {
                    tokio::time::sleep(Duration::from_millis(3250)).await;
                }
                held.commit().await.unwrap();
            };
            let (response, ()) = tokio::join!(pending, release);
            assert_ne!(
                response.status,
                StatusCode::SEE_OTHER,
                "{operation}/{change}: {}",
                response.body
            );
            assert_eq!(
                keys(&server, admin).await,
                1,
                "{operation}/{change}: passkeys changed after authority ended"
            );
        }
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn manually_disabling_an_already_directory_disabled_user_survives_restoration() {
    let server = setup().await;
    let admin = server.admin_sudo().await;
    let (user, _) = directory_account(&server, "manually-disabled", "readonly").await;
    let mut tx = server.state.db.begin().await.unwrap();
    directory::lock_all(&mut tx).await.unwrap();
    sqlx::query("UPDATE directory_users SET active=false WHERE user_id=$1")
        .bind(user)
        .execute(&mut *tx)
        .await
        .unwrap();
    directory::reconcile(&mut tx, user).await.unwrap();
    tx.commit().await.unwrap();
    let response = admin
        .post(&server, &format!("/admin/users/{user}/disable"), &[])
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER, "{}", response.body);
    let mut tx = server.state.db.begin().await.unwrap();
    directory::lock_all(&mut tx).await.unwrap();
    sqlx::query("UPDATE directory_users SET active=true WHERE user_id=$1")
        .bind(user)
        .execute(&mut *tx)
        .await
        .unwrap();
    directory::reconcile(&mut tx, user).await.unwrap();
    let (disabled, directory_disabled): (bool,bool) = sqlx::query_as("SELECT u.disabled_at IS NOT NULL,d.directory_disabled FROM users u JOIN directory_users d ON d.user_id=u.id WHERE u.id=$1")
        .bind(user).fetch_one(&mut *tx).await.unwrap();
    assert!(
        disabled,
        "directory restoration must preserve a separate manual disable"
    );
    assert!(
        !directory_disabled,
        "the persisted reason must still be manual"
    );
    tx.commit().await.unwrap();
    let response = admin
        .post(&server, &format!("/admin/users/{user}/enable"), &[])
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER, "{}", response.body);
    let (enabled,): (bool,) = sqlx::query_as("SELECT disabled_at IS NULL FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert!(
        enabled,
        "an explicit administrator restore remains available"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_support_cleanup_database_error_still_closes_every_affected_live_socket() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;

    let server = setup().await;
    let mut users = Vec::new();
    let mut invitations = Vec::new();
    // Do the expensive invitation/password hashing before connecting either socket,
    // keeping the 15-second periodic session check outside the assertion window.
    for subject in ["support-first", "support-second"] {
        let (user, org) = directory_account(&server, subject, "technician").await;
        let browser = provider_browser(&server, user).await;
        let response = browser
            .post(
                &server,
                "/support",
                &[
                    ("organization", &org.to_string()),
                    ("capability", "view"),
                    ("note", "Cleanup failure regression"),
                ],
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        let id = extract(&response.body, r#"href="/support/([0-9a-f-]{36})""#)
            .expect("support invitation created");
        invitations.push((id, browser));
        users.push(user);
    }
    let mut sockets = Vec::new();
    for (id, browser) in invitations {
        let mut request = format!("ws://{}/api/support/{id}/ws", server.addr)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert(header::COOKIE, browser.cookie.parse().unwrap());
        request
            .headers_mut()
            .insert(header::ORIGIN, "http://localhost".parse().unwrap());
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        loop {
            let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
                .await
                .unwrap()
                .expect("initial support state")
                .unwrap();
            if let Message::Text(text) = message {
                let value: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
                if value["type"] == "state" {
                    break;
                }
            }
        }
        sockets.push(socket);
    }
    sqlx::query("UPDATE sessions SET revoked_at=clock_timestamp() WHERE user_id=ANY($1)")
        .bind(&users)
        .execute(&server.state.db)
        .await
        .unwrap();
    // The database belongs only to this test. Renaming the table makes the support
    // listing fail while the existing session-validity and live-socket paths still work.
    sqlx::query("ALTER TABLE support_sessions RENAME TO support_sessions_cleanup_fault")
        .execute(&server.state.db)
        .await
        .unwrap();
    let mut affected = vec![Uuid::new_v4()];
    affected.extend(users);
    let outcome = directory::finish_revocations(&server.state, affected).await;
    let [first, second]: [_; 2] = sockets.try_into().ok().unwrap();
    let closed = |mut socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >| async move {
        loop {
            match socket.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                _ => {}
            }
        }
    };
    let (first_closed, second_closed) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(5), closed(first)),
        tokio::time::timeout(Duration::from_secs(5), closed(second)),
    );
    sqlx::query("ALTER TABLE support_sessions_cleanup_fault RENAME TO support_sessions")
        .execute(&server.state.db)
        .await
        .unwrap();
    assert!(
        outcome.is_err(),
        "the injected listing fault must be reported"
    );
    assert!(
        first_closed.is_ok(),
        "the first affected support socket stayed open"
    );
    assert!(
        second_closed.is_ok(),
        "the later affected support socket stayed open after an earlier cleanup error"
    );
    server.stop().await;
}
