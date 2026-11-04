//! Passkeys and sudo mode (ADR-0014 section 3) through the real router and PostgreSQL, with a software authenticator
//! (`common::SoftKey`) answering the ceremonies as a browser and security key would.

mod common;

use axum::http::StatusCode;
use common::*;
use flyw8t_protocol::webauthn::{b64url, FLAG_UP};
use flyw8t_server::config::Config;
use flyw8t_server::totp;
use uuid::Uuid;

const TECH: &str = "t@example.test";
const TECH_PASSWORD: &str = "a-long-enough-password";

/// A six-digit code that matches no step in the acceptance window.
fn wrong_code(secret: &[u8]) -> String {
    let now = totp::now_step();
    (0..1_000_000u32)
        .map(|n| format!("{n:06}"))
        .find(|c| {
            (now.saturating_sub(1)..=now + 1)
                .all(|step| totp::matching_step(secret, c, step).is_none())
        })
        .unwrap()
}

async fn audit_count(server: &TestServer, action: &str, outcome: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = $1 AND outcome = $2")
        .bind(action)
        .bind(outcome)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
}

async fn user_exists(server: &TestServer, email: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)")
        .bind(email)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
}

async fn passkeys_of(server: &TestServer, email: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM webauthn_credentials w JOIN users u ON u.id = w.user_id WHERE u.email = $1",
    )
    .bind(email)
    .fetch_one(&server.state.db)
    .await
    .unwrap()
}

async fn create_user(b: &Browser, server: &TestServer, email: &str) -> Response {
    b.post(
        server,
        "/admin/users",
        &[
            ("email", email),
            ("display_name", "New Person"),
            ("password", TECH_PASSWORD),
            ("role", "technician"),
        ],
    )
    .await
}

/// Post `key`'s answer to the sudo page's current challenge, with fields as given (for tampering).
async fn answer_sudo(
    b: &Browser,
    server: &TestServer,
    key: &SoftKey,
    auth: &[u8],
    client: &[u8],
    sig: &[u8],
) -> Response {
    b.post(
        server,
        "/sudo",
        &[
            ("next", "/admin"),
            ("credential_id", &b64url(&key.id)),
            ("authenticator_data", &b64url(auth)),
            ("client_data_json", &b64url(client)),
            ("signature", &b64url(sig)),
        ],
    )
    .await
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn guarded_changes_send_the_browser_to_confirm_and_change_nothing() {
    let server = start_fresh().await;
    let admin = server.admin().await;

    let r = create_user(&admin, &server, "a@example.test").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/sudo?next=%2Fadmin");
    assert!(!user_exists(&server, "a@example.test").await);

    let r = admin
        .post(
            &server,
            "/admin/tokens",
            &[("name", "ci"), ("scope", "read")],
        )
        .await;
    assert_eq!(r.location(), "/sudo?next=%2Fadmin");
    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM api_tokens")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(tokens, 0);

    let r = admin
        .post(
            &server,
            "/admin/fields",
            &[
                ("key", "asset_tag"),
                ("label", "Asset tag"),
                ("kind", "text"),
            ],
        )
        .await;
    assert_eq!(r.location(), "/sudo?next=%2Fadmin%2Ffields");
    let fields: i64 = sqlx::query_scalar("SELECT count(*) FROM field_definitions")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(fields, 0);

    // Without a passkey the sudo page offers to add one; it has no ceremony to answer.
    let page = admin.get(&server, "/sudo?next=/admin").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains("have not added one yet"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("data-options"));

    // With one, confirmed, the same change goes through.
    admin.sudo(&server, ADMIN_PASSWORD).await;
    // The ceremony's button is disabled until the script is ready: posted without it, the form would be empty.
    let page = admin.get(&server, "/sudo?next=/admin").await;
    assert!(
        page.body.contains(r#"<button type="submit" disabled"#),
        "{}",
        page.body
    );
    let r = create_user(&admin, &server, "a@example.test").await;
    assert_eq!(r.location(), "/admin?m=user-created", "{}", r.body);
    assert!(user_exists(&server, "a@example.test").await);
    assert_eq!(audit_count(&server, "user.sudo", "success").await, 1);
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn the_first_passkey_needs_the_password_and_the_code() {
    let server = start(Config {
        require_mfa: false,
        ..test_config(&fresh_database().await)
    })
    .await;
    let admin = server.admin().await;
    let key = SoftKey::new(&server);

    for fields in [vec![], vec![("password", "wrong-password-here")]] {
        let r = admin.add_passkey(&server, &key, &fields).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{fields:?}");
        assert!(r.body.contains("password is not right"), "{}", r.body);
    }
    assert_eq!(passkeys_of(&server, ADMIN_EMAIL).await, 0);
    assert_eq!(audit_count(&server, "user.passkey.add", "denied").await, 2);

    // A name is required and must be plain text.
    let mut all = vec![("password", ADMIN_PASSWORD)];
    let page = admin.get(&server, "/account/passkeys/new").await;
    let (att, client) = key.register(&ceremony_challenge(&page.body));
    let (att, client) = (b64url(&att), b64url(&client));
    all.extend([
        ("name", "bad\u{7}name"),
        ("attestation_object", att.as_str()),
        ("client_data_json", client.as_str()),
    ]);
    let r = admin.post(&server, "/account/passkeys", &all).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(passkeys_of(&server, ADMIN_EMAIL).await, 0);

    let r = admin
        .add_passkey(&server, &key, &[("password", ADMIN_PASSWORD)])
        .await;
    assert_eq!(r.location(), "/account?m=passkey-added", "{}", r.body);
    assert_eq!(passkeys_of(&server, ADMIN_EMAIL).await, 1);

    // A second one needs sudo mode; the password no longer suffices.
    let page = admin.get(&server, "/account/passkeys/new").await;
    assert_eq!(page.location(), "/sudo?next=%2Faccount%2Fpasskeys%2Fnew");
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn a_first_passkey_with_two_step_on_needs_the_current_code_too() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    // Two-step verification on, set directly: the MFA suite covers setting it up.
    let secret = totp::new_secret();
    sqlx::query("UPDATE users SET totp_secret = $2, totp_enabled_at = now() WHERE email = $1")
        .bind(ADMIN_EMAIL)
        .bind(&secret)
        .execute(&server.state.db)
        .await
        .unwrap();
    let page = admin.get(&server, "/account/passkeys/new").await;
    assert!(
        page.body.contains(r#"name="code""#),
        "the page asks for the code"
    );
    let key = SoftKey::new(&server);
    let wrong = wrong_code(&secret);
    for fields in [
        vec![("password", ADMIN_PASSWORD)],
        vec![("password", ADMIN_PASSWORD), ("code", wrong.as_str())],
    ] {
        let r = admin.add_passkey(&server, &key, &fields).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{fields:?}");
        assert!(r.body.contains("code is not valid"), "{}", r.body);
    }
    assert_eq!(passkeys_of(&server, ADMIN_EMAIL).await, 0);
    let code = totp::code_at(&secret, totp::now_step());
    let r = admin
        .add_passkey(
            &server,
            &key,
            &[("password", ADMIN_PASSWORD), ("code", &code)],
        )
        .await;
    assert_eq!(r.location(), "/account?m=passkey-added", "{}", r.body);
    assert_eq!(passkeys_of(&server, ADMIN_EMAIL).await, 1);
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn an_assertion_must_answer_this_challenge_once_with_this_users_key() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let mut key = admin.sudo(&server, ADMIN_PASSWORD).await;
    // End sudo mode so each case starts from outside it.
    let end = || async {
        sqlx::query("UPDATE sessions SET sudo_until = NULL")
            .execute(&server.state.db)
            .await
            .unwrap();
    };
    end().await;

    // Replaying an answer: the challenge was spent by the first post.
    let page = admin.get(&server, "/sudo?next=/admin").await;
    let (a, c, s) = key.assert(&ceremony_challenge(&page.body));
    assert_eq!(
        answer_sudo(&admin, &server, &key, &a, &c, &s)
            .await
            .location(),
        "/admin"
    );
    end().await;
    let r = answer_sudo(&admin, &server, &key, &a, &c, &s).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("expired"), "{}", r.body);

    // An answer to an older challenge, after a newer page load replaced it.
    let old = ceremony_challenge(&admin.get(&server, "/sudo?next=/admin").await.body);
    let _newer = admin.get(&server, "/sudo?next=/admin").await;
    let (a, c, s) = key.assert(&old);
    let r = answer_sudo(&admin, &server, &key, &a, &c, &s).await;
    assert!(r.body.contains("different challenge"), "{}", r.body);

    // Touched but not verified (no PIN or biometric).
    let page = admin.get(&server, "/sudo?next=/admin").await;
    key.flags = FLAG_UP;
    let (a, c, s) = key.assert(&ceremony_challenge(&page.body));
    key.flags |= flyw8t_protocol::webauthn::FLAG_UV;
    let r = answer_sudo(&admin, &server, &key, &a, &c, &s).await;
    assert!(r.body.contains("did not verify its user"), "{}", r.body);

    // Another user's key, presented as this user's.
    assert_eq!(
        admin
            .confirm_sudo(&server, &mut key, "/admin")
            .await
            .location(),
        "/admin"
    );
    assert_eq!(
        create_user(&admin, &server, TECH).await.location(),
        "/admin?m=user-created"
    );
    end().await;
    let tech = server.login(TECH, TECH_PASSWORD).await;
    let mut tech_key = tech.sudo(&server, TECH_PASSWORD).await;
    end().await;
    let page = admin.get(&server, "/sudo?next=/admin").await;
    let (a, c, s) = tech_key.assert(&ceremony_challenge(&page.body));
    let r = answer_sudo(&admin, &server, &tech_key, &a, &c, &s).await;
    assert!(r.body.contains("not one of yours"), "{}", r.body);

    // A signature by a different key over the right data.
    let page = admin.get(&server, "/sudo?next=/admin").await;
    let mut impostor = SoftKey::new(&server);
    impostor.id = key.id.clone();
    let (a, c, s) = impostor.assert(&ceremony_challenge(&page.body));
    let r = answer_sudo(&admin, &server, &key, &a, &c, &s).await;
    assert!(r.body.contains("does not verify"), "{}", r.body);

    // None of these entered sudo mode.
    let r = create_user(&admin, &server, "nobody@example.test").await;
    assert!(r.location().starts_with("/sudo"), "{}", r.location());
    assert!(audit_count(&server, "user.sudo", "denied").await >= 5);
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn a_counter_that_goes_backwards_is_refused() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let mut key = SoftKey::new(&server);
    key.counter = 10;
    let r = admin
        .add_passkey(&server, &key, &[("password", ADMIN_PASSWORD)])
        .await;
    assert_eq!(r.location(), "/account?m=passkey-added", "{}", r.body);
    assert_eq!(
        admin
            .confirm_sudo(&server, &mut key, "/admin")
            .await
            .location(),
        "/admin"
    );
    // A clone of the key, behind the original.
    key.counter = 5;
    let r = admin.confirm_sudo(&server, &mut key, "/admin").await;
    assert!(r.body.contains("counter went backwards"), "{}", r.body);
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn sudo_mode_ends_and_belongs_to_one_session() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    // Signed in elsewhere before the confirmation, and after it.
    let earlier = server.admin().await;
    let _key = admin.sudo(&server, ADMIN_PASSWORD).await;
    let r = create_user(&earlier, &server, "b@example.test").await;
    assert!(r.location().starts_with("/sudo"), "{}", r.location());
    let account = admin.get(&server, "/account").await;
    assert!(
        account.body.contains("Sudo mode"),
        "the account page shows it"
    );

    // Another session of the same person is not in sudo mode.
    let second = server.admin().await;
    let r = create_user(&second, &server, "b@example.test").await;
    assert!(r.location().starts_with("/sudo"), "{}", r.location());

    // When it lapses, the change needs a fresh confirmation.
    sqlx::query(
        "UPDATE sessions SET sudo_until = now() - interval '1 second' WHERE sudo_until IS NOT NULL",
    )
    .execute(&server.state.db)
    .await
    .unwrap();
    let r = create_user(&admin, &server, "b@example.test").await;
    assert!(r.location().starts_with("/sudo"), "{}", r.location());
    assert!(!user_exists(&server, "b@example.test").await);
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn removing_a_passkey_needs_sudo_and_a_reset_removes_them_all() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let mut admin_key = admin.sudo(&server, ADMIN_PASSWORD).await;
    assert_eq!(
        create_user(&admin, &server, TECH).await.location(),
        "/admin?m=user-created"
    );
    let tech = server.login(TECH, TECH_PASSWORD).await;
    tech.sudo(&server, TECH_PASSWORD).await;
    let (tid, kid): (Uuid, Uuid) = sqlx::query_as(
        "SELECT u.id, w.id FROM webauthn_credentials w JOIN users u ON u.id = w.user_id WHERE u.email = $1",
    )
    .bind(TECH)
    .fetch_one(&server.state.db)
    .await
    .unwrap();

    // Someone else's passkey is not found, even by an administrator in sudo mode.
    let r = admin
        .post(&server, &format!("/account/passkeys/{kid}/remove"), &[])
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Out of sudo mode, the owner is sent to confirm first.
    sqlx::query("UPDATE sessions SET sudo_until = NULL")
        .execute(&server.state.db)
        .await
        .unwrap();
    let r = tech
        .post(&server, &format!("/account/passkeys/{kid}/remove"), &[])
        .await;
    assert_eq!(r.location(), "/sudo?next=%2Faccount");
    assert_eq!(passkeys_of(&server, TECH).await, 1);

    // An administrator's reset is itself a sudo change; confirmed, it removes the passkeys and signs them out.
    let reset = format!("/admin/users/{tid}/mfa/reset");
    assert!(admin
        .post(&server, &reset, &[])
        .await
        .location()
        .starts_with("/sudo"));
    assert_eq!(passkeys_of(&server, TECH).await, 1);
    assert_eq!(
        admin
            .confirm_sudo(&server, &mut admin_key, "/admin")
            .await
            .location(),
        "/admin"
    );
    let r = admin.post(&server, &reset, &[]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert!(!r.location().starts_with("/sudo"), "{}", r.location());
    assert_eq!(passkeys_of(&server, TECH).await, 0);
    assert_eq!(passkeys_of(&server, ADMIN_EMAIL).await, 1);
    assert_eq!(
        tech.get(&server, "/account").await.status,
        StatusCode::SEE_OTHER,
        "signed out"
    );
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn a_console_reached_by_ip_address_says_why_passkeys_are_unavailable() {
    let server = start(Config {
        public_url: "http://127.0.0.1:8080".into(),
        ..test_config(&fresh_database().await)
    })
    .await;
    let admin = server.admin().await;
    let r = admin.get(&server, "/account/passkeys/new").await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.body.contains("host name"), "{}", r.body);
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn each_challenge_serves_only_its_own_ceremony_and_sudo_is_checked_when_the_key_arrives() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let mut key = admin.sudo(&server, ADMIN_PASSWORD).await;
    let end = || async {
        sqlx::query("UPDATE sessions SET sudo_until = NULL")
            .execute(&server.state.db)
            .await
            .unwrap();
    };

    // A registration challenge, signed as a sudo confirmation, does not confirm.
    let page = admin.get(&server, "/account/passkeys/new").await;
    assert_eq!(
        page.status,
        StatusCode::OK,
        "in sudo mode, a second key may be added"
    );
    let (a, c, s) = key.assert(&ceremony_challenge(&page.body));
    end().await;
    let r = answer_sudo(&admin, &server, &key, &a, &c, &s).await;
    assert!(r.body.contains("expired"), "{}", r.body);
    let r = create_user(&admin, &server, "c@example.test").await;
    assert!(r.location().starts_with("/sudo"), "{}", r.location());

    // A second key whose page was loaded in sudo mode, posted after it lapsed, is refused and not added.
    assert_eq!(
        admin
            .confirm_sudo(&server, &mut key, "/account")
            .await
            .location(),
        "/account"
    );
    let page = admin.get(&server, "/account/passkeys/new").await;
    let second = SoftKey::new(&server);
    let (att, client) = second.register(&ceremony_challenge(&page.body));
    end().await;
    let (att, client) = (b64url(&att), b64url(&client));
    let r = admin
        .post(
            &server,
            "/account/passkeys",
            &[
                ("name", "second"),
                ("attestation_object", att.as_str()),
                ("client_data_json", client.as_str()),
            ],
        )
        .await;
    assert_eq!(
        r.location(),
        "/sudo?next=%2Faccount%2Fpasskeys%2Fnew",
        "{}",
        r.body
    );
    assert_eq!(passkeys_of(&server, ADMIN_EMAIL).await, 1);
    server.stop().await;
}
