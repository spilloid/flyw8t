//! Managing users after they exist: name, role and organizations; disabling and enabling; temporary passwords; and
//! a person changing their own password. Every administrator change needs sudo mode, and the console can never be
//! left with no administrator who can sign in.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

const PASSWORD: &str = "first-password-123";

async fn make_user(
    server: &TestServer,
    admin: &Browser,
    email: &str,
    role: &str,
    org: Option<Uuid>,
) -> Uuid {
    let org = org.map(|o| o.to_string()).unwrap_or_default();
    let mut fields = vec![
        ("email", email),
        ("display_name", "Pat Example"),
        ("password", PASSWORD),
        ("role", role),
    ];
    if !org.is_empty() {
        fields.push(("org", &org));
    }
    let r = admin.post(server, "/admin/users", &fields).await;
    assert_eq!(r.location(), "/admin?m=user-created", "{}", r.body);
    user_id(server, email).await
}

async fn user_id(server: &TestServer, email: &str) -> Uuid {
    sqlx::query_as::<_, (Uuid,)>("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

/// The newest audit event for `action`: its outcome and detail.
async fn last_audit(server: &TestServer, action: &str) -> (String, Value) {
    sqlx::query_as::<_, (String, Value)>(
        "SELECT outcome, detail FROM audit_events WHERE action = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(action)
    .fetch_one(&server.state.db)
    .await
    .unwrap_or_else(|e| panic!("no {action} event: {e}"))
}

async fn disabled(server: &TestServer, id: Uuid) -> bool {
    sqlx::query_as::<_, (bool,)>("SELECT disabled_at IS NOT NULL FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

/// Whether a sign-in with this password is accepted.
async fn can_sign_in(server: &TestServer, email: &str, password: &str) -> bool {
    let r = server
        .request(server.login_request(email, password).await)
        .await;
    r.status == StatusCode::SEE_OTHER
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_change_to_a_users_role_or_organizations_applies_to_their_next_page() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin.create_org(&server, "Acme").await;
    let bolt = admin.create_org(&server, "Bolt").await;
    let id = make_user(&server, &admin, "pat@example.com", "technician", Some(acme)).await;
    let pat = server.login("pat@example.com", PASSWORD).await;
    let sees = |org: Uuid| {
        let (pat, server) = (&pat, &server);
        async move {
            pat.get(server, &format!("/organizations/{org}"))
                .await
                .status
        }
    };
    assert_eq!(sees(acme).await, StatusCode::OK);
    assert_eq!(sees(bolt).await, StatusCode::NOT_FOUND);

    // The user's page shows what they hold, and offers the change.
    let page = admin.get(&server, &format!("/admin/users/{id}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("pat@example.com"));
    assert!(
        page.body.contains(&format!(r#"value="{acme}" checked"#)),
        "the organization they hold is ticked"
    );
    assert!(!page.body.contains(&format!(r#"value="{bolt}" checked"#)));
    let listed = admin.get(&server, "/admin").await;
    assert!(listed.body.contains(&format!("/admin/users/{id}")));

    // Acme is taken away and Bolt given, with a new name.
    let r = admin
        .post(
            &server,
            &format!("/admin/users/{id}/edit"),
            &[
                ("display_name", "Pat Renamed"),
                ("role", "technician"),
                ("org", &bolt.to_string()),
            ],
        )
        .await;
    assert_eq!(
        r.location(),
        format!("/admin/users/{id}?m=user-updated"),
        "{}",
        r.body
    );
    assert_eq!(sees(acme).await, StatusCode::NOT_FOUND);
    assert_eq!(sees(bolt).await, StatusCode::OK);
    assert!(pat.get(&server, "/").await.body.contains("Pat Renamed"));
    let (outcome, detail) = last_audit(&server, "user.update").await;
    assert_eq!(outcome, "success");
    assert_eq!(detail["organizations_added"], serde_json::json!([bolt]));
    assert_eq!(detail["organizations_removed"], serde_json::json!([acme]));
    assert_eq!(detail["role"]["to"], "technician");

    // Read-only: the same pages, and no changes.
    let token = |pat: &Browser| {
        let (pat, server) = (pat.clone_for_test(), &server);
        async move {
            pat.post(
                server,
                &format!("/organizations/{bolt}/enrollment-tokens"),
                &[("ttl_minutes", "60"), ("max_uses", "1"), ("site", "")],
            )
            .await
            .status
        }
    };
    assert_eq!(token(&pat).await, StatusCode::OK);
    let r = admin
        .post(
            &server,
            &format!("/admin/users/{id}/edit"),
            &[
                ("display_name", "Pat Renamed"),
                ("role", "readonly"),
                ("org", &bolt.to_string()),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(sees(bolt).await, StatusCode::OK);
    assert_eq!(token(&pat).await, StatusCode::FORBIDDEN);

    // An administrator holds no assignments: they reach everything.
    let r = admin
        .post(
            &server,
            &format!("/admin/users/{id}/edit"),
            &[
                ("display_name", "Pat Renamed"),
                ("role", "admin"),
                ("org", &bolt.to_string()),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(sees(acme).await, StatusCode::OK);
    let (held,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM user_organizations WHERE user_id = $1")
            .bind(id)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(held, 0);

    // What is not a role or an organization is refused, and changes nothing.
    for fields in [
        vec![("display_name", "X"), ("role", "owner")],
        vec![
            ("display_name", "X"),
            ("role", "technician"),
            ("org", "not-an-id"),
        ],
        vec![
            ("display_name", "X"),
            ("role", "technician"),
            ("org", "00000000-0000-4000-8000-000000000000"),
        ],
        vec![("display_name", ""), ("role", "technician")],
    ] {
        let r = admin
            .post(&server, &format!("/admin/users/{id}/edit"), &fields)
            .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{fields:?}");
    }
    let (name, role): (String, String) =
        sqlx::query_as("SELECT display_name, role FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!((name.as_str(), role.as_str()), ("Pat Renamed", "admin"));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn user_changes_need_an_administrator_in_sudo_mode_with_the_csrf_token() {
    let server = start_fresh().await;
    let sudo = server.admin_sudo().await;
    let acme = admin_org(&server, &sudo).await;
    let id = make_user(&server, &sudo, "pat@example.com", "technician", Some(acme)).await;
    let pat = server.login("pat@example.com", PASSWORD).await;
    // A second session of the administrator's, which has not confirmed a passkey.
    let plain = server.admin().await;
    let changes = [
        ("edit", vec![("display_name", "Changed"), ("role", "admin")]),
        ("disable", vec![]),
        ("enable", vec![]),
        ("password", vec![]),
    ];
    for (what, fields) in &changes {
        let path = format!("/admin/users/{id}/{what}");
        // Without sudo mode: sent to confirm a passkey, and back to the user's page.
        let r = plain.post(&server, &path, fields).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{what}");
        assert!(
            r.location().starts_with("/sudo?next=%2Fadmin%2Fusers%2F"),
            "{what}: {}",
            r.location()
        );
        // Not an administrator.
        assert_eq!(
            pat.post(&server, &path, fields).await.status,
            StatusCode::FORBIDDEN,
            "{what}"
        );
        // Sudo mode, but not this session's CSRF token.
        let mut forged = sudo.clone_for_test();
        forged.csrf = "x".repeat(43);
        assert_eq!(
            forged.post(&server, &path, fields).await.status,
            StatusCode::FORBIDDEN,
            "{what}"
        );
        // Nobody by that id.
        let nobody = format!("/admin/users/{}/{what}", Uuid::new_v4());
        assert_eq!(
            sudo.post(&server, &nobody, fields).await.status,
            StatusCode::NOT_FOUND,
            "{what}"
        );
    }
    assert_eq!(
        pat.get(&server, &format!("/admin/users/{id}")).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        sudo.get(&server, &format!("/admin/users/{}", Uuid::new_v4()))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    // Nothing above changed anything.
    let (name, role, off, temporary): (String, String, bool, bool) = sqlx::query_as(
        "SELECT display_name, role, disabled_at IS NOT NULL, password_temporary FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(
        (name.as_str(), role.as_str(), off, temporary),
        ("Pat Example", "technician", false, false)
    );
    assert!(can_sign_in(&server, "pat@example.com", PASSWORD).await);
    server.stop().await;
}

async fn admin_org(server: &TestServer, admin: &Browser) -> Uuid {
    admin.create_org(server, "Acme").await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn disabling_a_user_ends_what_they_hold_and_enabling_gives_back_only_sign_in() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin_org(&server, &admin).await;
    // A second administrator, who holds a session, an API token and an unspent enrollment token.
    let id = make_user(&server, &admin, "sam@example.com", "admin", None).await;
    let sam = server.login("sam@example.com", PASSWORD).await;
    sam.sudo(&server, PASSWORD).await;
    let r = sam
        .post(
            &server,
            "/admin/tokens",
            &[
                ("name", "Integration"),
                ("scope", "read"),
                ("ttl_days", "30"),
            ],
        )
        .await;
    let api_token = extract(&r.body, r"(fw8_[A-Za-z0-9_-]{43})").expect("token revealed once");
    let enroll = sam.enrollment_token(&server, acme, "60", "5").await;
    let api = |token: String| {
        let server = &server;
        async move {
            server
                .api(Method::GET, "/api/v1/devices", &token, None, None)
                .await
                .status
        }
    };
    assert_eq!(api(api_token.clone()).await, StatusCode::OK);

    let r = admin
        .post(&server, &format!("/admin/users/{id}/disable"), &[])
        .await;
    assert_eq!(
        r.location(),
        format!("/admin/users/{id}?m=user-disabled"),
        "{}",
        r.body
    );
    assert!(disabled(&server, id).await);
    assert_eq!(sam.get(&server, "/").await.location(), "/login");
    assert!(!can_sign_in(&server, "sam@example.com", PASSWORD).await);
    assert_eq!(api(api_token.clone()).await, StatusCode::UNAUTHORIZED);
    assert!(
        TestAgent::enroll(&server.url(), &enroll).await.is_err(),
        "an enrollment token they made still enrolled a device"
    );
    let (outcome, detail) = last_audit(&server, "user.disable").await;
    assert_eq!(outcome, "success");
    assert_eq!(detail["api_tokens_revoked"], 1);
    assert_eq!(detail["enrollment_tokens_revoked"], 1);
    let page = admin.get(&server, &format!("/admin/users/{id}")).await;
    assert!(page.body.contains("Account disabled"));
    assert!(admin.get(&server, "/admin").await.body.contains("Disabled"));
    // Asking again changes nothing and records nothing new.
    let events = audit_count(&server, "user.disable").await;
    let r = admin
        .post(&server, &format!("/admin/users/{id}/disable"), &[])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(audit_count(&server, "user.disable").await, events);

    // Enabled again: they can sign in. What was revoked stays revoked.
    let r = admin
        .post(&server, &format!("/admin/users/{id}/enable"), &[])
        .await;
    assert_eq!(
        r.location(),
        format!("/admin/users/{id}?m=user-enabled"),
        "{}",
        r.body
    );
    assert!(!disabled(&server, id).await);
    assert!(can_sign_in(&server, "sam@example.com", PASSWORD).await);
    assert_eq!(sam.get(&server, "/").await.location(), "/login");
    assert_eq!(api(api_token).await, StatusCode::UNAUTHORIZED);
    assert!(TestAgent::enroll(&server.url(), &enroll).await.is_err());
    assert_eq!(last_audit(&server, "user.enable").await.0, "success");
    server.stop().await;
}

async fn audit_count(server: &TestServer, action: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM audit_events WHERE action = $1")
        .bind(action)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

/// Wait until a request is blocked on a row lock, in a statement matching `pattern` (a LIKE pattern).
async fn until_waiting(server: &TestServer, pattern: &'static str) {
    wait_for(
        "the request to reach the row lock",
        Duration::from_secs(15),
        || async {
            sqlx::query_as::<_, (i64,)>(
                "SELECT count(*) FROM pg_stat_activity
                  WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE $1",
            )
            .bind(pattern)
            .fetch_one(&server.state.db)
            .await
            .unwrap()
            .0 > 0
        },
    )
    .await;
}

async fn until_waiting_on_users(server: &TestServer) {
    until_waiting(server, "%FROM users%FOR UPDATE").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn the_console_is_never_left_without_an_administrator() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let me = user_id(&server, ADMIN_EMAIL).await;

    // Alone: no demoting or disabling yourself, and the page does not offer either.
    let r = admin
        .post(
            &server,
            &format!("/admin/users/{me}/edit"),
            &[("display_name", "Administrator"), ("role", "technician")],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    let r = admin
        .post(&server, &format!("/admin/users/{me}/disable"), &[])
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    let r = admin
        .post(&server, &format!("/admin/users/{me}/password"), &[])
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    let page = admin.get(&server, &format!("/admin/users/{me}")).await;
    assert!(!page.body.contains(&format!("/admin/users/{me}/disable")));
    assert!(!page.body.contains(r#"<select name="role""#));
    // Your own name is yours to change.
    let r = admin
        .post(
            &server,
            &format!("/admin/users/{me}/edit"),
            &[("display_name", "Root"), ("role", "admin")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);

    // Two administrators act on each other at once. The other's change (made here by hand, and held open) disables
    // this one while this one's request waits; when it goes on, it must see that it is no longer anyone's
    // administrator, and do nothing.
    let other = make_user(&server, &admin, "sam@example.com", "admin", None).await;
    for (path, fields) in [
        (format!("/admin/users/{other}/disable"), vec![]),
        (
            format!("/admin/users/{other}/edit"),
            vec![("display_name", "Sam"), ("role", "technician")],
        ),
    ] {
        let mut held = server.state.db.begin().await.unwrap();
        sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1")
            .bind(me)
            .execute(&mut *held)
            .await
            .unwrap();
        let request = admin.post(&server, &path, &fields);
        let release = async {
            until_waiting_on_users(&server).await;
            held.commit().await.unwrap();
        };
        let (r, ()) = tokio::join!(request, release);
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}: {}", r.body);
        let (role, off): (String, bool) =
            sqlx::query_as("SELECT role, disabled_at IS NOT NULL FROM users WHERE id = $1")
                .bind(other)
                .fetch_one(&server.state.db)
                .await
                .unwrap();
        assert_eq!(
            (role.as_str(), off),
            ("admin", false),
            "{path}: the last administrator who can sign in was changed"
        );
        sqlx::query("UPDATE users SET disabled_at = NULL WHERE id = $1")
            .bind(me)
            .execute(&server.state.db)
            .await
            .unwrap();
    }

    // With two, either may demote or disable the other.
    let r = admin
        .post(
            &server,
            &format!("/admin/users/{other}/edit"),
            &[("display_name", "Sam"), ("role", "technician")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_temporary_password_is_shown_once_and_the_person_replaces_it() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin_org(&server, &admin).await;
    let id = make_user(&server, &admin, "pat@example.com", "technician", Some(acme)).await;
    let old_session = server.login("pat@example.com", PASSWORD).await;

    let r = admin
        .post(&server, &format!("/admin/users/{id}/password"), &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.headers["cache-control"], "no-store");
    let temporary = extract(
        &r.body,
        r#"<pre class="output secret">([A-Za-z0-9_-]{20})</pre>"#,
    )
    .expect("shown once");
    // The old password and the old session are finished; the secret is nowhere in the audit log or on a reload.
    assert_eq!(old_session.get(&server, "/").await.location(), "/login");
    assert!(!can_sign_in(&server, "pat@example.com", PASSWORD).await);
    let (leaked,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_events WHERE detail::text LIKE '%' || $1 || '%'",
    )
    .bind(&temporary)
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(leaked, 0);
    assert_eq!(
        last_audit(&server, "user.password.reset").await.0,
        "success"
    );
    let again = admin.get(&server, &format!("/admin/users/{id}")).await;
    assert!(!again.body.contains(&temporary));
    assert!(again.body.contains("Temporary"));

    // They sign in with it and are told to choose their own.
    let pat = server.login("pat@example.com", &temporary).await;
    let second = server.login("pat@example.com", &temporary).await;
    let account = pat.get(&server, "/account").await;
    assert!(account.body.contains("temporary password"));

    let change = |current: &str, new: &str, repeat: &str| {
        let (pat, server) = (pat.clone_for_test(), &server);
        let fields = [
            ("current".to_string(), current.to_string()),
            ("new".to_string(), new.to_string()),
            ("repeat".to_string(), repeat.to_string()),
        ];
        async move {
            let fields: Vec<(&str, &str)> = fields
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            pat.post(server, "/account/password", &fields).await
        }
    };
    const NEW: &str = "a-password-of-my-own";
    for (current, new, repeat, why) in [
        (temporary.as_str(), "short", "short", "at least 12"),
        (
            temporary.as_str(),
            NEW,
            "something-else-123",
            "not the same",
        ),
        (
            temporary.as_str(),
            temporary.as_str(),
            temporary.as_str(),
            "must differ",
        ),
        ("not-my-password-1", NEW, NEW, "not your current password"),
    ] {
        let r = change(current, new, repeat).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{why}");
        assert!(r.body.contains(why), "{why}: {}", r.body);
    }
    assert_eq!(
        last_audit(&server, "user.password.change").await.0,
        "denied"
    );
    assert!(can_sign_in(&server, "pat@example.com", &temporary).await);

    let r = change(&temporary, NEW, NEW).await;
    assert_eq!(r.location(), "/account?m=password-changed", "{}", r.body);
    assert_eq!(
        last_audit(&server, "user.password.change").await.0,
        "success"
    );
    // This browser stays; the other one of theirs is signed out; only the new password works.
    assert_eq!(pat.get(&server, "/account").await.status, StatusCode::OK);
    assert_eq!(second.get(&server, "/").await.location(), "/login");
    assert!(!can_sign_in(&server, "pat@example.com", &temporary).await);
    assert!(can_sign_in(&server, "pat@example.com", NEW).await);
    let account = pat.get(&server, "/account").await;
    assert!(!account.body.contains("temporary password"));
    assert!(account.body.contains("Last changed"));
    let (temporary_flag,): (bool,) =
        sqlx::query_as("SELECT password_temporary FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert!(!temporary_flag);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_held_browser_cannot_keep_guessing_the_password() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let guess = |n: usize| {
        let (admin, server) = (admin.clone_for_test(), &server);
        async move {
            admin
                .post(
                    server,
                    "/account/password",
                    &[
                        ("current", &format!("wrong-guess-number-{n}")),
                        ("new", "a-password-of-my-own"),
                        ("repeat", "a-password-of-my-own"),
                    ],
                )
                .await
                .status
        }
    };
    for n in 0..5 {
        assert_eq!(
            guess(n).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "guess {n}"
        );
    }
    assert_eq!(guess(5).await, StatusCode::TOO_MANY_REQUESTS);
    // Even the right password waits out the window now.
    let r = admin
        .post(
            &server,
            "/account/password",
            &[
                ("current", ADMIN_PASSWORD),
                ("new", "a-password-of-my-own"),
                ("repeat", "a-password-of-my-own"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(can_sign_in(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await);
    // The form needs this session's CSRF token.
    let mut forged = admin.clone_for_test();
    forged.csrf = "x".repeat(43);
    assert_eq!(
        forged
            .post(&server, "/account/password", &[("current", ADMIN_PASSWORD)])
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    server.stop().await;
}

/// A support session `b` starts for `org`; returns its id.
async fn start_support(server: &TestServer, b: &Browser, org: Uuid) -> Uuid {
    let org = org.to_string();
    let r = b
        .post(
            server,
            "/support",
            &[
                ("organization", org.as_str()),
                ("note", "Front desk"),
                ("capability", "view"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    extract(&r.body, r#"href="/support/([0-9a-f-]{36})""#)
        .expect("the new session's page")
        .parse()
        .unwrap()
}

/// Whether a support session can still go on (it has not been ended, revoked, declined or timed out).
async fn support_live(server: &TestServer, id: Uuid) -> bool {
    let (state,): (String,) = sqlx::query_as("SELECT state FROM support_sessions WHERE id = $1")
        .bind(id)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    matches!(
        state.as_str(),
        "created" | "waiting" | "authorizing" | "awaiting_helper" | "connecting" | "connected"
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn taking_access_away_ends_the_support_sessions_a_person_started() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin.create_org(&server, "Acme").await;
    let bolt = admin.create_org(&server, "Bolt").await;
    let id = make_user(&server, &admin, "pat@example.com", "technician", Some(acme)).await;
    let pat = server.login("pat@example.com", PASSWORD).await;
    let edit = |role: &'static str, orgs: Vec<Uuid>| {
        let (admin, server) = (&admin, &server);
        async move {
            let orgs: Vec<String> = orgs.iter().map(Uuid::to_string).collect();
            let mut fields = vec![("display_name", "Pat Example"), ("role", role)];
            fields.extend(orgs.iter().map(|o| ("org", o.as_str())));
            let r = admin
                .post(server, &format!("/admin/users/{id}/edit"), &fields)
                .await;
            assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
        }
    };

    // More access, or only a new name, ends nothing.
    let open = start_support(&server, &pat, acme).await;
    edit("technician", vec![acme, bolt]).await;
    assert!(support_live(&server, open).await);

    // An organization taken away.
    edit("technician", vec![bolt]).await;
    assert!(!support_live(&server, open).await);

    // A lowered role.
    let open = start_support(&server, &pat, bolt).await;
    edit("readonly", vec![bolt]).await;
    assert!(!support_live(&server, open).await);

    // A temporary password, and a disabled account.
    edit("technician", vec![bolt]).await;
    let open = start_support(&server, &pat, bolt).await;
    let r = admin
        .post(&server, &format!("/admin/users/{id}/password"), &[])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(!support_live(&server, open).await);
    let temporary = extract(
        &r.body,
        r#"<pre class="output secret">([A-Za-z0-9_-]{20})</pre>"#,
    )
    .unwrap();
    let pat = server.login("pat@example.com", &temporary).await;
    let open = start_support(&server, &pat, bolt).await;
    let r = admin
        .post(&server, &format!("/admin/users/{id}/disable"), &[])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(!support_live(&server, open).await);
    server.stop().await;
}

async fn count(server: &TestServer, sql: &str, user: Uuid) -> i64 {
    sqlx::query_as::<_, (i64,)>(sql)
        .bind(user)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

/// Found by the cross-family review: a sign-in that had already checked the password could finish after the account
/// was disabled or its password replaced, leaving a session behind.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_sign_in_in_flight_does_not_outlive_a_disable_or_a_new_password() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin_org(&server, &admin).await;
    let id = make_user(&server, &admin, "pat@example.com", "technician", Some(acme)).await;
    const SESSIONS: &str =
        "SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL";
    for change in [
        "UPDATE users SET disabled_at = now() WHERE id = $1",
        "UPDATE users SET password_hash = 'replaced' WHERE id = $1",
    ] {
        // The administrator's change is made and held open; the sign-in passes the password check against what
        // is still committed, then waits for the row.
        let mut held = server.state.db.begin().await.unwrap();
        sqlx::query(change)
            .bind(id)
            .execute(&mut *held)
            .await
            .unwrap();
        let request = server.login_request("pat@example.com", PASSWORD).await;
        let sign_in = server.request(request);
        let release = async {
            until_waiting(&server, "%FROM users WHERE id = $1 FOR SHARE%").await;
            held.commit().await.unwrap();
        };
        let (r, ()) = tokio::join!(sign_in, release);
        assert_eq!(
            r.status,
            StatusCode::UNAUTHORIZED,
            "{change}: {}",
            r.location()
        );
        assert_eq!(
            count(&server, SESSIONS, id).await,
            0,
            "{change}: a session was left behind"
        );
        assert_eq!(last_audit(&server, "user.login").await.0, "denied");
        sqlx::query("UPDATE users SET disabled_at = NULL WHERE id = $1")
            .bind(id)
            .execute(&server.state.db)
            .await
            .unwrap();
    }
    server.stop().await;
}

/// Found by the cross-family review: a token being issued while its issuer was disabled, or lost the organization,
/// was inserted after the change had revoked "everything they hold".
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_credential_cannot_be_issued_across_a_change_to_its_issuer() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin_org(&server, &admin).await;
    let sam = make_user(&server, &admin, "sam@example.com", "admin", None).await;
    let sam_browser = server.login("sam@example.com", PASSWORD).await;
    sam_browser.sudo(&server, PASSWORD).await;
    let pat = make_user(&server, &admin, "pat@example.com", "technician", Some(acme)).await;
    let pat_browser = server.login("pat@example.com", PASSWORD).await;
    const ENROLL: &str = "SELECT count(*) FROM enrollment_tokens WHERE created_by = $1";
    const API: &str = "SELECT count(*) FROM api_tokens WHERE user_id = $1";
    let enroll_path = format!("/organizations/{acme}/enrollment-tokens");
    let enroll_fields = vec![("ttl_minutes", "60"), ("max_uses", "1"), ("site", "")];
    let api_fields = vec![
        ("name", "Integration"),
        ("scope", "read"),
        ("ttl_days", "30"),
    ];

    // The issuer is disabled while each request waits: nothing is issued.
    for (path, fields, counted) in [
        (enroll_path.as_str(), &enroll_fields, ENROLL),
        ("/admin/tokens", &api_fields, API),
    ] {
        let mut held = server.state.db.begin().await.unwrap();
        sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1")
            .bind(sam)
            .execute(&mut *held)
            .await
            .unwrap();
        let request = sam_browser.post(&server, path, fields);
        let release = async {
            until_waiting(&server, "%FROM users u WHERE u.id = $1%FOR SHARE OF u").await;
            held.commit().await.unwrap();
        };
        let (r, ()) = tokio::join!(request, release);
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}: {}", r.body);
        assert!(!r.body.contains("fw8"), "{path}: a secret was shown");
        assert_eq!(count(&server, counted, sam).await, 0, "{path}");
        sqlx::query("UPDATE users SET disabled_at = NULL WHERE id = $1")
            .bind(sam)
            .execute(&server.state.db)
            .await
            .unwrap();
    }

    // The issuer loses the organization while the request waits (what an administrator's edit does, held open).
    let mut held = server.state.db.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(pat)
        .execute(&mut *held)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_organizations WHERE user_id = $1")
        .bind(pat)
        .execute(&mut *held)
        .await
        .unwrap();
    let request = pat_browser.post(&server, &enroll_path, &enroll_fields);
    let release = async {
        until_waiting(&server, "%FROM users u WHERE u.id = $1%FOR SHARE OF u").await;
        held.commit().await.unwrap();
    };
    let (r, ()) = tokio::join!(request, release);
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    assert!(!r.body.contains("fw8e_"), "a secret was shown");
    assert_eq!(count(&server, ENROLL, pat).await, 0);

    // Undisturbed, the administrator can issue.
    assert_eq!(
        sam_browser
            .post(&server, "/admin/tokens", &api_fields)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(count(&server, API, sam).await, 1);
    server.stop().await;
}

/// Found by the cross-family review: an enrollment token outlived the authority it was issued under.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn enrollment_tokens_end_with_the_authority_they_were_issued_under() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin.create_org(&server, "Acme").await;
    let bolt = admin.create_org(&server, "Bolt").await;
    let id = make_user(&server, &admin, "pat@example.com", "technician", Some(acme)).await;
    let edit = |role: &'static str, orgs: Vec<Uuid>| {
        let (admin, server) = (&admin, &server);
        async move {
            let orgs: Vec<String> = orgs.iter().map(Uuid::to_string).collect();
            let mut fields = vec![("display_name", "Pat Example"), ("role", role)];
            fields.extend(orgs.iter().map(|o| ("org", o.as_str())));
            let r = admin
                .post(server, &format!("/admin/users/{id}/edit"), &fields)
                .await;
            assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
        }
    };
    let enrolls = |token: String| {
        let server = &server;
        async move {
            match TestAgent::enroll(&server.url(), &token).await {
                Ok(agent) => {
                    std::mem::forget(agent);
                    true
                }
                Err(_) => false,
            }
        }
    };
    let revoked = || {
        let server = &server;
        async move { last_audit(server, "user.update").await.1["enrollment_tokens_revoked"].clone() }
    };
    let pat = server.login("pat@example.com", PASSWORD).await;
    let for_acme = pat.enrollment_token(&server, acme, "1440", "100").await;
    assert!(enrolls(for_acme.clone()).await);

    // More access leaves it working.
    edit("technician", vec![acme, bolt]).await;
    assert!(enrolls(for_acme.clone()).await);
    assert_eq!(revoked().await, 0);
    let for_bolt = pat.enrollment_token(&server, bolt, "1440", "100").await;

    // Acme is taken away: its token stops, Bolt's goes on.
    edit("technician", vec![bolt]).await;
    assert!(
        !enrolls(for_acme).await,
        "a token for a removed organization still enrolled"
    );
    assert!(enrolls(for_bolt.clone()).await);
    assert_eq!(revoked().await, 1);

    // A role that may not enroll: every token of theirs stops.
    edit("readonly", vec![bolt]).await;
    assert!(
        !enrolls(for_bolt).await,
        "a read-only user's token still enrolled"
    );
    assert_eq!(revoked().await, 1);
    server.stop().await;
}

/// A request to make: its path, its form fields, and the lock statement it is expected to wait on.
type Attempt<'a> = (String, &'a Vec<(&'a str, &'a str)>, &'static str);

/// Found by the cross-family re-review: a request already authorized went on to act after its caller had been
/// disabled, signed out everywhere, or had left sudo mode.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_request_under_way_does_nothing_once_its_caller_is_disabled_or_signed_out() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin_org(&server, &admin).await;
    let sam = make_user(&server, &admin, "sam@example.com", "admin", None).await;
    let sam_browser = server.login("sam@example.com", PASSWORD).await;
    sam_browser.sudo(&server, PASSWORD).await;
    let pat = make_user(&server, &admin, "pat@example.com", "technician", Some(acme)).await;
    let pat_browser = server.login("pat@example.com", PASSWORD).await;
    const USERS: &str = "SELECT count(*) FROM users WHERE id <> $1";
    const API: &str = "SELECT count(*) FROM api_tokens WHERE user_id = $1";
    const SUPPORT: &str = "SELECT count(*) FROM support_sessions WHERE created_by = $1";
    let users_before = count(&server, USERS, sam).await;
    let new_user = vec![
        ("email", "mallory@example.com"),
        ("display_name", "Mallory"),
        ("password", PASSWORD),
        ("role", "admin"),
    ];
    let api_fields = vec![
        ("name", "Integration"),
        ("scope", "read"),
        ("ttl_days", "30"),
    ];
    let none: Vec<(&str, &str)> = vec![];
    const ON_USERS: &str = "%FROM users%WHERE id = $1 OR id = $2%FOR UPDATE";
    const ON_ISSUER: &str = "%FROM users u WHERE u.id = $1%FOR SHARE OF u";

    // What an administrator's change to Sam does, made by hand and held open while Sam's own request waits.
    let changes: [(&str, &[&str]); 3] = [
        (
            "disabled",
            &["UPDATE users SET disabled_at = now() WHERE id = $1"],
        ),
        (
            "signed out",
            &[
                "SELECT 1 FROM users WHERE id = $1 FOR UPDATE",
                "UPDATE sessions SET revoked_at = now() WHERE user_id = $1",
            ],
        ),
        (
            "out of sudo mode",
            &[
                "SELECT 1 FROM users WHERE id = $1 FOR UPDATE",
                "UPDATE sessions SET sudo_until = now() - interval '1 second' WHERE user_id = $1",
            ],
        ),
    ];
    for (what, statements) in changes {
        // Sam's requests: re-enable themselves, disable someone else, make another administrator, issue a token.
        let requests: [Attempt; 4] = [
            (format!("/admin/users/{sam}/enable"), &none, ON_USERS),
            (format!("/admin/users/{pat}/disable"), &none, ON_USERS),
            ("/admin/users".to_string(), &new_user, ON_ISSUER),
            ("/admin/tokens".to_string(), &api_fields, ON_ISSUER),
        ];
        for (path, fields, waits_on) in requests {
            let mut held = server.state.db.begin().await.unwrap();
            for sql in statements {
                sqlx::query(sql)
                    .bind(sam)
                    .execute(&mut *held)
                    .await
                    .unwrap();
            }
            let request = sam_browser.post(&server, &path, fields);
            let release = async {
                until_waiting(&server, waits_on).await;
                held.commit().await.unwrap();
            };
            let (r, ()) = tokio::join!(request, release);
            let expected = if what == "out of sudo mode" {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            };
            assert_eq!(r.status, expected, "{what}, {path}: {}", r.body);
            assert!(
                !r.body.contains("fw8_"),
                "{what}, {path}: a secret was shown"
            );
            assert!(!disabled(&server, pat).await, "{what}: Pat was disabled");
            assert_eq!(
                count(&server, USERS, sam).await,
                users_before,
                "{what}: a user was made"
            );
            assert_eq!(
                count(&server, API, sam).await,
                0,
                "{what}: a token was issued"
            );
            if what == "disabled" {
                assert!(
                    disabled(&server, sam).await,
                    "Sam undid their own disabling"
                );
            }
            // Put Sam back as they were: enabled, signed in, in sudo mode.
            sqlx::query("UPDATE users SET disabled_at = NULL WHERE id = $1")
                .bind(sam)
                .execute(&server.state.db)
                .await
                .unwrap();
            sqlx::query(
                "UPDATE sessions SET revoked_at = NULL, sudo_until = now() + interval '5 minutes' WHERE user_id = $1",
            )
            .bind(sam)
            .execute(&server.state.db)
            .await
            .unwrap();
        }
    }
    // Left alone, the same request goes through.
    let r = sam_browser
        .post(&server, "/admin/tokens", &api_fields)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    // A support session is authority handed out in advance too: none is made across a disable.
    let org = acme.to_string();
    let support = vec![
        ("organization", org.as_str()),
        ("note", "x"),
        ("capability", "view"),
    ];
    let mut held = server.state.db.begin().await.unwrap();
    sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1")
        .bind(pat)
        .execute(&mut *held)
        .await
        .unwrap();
    let request = pat_browser.post(&server, "/support", &support);
    let release = async {
        until_waiting(&server, ON_ISSUER).await;
        held.commit().await.unwrap();
    };
    let (r, ()) = tokio::join!(request, release);
    assert_ne!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        count(&server, SUPPORT, pat).await,
        0,
        "a support session was made"
    );
    server.stop().await;
}

/// Found by the cross-family re-review: an administrator has no assignments to take away, so demoting one left
/// their enrollment tokens for every organization working.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_demoted_administrator_keeps_only_the_enrollment_tokens_of_their_new_organizations() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin.create_org(&server, "Acme").await;
    let bolt = admin.create_org(&server, "Bolt").await;
    let id = make_user(&server, &admin, "sam@example.com", "admin", None).await;
    let sam = server.login("sam@example.com", PASSWORD).await;
    let for_acme = sam.enrollment_token(&server, acme, "1440", "100").await;
    let for_bolt = sam.enrollment_token(&server, bolt, "1440", "100").await;
    let r = admin
        .post(
            &server,
            &format!("/admin/users/{id}/edit"),
            &[
                ("display_name", "Sam"),
                ("role", "technician"),
                ("org", &acme.to_string()),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let enrolls = |token: String| {
        let server = &server;
        async move {
            match TestAgent::enroll(&server.url(), &token).await {
                Ok(agent) => {
                    std::mem::forget(agent);
                    true
                }
                Err(_) => false,
            }
        }
    };
    assert!(
        enrolls(for_acme).await,
        "the token for the organization they keep stopped working"
    );
    assert!(
        !enrolls(for_bolt).await,
        "a token outside their new organizations still enrolled"
    );
    assert_eq!(
        last_audit(&server, "user.update").await.1["enrollment_tokens_revoked"],
        1
    );
    server.stop().await;
}
