//! Two-step verification (TOTP + recovery codes) through the real router and PostgreSQL.
//! Codes are computed from the key the set-up page shows, as an authenticator app would.

mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use common::*;
use flyw8t_server::config::Config;
use flyw8t_server::totp;

async fn start_mfa(require: bool) -> TestServer {
    start(Config {
        require_mfa: require,
        ..test_config(&fresh_database().await)
    })
    .await
}

async fn raw(
    server: &TestServer,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    fields: &[(&str, &str)],
) -> Response {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    let body = if method == "POST" {
        req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        Body::from(form(fields))
    } else {
        Body::empty()
    };
    server.request(req.body(body).unwrap()).await
}

/// Password step: returns where it sends the browser, and the (partial) session cookie.
async fn password(server: &TestServer, email: &str, pw: &str) -> (String, String) {
    let r = raw(
        server,
        "POST",
        "/login",
        None,
        &[("email", email), ("password", pw)],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    (r.location(), r.cookie().expect("session cookie"))
}

fn csrf_of(body: &str) -> String {
    extract(body, r#"name="csrf" value="([^"]+)""#).expect("csrf on page")
}

fn base32_decode(s: &str) -> Vec<u8> {
    const A: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buf, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.chars().filter(|c| !c.is_whitespace()) {
        buf = (buf << 5) | A.find(c).expect("base32") as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

/// A six-digit code that matches no step in the acceptance window.
fn wrong_code(secret: &[u8]) -> String {
    let now = totp::now_step();
    (0..1_000_000u32)
        .map(|n| format!("{n:06}"))
        .find(|c| {
            totp::matching_step(secret, c, now).is_none()
                && totp::matching_step(secret, c, now + 1).is_none()
        })
        .unwrap()
}

/// The console refuses this cookie (sends it to sign in).
async fn shut_out(server: &TestServer, cookie: &str) {
    for path in ["/", "/admin", "/devices", "/account", "/support"] {
        let r = raw(server, "GET", path, Some(cookie), &[]).await;
        assert_eq!(
            r.status,
            StatusCode::SEE_OTHER,
            "{path} let a partial session in"
        );
        assert_eq!(r.location(), "/login", "{path}");
    }
}

struct Enrolled {
    cookie: String,
    secret: Vec<u8>,
    step: u64,
    recovery: Vec<String>,
}

/// Finish set-up from a session that is on the set-up page.
async fn enroll(server: &TestServer, cookie: &str) -> Enrolled {
    let page = raw(server, "GET", "/account/mfa", Some(cookie), &[]).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.location());
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    let key = extract(&page.body, r#"id="totp-key"[^>]*>([A-Z2-7 ]+)<"#)
        .unwrap_or_else(|| panic!("key on set-up page: {}", page.body));
    let secret = base32_decode(&key);
    assert_eq!(secret.len(), totp::SECRET_LEN);
    let qr = extract(
        &page.body,
        r#"(?s)<svg[^>]*class="qr"[^>]*>.*?<path d="(M[^"]+)""#,
    )
    .expect("QR code rendered");
    assert!(qr.matches('M').count() > 200, "QR code has its modules");
    let csrf = csrf_of(&page.body);

    // A reload shows the same pending key (it belongs to this session until confirmed).
    let again = raw(server, "GET", "/account/mfa", Some(cookie), &[]).await;
    assert!(again.body.contains(&key));

    let bad = raw(
        server,
        "POST",
        "/account/mfa",
        Some(cookie),
        &[("csrf", &csrf), ("code", &wrong_code(&secret))],
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
    let forged = raw(
        server,
        "POST",
        "/account/mfa",
        Some(cookie),
        &[
            ("csrf", "nope"),
            ("code", &totp::code_at(&secret, totp::now_step())),
        ],
    )
    .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);

    let step = totp::now_step();
    let ok = raw(
        server,
        "POST",
        "/account/mfa",
        Some(cookie),
        &[("csrf", &csrf), ("code", &totp::code_at(&secret, step))],
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
    assert_eq!(ok.headers[header::CACHE_CONTROL], "no-store");
    let codes = extract(&ok.body, r#"(?s)id="recovery-codes"[^>]*>([^<]+)<"#)
        .expect("recovery codes shown");
    let recovery: Vec<String> = codes.lines().map(str::to_string).collect();
    assert_eq!(recovery.len(), totp::RECOVERY_CODES);
    Enrolled {
        cookie: ok.cookie().unwrap_or_else(|| cookie.to_string()),
        secret,
        step,
        recovery,
    }
}

async fn sign_out(server: &TestServer, cookie: &str) {
    let b = server.browser(cookie.to_string()).await;
    let r = b.post(server, "/logout", &[]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

async fn audit_actions(server: &TestServer) -> Vec<(String, String, String)> {
    sqlx::query_as("SELECT action, outcome, detail::text FROM audit_events ORDER BY id")
        .fetch_all(&server.state.db)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn required_mfa_enrollment_challenge_replay_and_recovery() {
    let server = start_mfa(true).await;

    // A correct password alone reaches only set-up.
    let (next, partial) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    assert_eq!(next, "/account/mfa");
    shut_out(&server, &partial).await;
    let challenge = raw(&server, "GET", "/login/mfa", Some(&partial), &[]).await;
    assert_eq!(challenge.location(), "/login", "no challenge before set-up");

    let e = enroll(&server, &partial).await;
    assert_ne!(e.cookie, partial, "session secret rotated on promotion");
    shut_out(&server, &partial).await;
    server.browser(e.cookie.clone()).await;
    sign_out(&server, &e.cookie).await;

    // Next sign-in owes a code.
    let (next, partial) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    assert_eq!(next, "/login/mfa");
    shut_out(&server, &partial).await;
    let page = raw(&server, "GET", "/login/mfa", Some(&partial), &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    let csrf = csrf_of(&page.body);

    // The code used to confirm set-up cannot be replayed.
    let replay = raw(
        &server,
        "POST",
        "/login/mfa",
        Some(&partial),
        &[("csrf", &csrf), ("code", &totp::code_at(&e.secret, e.step))],
    )
    .await;
    assert_eq!(
        replay.status,
        StatusCode::UNAUTHORIZED,
        "replayed code accepted"
    );
    let forged = raw(
        &server,
        "POST",
        "/login/mfa",
        Some(&partial),
        &[
            ("csrf", "x"),
            ("code", &totp::code_at(&e.secret, e.step + 1)),
        ],
    )
    .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);

    let ok = raw(
        &server,
        "POST",
        "/login/mfa",
        Some(&partial),
        &[
            ("csrf", &csrf),
            ("code", &totp::code_at(&e.secret, e.step + 1)),
        ],
    )
    .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER, "{}", ok.body);
    assert_eq!(ok.location(), "/");
    let full = ok.cookie().unwrap();
    assert_ne!(full, partial);
    shut_out(&server, &partial).await;
    server.browser(full.clone()).await;
    sign_out(&server, &full).await;

    // A recovery code works once, typed loosely.
    let (_, partial) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    let csrf = csrf_of(
        &raw(&server, "GET", "/login/mfa", Some(&partial), &[])
            .await
            .body,
    );
    let typed = e.recovery[3].to_uppercase().replace('-', " ");
    let ok = raw(
        &server,
        "POST",
        "/login/mfa",
        Some(&partial),
        &[("csrf", &csrf), ("code", &typed)],
    )
    .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER, "{}", ok.body);
    let full = ok.cookie().unwrap();
    let account = raw(&server, "GET", "/account", Some(&full), &[]).await;
    assert!(
        account.body.contains("9 unused recovery codes"),
        "{}",
        account.body
    );
    sign_out(&server, &full).await;

    let (_, partial) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    let csrf = csrf_of(
        &raw(&server, "GET", "/login/mfa", Some(&partial), &[])
            .await
            .body,
    );
    let reused = raw(
        &server,
        "POST",
        "/login/mfa",
        Some(&partial),
        &[("csrf", &csrf), ("code", &e.recovery[3])],
    )
    .await;
    assert_eq!(
        reused.status,
        StatusCode::UNAUTHORIZED,
        "recovery code reused"
    );

    let audit = audit_actions(&server).await;
    let has = |action: &str, outcome: &str, detail: &str| {
        audit
            .iter()
            .any(|(a, o, d)| a == action && o == outcome && d.contains(detail))
    };
    assert!(has("user.login.password", "success", "enroll"));
    assert!(has("user.mfa.enable", "success", ""));
    assert!(has("user.login", "success", "totp_enrolled"));
    assert!(has("user.login", "success", "\"totp\""));
    assert!(has("user.login", "success", "recovery_code"));
    assert!(has("user.login", "denied", "wrong or reused code"));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn wrong_codes_end_the_partial_session() {
    let server = start_mfa(true).await;
    let (_, partial) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    let e = enroll(&server, &partial).await;
    sign_out(&server, &e.cookie).await;

    let (_, partial) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    let csrf = csrf_of(
        &raw(&server, "GET", "/login/mfa", Some(&partial), &[])
            .await
            .body,
    );
    let wrong = wrong_code(&e.secret);
    for _ in 0..flyw8t_server::mfa::MAX_ATTEMPTS {
        let r = raw(
            &server,
            "POST",
            "/login/mfa",
            Some(&partial),
            &[("csrf", &csrf), ("code", &wrong)],
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    // Even a correct code is refused once the attempts are spent, and the session is gone.
    let r = raw(
        &server,
        "POST",
        "/login/mfa",
        Some(&partial),
        &[
            ("csrf", &csrf),
            ("code", &totp::code_at(&e.secret, e.step + 1)),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.body.contains("Too many incorrect codes"), "{}", r.body);
    let gone = raw(&server, "GET", "/login/mfa", Some(&partial), &[]).await;
    assert_eq!(gone.location(), "/login");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn admin_reset_signs_the_user_out_and_forces_setup_again() {
    let server = start_mfa(true).await;
    let (_, partial) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    let admin = server.browser(enroll(&server, &partial).await.cookie).await;

    let r = admin
        .post(
            &server,
            "/admin/users",
            &[
                ("email", "tech@example.test"),
                ("display_name", "Tech"),
                ("password", "tech-password-123"),
                ("role", "technician"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let (next, partial) = password(&server, "tech@example.test", "tech-password-123").await;
    assert_eq!(next, "/account/mfa");
    let tech = enroll(&server, &partial).await;
    server.browser(tech.cookie.clone()).await;

    let page = admin.get(&server, "/admin").await;
    let tech_id: String = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT id FROM users WHERE email = 'tech@example.test'",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap()
    .0
    .to_string();
    let reset = format!("/admin/users/{tech_id}/mfa/reset");
    assert!(
        page.body.contains(&reset),
        "reset offered on the admin page"
    );

    // A technician cannot reset anyone, including themselves.
    let tb = server.browser(tech.cookie.clone()).await;
    assert_eq!(
        tb.post(&server, &reset, &[]).await.status,
        StatusCode::FORBIDDEN
    );

    let r = admin.post(&server, &reset, &[]).await;
    assert_eq!(r.location(), "/admin?m=mfa-reset");
    shut_out(&server, &tech.cookie).await;
    let (next, _) = password(&server, "tech@example.test", "tech-password-123").await;
    assert_eq!(next, "/account/mfa", "set-up owed again after reset");
    let audit = audit_actions(&server).await;
    assert!(audit.iter().any(|(a, o, d)| a == "user.mfa.reset"
        && o == "success"
        && d.contains("tech@example.test")));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn optional_mfa_can_be_set_up_and_turned_off() {
    let server = start_mfa(false).await;
    let (next, full) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    assert_eq!(
        next, "/",
        "password suffices when MFA is neither set up nor required"
    );
    let account = raw(&server, "GET", "/account", Some(&full), &[]).await;
    assert!(account.body.contains("Set up two-step verification"));

    let setup = raw(&server, "GET", "/account/mfa", Some(&full), &[]).await;
    assert!(
        setup.body.contains(">Cancel<"),
        "voluntary set-up can be cancelled"
    );
    // A second password-only session, as someone who already had the password would hold.
    let (_, other) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    let e = enroll(&server, &full).await;
    assert_ne!(
        e.cookie, full,
        "the enrolling session continues under a new secret"
    );
    shut_out(&server, &full).await;
    shut_out(&server, &other).await;
    let b = server.browser(e.cookie.clone()).await;

    // Turning it off needs a current code; a wrong one changes nothing.
    let r = b
        .post(
            &server,
            "/account/mfa/disable",
            &[("code", &wrong_code(&e.secret))],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Replacing recovery codes needs a valid, unspent code; a refusal changes nothing.
    let replay = totp::code_at(&e.secret, e.step);
    for bad in ["", replay.as_str()] {
        let r = b
            .post(&server, "/account/mfa/recovery-codes", &[("code", bad)])
            .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{bad:?}");
    }
    let mut last = e.step;
    let r = b
        .post(
            &server,
            "/account/mfa/recovery-codes",
            &[("code", &fresh_code(&e.secret, &mut last).await)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let codes = extract(&r.body, r#"(?s)id="recovery-codes"[^>]*>([^<]+)<"#).unwrap();
    let fresh: Vec<String> = codes.lines().map(str::to_string).collect();
    assert_eq!(fresh.len(), totp::RECOVERY_CODES);
    sign_out(&server, &b.cookie).await;

    // The old codes died with the replacement; a new one works.
    let (next, partial) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    assert_eq!(next, "/login/mfa");
    let csrf = csrf_of(
        &raw(&server, "GET", "/login/mfa", Some(&partial), &[])
            .await
            .body,
    );
    let old = raw(
        &server,
        "POST",
        "/login/mfa",
        Some(&partial),
        &[("csrf", &csrf), ("code", &e.recovery[0])],
    )
    .await;
    assert_eq!(
        old.status,
        StatusCode::UNAUTHORIZED,
        "a replaced recovery code still worked"
    );
    let ok = raw(
        &server,
        "POST",
        "/login/mfa",
        Some(&partial),
        &[("csrf", &csrf), ("code", &fresh[0])],
    )
    .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER, "{}", ok.body);
    let b = server.browser(ok.cookie().unwrap()).await;

    // A sign-in waiting for a code does not survive the factor changing under it.
    let (_, pending) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    let r = b
        .post(
            &server,
            "/account/mfa/disable",
            &[("code", &fresh_code(&e.secret, &mut last).await)],
        )
        .await;
    assert_eq!(r.location(), "/account?m=mfa-disabled", "{}", r.body);
    let gone = raw(&server, "GET", "/login/mfa", Some(&pending), &[]).await;
    assert_eq!(gone.location(), "/login");
    sign_out(&server, &b.cookie).await;
    let (next, _) = password(&server, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    assert_eq!(next, "/");
    server.stop().await;
}

/// The code for the earliest step after `last` that the server still accepts, waiting for the
/// clock when every step in the window is spent (as a person waits for the next code).
async fn fresh_code(secret: &[u8], last: &mut u64) -> String {
    loop {
        let now = totp::now_step();
        let step = (*last + 1).max(now.saturating_sub(totp::SKEW));
        if step <= now + totp::SKEW {
            *last = step;
            return totp::code_at(secret, step);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
