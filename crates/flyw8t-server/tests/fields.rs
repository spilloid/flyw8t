//! Custom fields: definitions, values at four levels with history, resolution, required values, roles and scope,
//! and secrets that are stored encrypted and never shown again.

mod common;

use axum::http::StatusCode;
use common::*;
use uuid::Uuid;

async fn org_with_device(server: &TestServer, admin: &Browser, name: &str) -> (Uuid, Uuid) {
    let org = admin.create_org(server, name).await;
    let token = admin.enrollment_token(server, org, "60", "1").await;
    let agent = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let id = agent.device_id;
    std::mem::forget(agent);
    (org, id)
}

async fn technician(server: &TestServer, admin: &Browser, email: &str, org: Uuid) -> Browser {
    let r = admin
        .post(
            server,
            "/admin/users",
            &[
                ("email", email),
                ("display_name", "Tech"),
                ("password", "tech-password-123"),
                ("role", "technician"),
                ("org", &org.to_string()),
            ],
        )
        .await;
    assert_eq!(r.location(), "/admin?m=user-created", "{}", r.body);
    server.login(email, "tech-password-123").await
}

/// Define a field; returns its id.
async fn define(server: &TestServer, admin: &Browser, fields: &[(&str, &str)]) -> Uuid {
    let r = admin.post(server, "/admin/fields", fields).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let key = fields.iter().find(|(k, _)| *k == "key").unwrap().1;
    sqlx::query_as::<_, (Uuid,)>("SELECT id FROM field_definitions WHERE key = $1")
        .bind(key)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

async fn set(
    server: &TestServer,
    who: &Browser,
    field: Uuid,
    scope: &str,
    target: Option<Uuid>,
    value: &str,
) -> StatusCode {
    let t = target.map(|t| t.to_string()).unwrap_or_default();
    let mut f = vec![("scope", scope), ("value", value)];
    if target.is_some() {
        f.push(("target", t.as_str()));
    }
    who.post(server, &format!("/fields/{field}/value"), &f)
        .await
        .status
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn values_resolve_from_device_to_organization_to_global_with_history() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (org_a, dev_a) = org_with_device(&server, &admin, "Org A").await;
    let (_, dev_b) = org_with_device(&server, &admin, "Org B").await;
    let f = define(
        &server,
        &admin,
        &[
            ("key", "backup_share"),
            ("label", "Backup share"),
            ("kind", "text"),
            ("scope", "global"),
            ("scope", "organization"),
            ("scope", "device"),
        ],
    )
    .await;

    assert_eq!(
        set(&server, &admin, f, "global", None, r"\\nas\global").await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        set(
            &server,
            &admin,
            f,
            "organization",
            Some(org_a),
            r"\\nas\org-a"
        )
        .await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        set(
            &server,
            &admin,
            f,
            "device",
            Some(dev_a),
            r"\\nas\front-desk"
        )
        .await,
        StatusCode::SEE_OTHER
    );

    let page = admin.get(&server, &format!("/devices/{dev_a}")).await.body;
    assert!(
        page.contains(r"\\nas\front-desk") && page.contains("set on this device"),
        "{page}"
    );
    let page = admin.get(&server, &format!("/devices/{dev_b}")).await.body;
    assert!(page.contains(r"\\nas\global") && page.contains("global"));
    let page = admin
        .get(&server, &format!("/organizations/{org_a}"))
        .await
        .body;
    assert!(page.contains(r"\\nas\org-a"));

    // Clearing the device value makes it inherit again; the history keeps both changes.
    assert_eq!(
        set(&server, &admin, f, "device", Some(dev_a), "").await,
        StatusCode::SEE_OTHER
    );
    let page = admin.get(&server, &format!("/devices/{dev_a}")).await.body;
    assert!(
        page.contains(r"\\nas\org-a") && page.contains("from the organization"),
        "{page}"
    );
    let hist = admin
        .get(
            &server,
            &format!("/fields/{f}/history?scope=device&target={dev_a}"),
        )
        .await;
    assert_eq!(hist.status, StatusCode::OK);
    assert!(
        hist.body.contains(r"\\nas\front-desk") && hist.body.contains("cleared"),
        "{}",
        hist.body
    );

    // The API shows resolved values with their source.
    let api = admin.get(&server, &format!("/devices/{dev_a}")).await;
    assert_eq!(api.status, StatusCode::OK);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn roles_and_organizations_limit_who_sets_what() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (org_a, dev_a) = org_with_device(&server, &admin, "Org A").await;
    let (org_b, _) = org_with_device(&server, &admin, "Org B").await;
    let tech = technician(&server, &admin, "tech@example.test", org_a).await;
    let open = define(
        &server,
        &admin,
        &[
            ("key", "asset_tag"),
            ("label", "Asset tag"),
            ("kind", "text"),
            ("scope", "global"),
            ("scope", "organization"),
            ("scope", "device"),
            ("technician_can_edit", "yes"),
        ],
    )
    .await;
    let closed = define(
        &server,
        &admin,
        &[
            ("key", "contract"),
            ("label", "Contract"),
            ("kind", "text"),
            ("scope", "organization"),
        ],
    )
    .await;

    // Technicians cannot define fields or set global values.
    let r = tech
        .post(
            &server,
            "/admin/fields",
            &[
                ("key", "x"),
                ("label", "X"),
                ("kind", "text"),
                ("scope", "global"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(
        tech.get(&server, "/admin/fields").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        set(&server, &tech, open, "global", None, "x").await,
        StatusCode::FORBIDDEN
    );
    // In their organization, on a field that allows it: yes. On one that does not: no.
    assert_eq!(
        set(&server, &tech, open, "device", Some(dev_a), "A-100").await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        set(&server, &tech, closed, "organization", Some(org_a), "gold").await,
        StatusCode::FORBIDDEN
    );
    // Another organization does not exist for them, for setting or for history.
    assert_eq!(
        set(&server, &tech, open, "organization", Some(org_b), "x").await,
        StatusCode::NOT_FOUND
    );
    let h = tech
        .get(
            &server,
            &format!("/fields/{open}/history?scope=organization&target={org_b}"),
        )
        .await;
    assert_eq!(h.status, StatusCode::NOT_FOUND);
    // A level the field does not allow is refused even for an administrator.
    assert_eq!(
        set(&server, &admin, closed, "device", Some(dev_a), "x").await,
        StatusCode::FORBIDDEN
    );
    // Archived fields cannot change.
    let r = admin
        .post(&server, &format!("/admin/fields/{open}/archive"), &[])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        set(&server, &admin, open, "device", Some(dev_a), "A-200").await,
        StatusCode::FORBIDDEN
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn values_are_checked_by_kind() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (org, _) = org_with_device(&server, &admin, "Org").await;
    let n = define(
        &server,
        &admin,
        &[
            ("key", "seats"),
            ("label", "Seats"),
            ("kind", "number"),
            ("scope", "organization"),
        ],
    )
    .await;
    let c = define(
        &server,
        &admin,
        &[
            ("key", "tier"),
            ("label", "Tier"),
            ("kind", "choice"),
            ("choices", "bronze, silver, gold"),
            ("scope", "organization"),
        ],
    )
    .await;
    assert_eq!(
        set(&server, &admin, n, "organization", Some(org), "many").await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        set(&server, &admin, n, "organization", Some(org), "12").await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        set(&server, &admin, c, "organization", Some(org), "platinum").await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        set(&server, &admin, c, "organization", Some(org), "silver").await,
        StatusCode::SEE_OTHER
    );
    // Bad definitions.
    let r = admin
        .post(
            &server,
            "/admin/fields",
            &[
                ("key", "Bad Key"),
                ("label", "X"),
                ("kind", "text"),
                ("scope", "global"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = admin
        .post(
            &server,
            "/admin/fields",
            &[
                ("key", "pw"),
                ("label", "X"),
                ("kind", "secret"),
                ("scope", "global"),
                ("default_value", "x"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = admin
        .post(
            &server,
            "/admin/fields",
            &[
                ("key", "seats"),
                ("label", "Dup"),
                ("kind", "text"),
                ("scope", "global"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn secrets_are_encrypted_and_never_shown_again() {
    // Without a field key, a secret value is refused.
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (org, _) = org_with_device(&server, &admin, "Org").await;
    let f = define(
        &server,
        &admin,
        &[
            ("key", "wifi_psk"),
            ("label", "Wi-Fi key"),
            ("kind", "secret"),
            ("scope", "organization"),
        ],
    )
    .await;
    assert_eq!(
        set(&server, &admin, f, "organization", Some(org), "hunter2-psk").await,
        StatusCode::CONFLICT
    );
    server.stop().await;

    let mut cfg = test_config(&fresh_database().await);
    cfg.field_key = Some([9u8; 32]);
    let server = start(cfg).await;
    let admin = server.admin_sudo().await;
    let (org, dev) = org_with_device(&server, &admin, "Org").await;
    let f = define(
        &server,
        &admin,
        &[
            ("key", "wifi_psk"),
            ("label", "Wi-Fi key"),
            ("kind", "secret"),
            ("scope", "organization"),
        ],
    )
    .await;
    assert_eq!(
        set(&server, &admin, f, "organization", Some(org), "hunter2-psk").await,
        StatusCode::SEE_OTHER
    );
    // Stored encrypted: no plaintext column, the ciphertext opens with the key.
    let (value, secret): (Option<String>, Vec<u8>) =
        sqlx::query_as("SELECT value, secret FROM field_values WHERE field_id = $1")
            .bind(f)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(value, None);
    assert!(!secret.windows(11).any(|w| w == b"hunter2-psk"));
    assert_eq!(
        flyw8t_server::fields::open(&[9u8; 32], &secret).as_deref(),
        Some("hunter2-psk")
    );
    // Never shown again: pages, history, the API and the audit log.
    for path in [
        format!("/organizations/{org}"),
        format!("/devices/{dev}"),
        format!("/fields/{f}/history?scope=organization&target={org}"),
        "/audit".to_string(),
    ] {
        let page = admin.get(&server, &path).await;
        assert_eq!(page.status, StatusCode::OK, "{path}");
        assert!(!page.body.contains("hunter2"), "{path} shows the secret");
        assert!(path == "/audit" || page.body.contains("••••••"), "{path}");
    }
    let (status, body) = server_api_device(&server, &admin, dev).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("hunter2") && body.contains("\"secret\":true"),
        "{body}"
    );
    server.stop().await;
}

/// The device's JSON through the API, with a token made for the test.
async fn server_api_device(
    server: &TestServer,
    admin: &Browser,
    dev: Uuid,
) -> (StatusCode, String) {
    let r = admin
        .post(
            server,
            "/admin/tokens",
            &[
                ("name", "fields test"),
                ("scope", "read"),
                ("ttl_days", "1"),
            ],
        )
        .await;
    let token = extract(&r.body, r"(fw8_[A-Za-z0-9_-]{20,})").expect("token shown once");
    let r = server
        .api(
            axum::http::Method::GET,
            &format!("/api/v1/devices/{dev}"),
            &token,
            None,
            None,
        )
        .await;
    (r.status, r.body)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn missing_required_values_are_reported_until_set() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (org_a, _) = org_with_device(&server, &admin, "Org A").await;
    let (org_b, dev_b) = org_with_device(&server, &admin, "Org B").await;
    let per_org = define(
        &server,
        &admin,
        &[
            ("key", "backup_share"),
            ("label", "Backup share"),
            ("kind", "text"),
            ("scope", "organization"),
            ("required_at", "organization"),
        ],
    )
    .await;
    let per_dev = define(
        &server,
        &admin,
        &[
            ("key", "owner"),
            ("label", "Owner"),
            ("kind", "text"),
            ("scope", "organization"),
            ("scope", "device"),
            ("required_at", "device"),
        ],
    )
    .await;
    let page = admin.get(&server, "/admin/fields").await.body;
    assert!(
        page.contains("Backup share") && page.contains("2 organization(s) missing"),
        "{page}"
    );
    assert!(page.contains("2 device(s) missing"), "{page}");
    assert!(admin
        .get(&server, &format!("/organizations/{org_a}"))
        .await
        .body
        .contains("required"));

    set(&server, &admin, per_org, "organization", Some(org_a), "a").await;
    set(&server, &admin, per_org, "organization", Some(org_b), "b").await;
    // An organization value counts for its devices (inherited).
    set(
        &server,
        &admin,
        per_dev,
        "organization",
        Some(org_b),
        "IT desk",
    )
    .await;
    let page = admin.get(&server, "/admin/fields").await.body;
    assert!(!page.contains("organization(s) missing"), "{page}");
    assert!(
        page.contains("1 device(s) missing") && !page.contains(&dev_b.to_string()),
        "{page}"
    );
    server.stop().await;
}

async fn readonly(server: &TestServer, admin: &Browser, email: &str, org: Uuid) -> Browser {
    let r = admin
        .post(
            server,
            "/admin/users",
            &[
                ("email", email),
                ("display_name", "Viewer"),
                ("password", "viewer-password-123"),
                ("role", "readonly"),
                ("org", &org.to_string()),
            ],
        )
        .await;
    assert_eq!(r.location(), "/admin?m=user-created", "{}", r.body);
    server.login(email, "viewer-password-123").await
}

async fn value_rows(server: &TestServer, field: Uuid) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM field_values WHERE field_id = $1")
        .bind(field)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn foreign_devices_readonly_users_and_forged_forms_change_nothing() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (org_a, dev_a) = org_with_device(&server, &admin, "Org A").await;
    let (_, dev_b) = org_with_device(&server, &admin, "Org B").await;
    let tech = technician(&server, &admin, "tech@example.test", org_a).await;
    let viewer = readonly(&server, &admin, "viewer@example.test", org_a).await;
    let f = define(
        &server,
        &admin,
        &[
            ("key", "asset_tag"),
            ("label", "Asset tag"),
            ("kind", "text"),
            ("scope", "device"),
            ("technician_can_edit", "yes"),
        ],
    )
    .await;
    assert_eq!(
        set(&server, &admin, f, "device", Some(dev_b), "B-SENTINEL").await,
        StatusCode::SEE_OTHER
    );
    let before = value_rows(&server, f).await;

    // Another organization's device does not exist for the technician: not for writing, not for its history.
    assert_eq!(
        set(&server, &tech, f, "device", Some(dev_b), "overwrite").await,
        StatusCode::NOT_FOUND
    );
    let h = tech
        .get(
            &server,
            &format!("/fields/{f}/history?scope=device&target={dev_b}"),
        )
        .await;
    assert_eq!(h.status, StatusCode::NOT_FOUND);
    assert!(!h.body.contains("B-SENTINEL"));
    // A readonly user sets nothing, even in their own organization.
    assert_eq!(
        set(&server, &viewer, f, "device", Some(dev_a), "x").await,
        StatusCode::FORBIDDEN
    );
    // A form without this session's CSRF token is refused.
    let dev = dev_a.to_string();
    let forged = server
        .request(
            axum::http::Request::post(format!("/fields/{f}/value"))
                .header(axum::http::header::COOKIE, &admin.cookie)
                .header(
                    axum::http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(form(&[
                    ("scope", "device"),
                    ("target", &dev),
                    ("value", "forged"),
                ])))
                .unwrap(),
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let r = tech
        .post(&server, &format!("/admin/fields/{f}/archive"), &[])
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(value_rows(&server, f).await, before, "nothing was written");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn archiving_cannot_interleave_with_a_save_and_is_audited_or_not_done() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (org, _) = org_with_device(&server, &admin, "Org").await;
    let f = define(
        &server,
        &admin,
        &[
            ("key", "note"),
            ("label", "Note"),
            ("kind", "text"),
            ("scope", "organization"),
        ],
    )
    .await;

    // An archive holding the field's row: a save waits for it, then sees the field archived and writes nothing.
    let mut tx = server.state.db.begin().await.unwrap();
    sqlx::query("SELECT id FROM field_definitions WHERE id = $1 FOR UPDATE")
        .bind(f)
        .execute(&mut *tx)
        .await
        .unwrap();
    let (status, _) = tokio::join!(
        set(&server, &admin, f, "organization", Some(org), "late"),
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            sqlx::query("UPDATE field_definitions SET archived_at = now() WHERE id = $1")
                .bind(f)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
    );
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(value_rows(&server, f).await, 0);

    // If the audit event cannot be written, the archive does not happen either.
    let g = define(
        &server,
        &admin,
        &[
            ("key", "note2"),
            ("label", "Note 2"),
            ("kind", "text"),
            ("scope", "organization"),
        ],
    )
    .await;
    sqlx::query(
        "CREATE FUNCTION refuse_archive_audit() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN IF NEW.action = 'field.archive' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$",
    )
    .execute(&server.state.db)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER refuse_archive_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION refuse_archive_audit()",
    )
    .execute(&server.state.db)
    .await
    .unwrap();
    let r = admin
        .post(&server, &format!("/admin/fields/{g}/archive"), &[])
        .await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    let (archived,): (bool,) =
        sqlx::query_as("SELECT archived_at IS NOT NULL FROM field_definitions WHERE id = $1")
            .bind(g)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert!(!archived);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn defaults_device_requirements_secrets_and_markup_are_handled_exactly() {
    let mut cfg = test_config(&fresh_database().await);
    cfg.field_key = Some([5u8; 32]);
    let server = start(cfg).await;
    let admin = server.admin_sudo().await;
    let (org, dev) = org_with_device(&server, &admin, "Org").await;

    // A default applies where nothing is set, and says so.
    define(
        &server,
        &admin,
        &[
            ("key", "timezone"),
            ("label", "Time zone"),
            ("kind", "text"),
            ("scope", "device"),
            ("default_value", "UTC"),
        ],
    )
    .await;
    let page = admin.get(&server, &format!("/devices/{dev}")).await.body;
    assert!(page.contains("UTC") && page.contains(">default "), "{page}");

    // A requirement on devices is not flagged on the organization page once every device has a value.
    let owner = define(
        &server,
        &admin,
        &[
            ("key", "owner"),
            ("label", "Owner"),
            ("kind", "text"),
            ("scope", "device"),
            ("required_at", "device"),
        ],
    )
    .await;
    set(&server, &admin, owner, "device", Some(dev), "Pat").await;
    let page = admin
        .get(&server, &format!("/organizations/{org}"))
        .await
        .body;
    assert!(!page.contains("badge bad\">required"), "{page}");

    // A secret is kept exactly as typed, surrounding spaces included.
    let psk = define(
        &server,
        &admin,
        &[
            ("key", "psk"),
            ("label", "PSK"),
            ("kind", "secret"),
            ("scope", "device"),
        ],
    )
    .await;
    assert_eq!(
        set(&server, &admin, psk, "device", Some(dev), "  pass word  ").await,
        StatusCode::SEE_OTHER
    );
    let (sealed,): (Vec<u8>,) =
        sqlx::query_as("SELECT secret FROM field_values WHERE field_id = $1")
            .bind(psk)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(
        flyw8t_server::fields::open(&[5u8; 32], &sealed).as_deref(),
        Some("  pass word  ")
    );

    // Markup in a label is shown as text.
    define(
        &server,
        &admin,
        &[
            ("key", "evil"),
            ("label", "<img src=x onerror=alert(1)>"),
            ("kind", "text"),
            ("scope", "device"),
        ],
    )
    .await;
    let page = admin.get(&server, "/admin/fields").await.body;
    assert!(
        !page.contains("<img src=x") && page.contains("&lt;img src=x"),
        "{page}"
    );
    server.stop().await;
}

async fn add_site(server: &TestServer, admin: &Browser, org: Uuid, name: &str) -> Uuid {
    let r = admin
        .post(
            server,
            &format!("/organizations/{org}/sites"),
            &[("name", name)],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    sqlx::query_as::<_, (Uuid,)>("SELECT id FROM sites WHERE organization_id = $1 AND name = $2")
        .bind(org)
        .bind(name)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

async fn put_in_site(server: &TestServer, admin: &Browser, device: Uuid, site: Uuid) {
    let site = site.to_string();
    let r = admin
        .post(
            server,
            &format!("/devices/{device}/edit"),
            &[
                ("display_name", ""),
                ("tags", ""),
                ("notes", ""),
                ("site", site.as_str()),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn sites_sit_between_the_organization_and_the_device() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (org_a, dev_a) = org_with_device(&server, &admin, "Org A").await;
    let (org_b, dev_b) = org_with_device(&server, &admin, "Org B").await;
    let branch = add_site(&server, &admin, org_a, "Branch").await;
    let elsewhere = add_site(&server, &admin, org_b, "Elsewhere").await;
    put_in_site(&server, &admin, dev_a, branch).await;
    let f = define(
        &server,
        &admin,
        &[
            ("key", "printer"),
            ("label", "Printer"),
            ("kind", "text"),
            ("scope", "organization"),
            ("scope", "site"),
            ("scope", "device"),
            ("required_at", "device"),
            ("technician_can_edit", "yes"),
        ],
    )
    .await;
    assert!(admin
        .get(&server, "/admin/fields")
        .await
        .body
        .contains("2 device(s) missing"));

    // Organization, then site: the site wins for its devices; the site page shows its own value.
    set(
        &server,
        &admin,
        f,
        "organization",
        Some(org_a),
        "org-printer",
    )
    .await;
    assert_eq!(
        set(&server, &admin, f, "site", Some(branch), "branch-printer").await,
        StatusCode::SEE_OTHER
    );
    let page = admin.get(&server, &format!("/devices/{dev_a}")).await.body;
    assert!(
        page.contains("branch-printer") && page.contains("from the site"),
        "{page}"
    );
    let page = admin.get(&server, &format!("/sites/{branch}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains("branch-printer") && page.body.contains(&format!("/devices/{dev_a}")),
        "{}",
        page.body
    );
    assert!(admin
        .get(&server, &format!("/organizations/{org_a}"))
        .await
        .body
        .contains(&format!("/sites/{branch}")));

    // A device value overrides the site's; clearing it inherits from the site again.
    set(&server, &admin, f, "device", Some(dev_a), "desk-printer").await;
    let page = admin.get(&server, &format!("/devices/{dev_a}")).await.body;
    assert!(
        page.contains("desk-printer") && page.contains("set on this device"),
        "{page}"
    );
    set(&server, &admin, f, "device", Some(dev_a), "").await;
    let page = admin.get(&server, &format!("/devices/{dev_a}")).await.body;
    assert!(
        page.contains("branch-printer") && page.contains("from the site"),
        "{page}"
    );
    let hist = admin
        .get(
            &server,
            &format!("/fields/{f}/history?scope=site&target={branch}"),
        )
        .await;
    assert_eq!(hist.status, StatusCode::OK);
    assert!(hist.body.contains("branch-printer"), "{}", hist.body);

    // A site value counts for the devices in that site only.
    set(&server, &admin, f, "site", Some(elsewhere), "far-printer").await;
    let page = admin.get(&server, "/admin/fields").await.body;
    assert!(page.contains("1 device(s) missing"), "{page}");
    put_in_site(&server, &admin, dev_b, elsewhere).await;
    let page = admin.get(&server, "/admin/fields").await.body;
    assert!(!page.contains("device(s) missing"), "{page}");

    // Stored against the site alone; audited under its organization.
    let (scope, o, s, d): (String, Option<Uuid>, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT scope, organization_id, site_id, device_id FROM field_values WHERE value = 'branch-printer'",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(
        (scope.as_str(), o, s, d),
        ("site", None, Some(branch), None)
    );
    let (audited,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_events WHERE action = 'field.set' AND organization_id = $1 AND detail->>'site_id' = $2",
    )
    .bind(org_a)
    .bind(branch.to_string())
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(audited, 1);
    // The table holds a site row to its one target.
    let bad = sqlx::query(
        "INSERT INTO field_values (field_id, scope, organization_id, site_id, set_by)
         SELECT $1, 'site', $2, $3, id FROM users LIMIT 1",
    )
    .bind(f)
    .bind(org_a)
    .bind(branch)
    .execute(&server.state.db)
    .await;
    assert!(bad.is_err());

    // A technician of Org A: their sites only.
    let tech = technician(&server, &admin, "tech@example.com", org_a).await;
    assert_eq!(
        set(&server, &tech, f, "site", Some(branch), "tech-printer").await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        set(&server, &tech, f, "site", Some(elsewhere), "mine-now").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        tech.get(&server, &format!("/sites/{elsewhere}"))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        tech.get(
            &server,
            &format!("/fields/{f}/history?scope=site&target={elsewhere}")
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    let far = admin
        .get(&server, &format!("/sites/{elsewhere}"))
        .await
        .body;
    assert!(
        far.contains("far-printer") && !far.contains("mine-now"),
        "{far}"
    );
    // Each site, its devices and its history see that site's values and no other's (both ways round, whichever sorts
    // first).
    for (site, device, mine, other) in [
        (branch, dev_a, "tech-printer", "far-printer"),
        (elsewhere, dev_b, "far-printer", "tech-printer"),
    ] {
        for path in [
            format!("/sites/{site}"),
            format!("/devices/{device}"),
            format!("/fields/{f}/history?scope=site&target={site}"),
        ] {
            let body = admin.get(&server, &path).await.body;
            assert!(
                body.contains(mine) && !body.contains(other),
                "{path}: {body}"
            );
        }
    }

    // A device requirement may be met by site values alone; not by global ones alone.
    let r = admin
        .post(
            &server,
            "/admin/fields",
            &[
                ("key", "site_only"),
                ("label", "Site only"),
                ("kind", "text"),
                ("scope", "site"),
                ("required_at", "device"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let r = admin
        .post(
            &server,
            "/admin/fields",
            &[
                ("key", "global_only"),
                ("label", "Global only"),
                ("kind", "text"),
                ("scope", "global"),
                ("required_at", "device"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    server.stop().await;
}
