//! Script library: scripts and permanent revisions, diffs, downloads, the server's checks, saves that never lose text,
//! and who may read and edit what.

mod common;

use axum::http::StatusCode;
use common::*;
use uuid::Uuid;

async fn user(server: &TestServer, admin: &Browser, email: &str, role: &str, org: Uuid) -> Browser {
    let r = admin
        .post(
            server,
            "/admin/users",
            &[
                ("email", email),
                ("display_name", "Someone"),
                ("password", "user-password-123"),
                ("role", role),
                ("org", &org.to_string()),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    server.login(email, "user-password-123").await
}

/// Create a script; returns its id.
async fn create(
    server: &TestServer,
    who: &Browser,
    name: &str,
    scope: &str,
    language: &str,
) -> Uuid {
    let r = who
        .post(
            server,
            "/scripts",
            &[("name", name), ("scope", scope), ("language", language)],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    extract(&r.location(), r"/scripts/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap()
}

async fn save(
    server: &TestServer,
    who: &Browser,
    id: Uuid,
    base: i32,
    source: &str,
    params: &str,
) -> Response {
    who.post(
        server,
        &format!("/scripts/{id}/revisions"),
        &[
            ("base", &base.to_string()),
            ("source", source),
            ("parameters", params),
            ("risk_class", "C0"),
            ("note", ""),
        ],
    )
    .await
}

async fn revisions(server: &TestServer, id: Uuid) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM script_revisions WHERE script_id = $1")
        .bind(id)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn every_save_is_a_permanent_revision_with_its_hash_diff_and_file() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let id = create(&server, &admin, "Clear temp", "global", "powershell").await;

    let r = save(
        &server,
        &admin,
        id,
        0,
        "Write-Output 'one'\r\nWrite-Output 'two'\r\n",
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert!(r.location().ends_with("?m=script-saved"));
    let r = save(
        &server,
        &admin,
        id,
        1,
        "Write-Output 'one'\nWrite-Output 'TWO'\n",
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(revisions(&server, id).await, 2);

    // The same content again is not a new revision.
    let r = save(
        &server,
        &admin,
        id,
        2,
        "Write-Output 'one'\r\nWrite-Output 'TWO'\r\n",
        "",
    )
    .await;
    assert!(
        r.location().ends_with("?m=script-unchanged"),
        "{}",
        r.location()
    );
    assert_eq!(revisions(&server, id).await, 2);

    // Stored with one line ending, and the hash is of what is stored.
    let (source, hash): (String, Vec<u8>) = sqlx::query_as(
        "SELECT source, content_hash FROM script_revisions WHERE script_id = $1 AND number = 1",
    )
    .bind(id)
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(source, "Write-Output 'one'\nWrite-Output 'two'\n");
    assert_eq!(
        hash,
        flyw8t_server::scripts::content_hash(id, "powershell", "C0", "", &source).to_vec()
    );

    // Revisions are never changed or removed, even directly in the database.
    for sql in [
        "UPDATE script_revisions SET source = 'evil' WHERE script_id = $1",
        "DELETE FROM script_revisions WHERE script_id = $1",
    ] {
        let e = sqlx::query(sql).bind(id).execute(&server.state.db).await;
        assert!(e.is_err(), "{sql}");
    }
    assert!(sqlx::query("TRUNCATE script_revisions CASCADE")
        .execute(&server.state.db)
        .await
        .is_err());

    let page = admin.get(&server, &format!("/scripts/{id}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Revision 2"), "{}", page.body);
    assert!(page.headers[axum::http::header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .contains("script-src 'self'"));
    assert!(page.body.contains("/static/editor.js"));

    let diff = admin
        .get(&server, &format!("/scripts/{id}/revisions/2"))
        .await;
    assert_eq!(diff.status, StatusCode::OK);
    assert!(diff.body.contains("Changes from revision 1"));
    assert!(
        diff.body.contains("- Write-Output &#39;two&#39;")
            || diff.body.contains("- Write-Output 'two'"),
        "{}",
        diff.body
    );
    assert!(
        diff.body.contains("+ Write-Output &#39;TWO&#39;")
            || diff.body.contains("+ Write-Output 'TWO'")
    );
    assert!(
        !diff.body.contains("/static/editor.js"),
        "read-only pages load no script"
    );

    let file = admin
        .get(&server, &format!("/scripts/{id}/revisions/1/download"))
        .await;
    assert_eq!(file.status, StatusCode::OK);
    assert_eq!(file.body, "Write-Output 'one'\nWrite-Output 'two'\n");
    assert_eq!(
        file.headers[axum::http::header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        file.headers[axum::http::header::CONTENT_DISPOSITION],
        "attachment; filename=\"Clear_temp-r1.ps1\""
    );

    // The audit log records each revision by number and hash, never its text.
    let detail: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT action, detail FROM audit_events WHERE action LIKE 'script.%' ORDER BY id",
    )
    .fetch_all(&server.state.db)
    .await
    .unwrap();
    let actions: Vec<&str> = detail.iter().map(|(a, _)| a.as_str()).collect();
    assert_eq!(actions, ["script.create", "script.revise", "script.revise"]);
    assert_eq!(detail[1].1["sha256"], hex::encode(&hash));
    assert!(!detail
        .iter()
        .any(|(_, d)| d.to_string().contains("Write-Output")));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_save_that_cannot_be_made_keeps_the_text_typed() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let id = create(&server, &admin, "Inventory", "global", "bash").await;
    assert_eq!(
        save(&server, &admin, id, 0, "echo first\n", "")
            .await
            .status,
        StatusCode::SEE_OTHER
    );

    // Someone else saved revision 1 while this editor still had none: refused, with the text kept.
    let r = save(&server, &admin, id, 0, "echo mine </textarea><b>\n", "").await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    assert!(r.body.contains("Not saved"), "{}", r.body);
    assert!(
        r.body.contains("echo mine &lt;/textarea>&lt;b>"),
        "kept and escaped: {}",
        r.body
    );
    assert!(!r.body.contains("<b>"), "{}", r.body);
    assert!(
        r.body.contains("name=\"base\" value=\"1\""),
        "the next try is based on what is there now"
    );
    assert_eq!(revisions(&server, id).await, 1);

    // Too large: refused, text kept.
    let big = "x".repeat(256 * 1024 + 1);
    let r = save(&server, &admin, id, 1, &big, "").await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(r.body.contains("at most 256 KiB"));
    assert!(r.body.contains(&big[..1000]));
    assert_eq!(revisions(&server, id).await, 1);

    // At the limit it saves (the form, encoded, is larger than the console's usual body limit).
    let max = "y".repeat(256 * 1024);
    assert_eq!(
        save(&server, &admin, id, 1, &max, "").await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(revisions(&server, id).await, 2);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn checks_name_bad_parameters_missing_fields_and_placeholders() {
    let mut config = test_config(&fresh_database().await);
    config.script_checks = false;
    let server = start(config).await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Acme").await;
    let r = admin
        .post(
            &server,
            "/admin/fields",
            &[
                ("key", "backup_share"),
                ("label", "Backup share"),
                ("kind", "text"),
                ("scope", "organization"),
                ("required_at", "organization"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let id = create(&server, &admin, "Backup", &org.to_string(), "python").await;
    let r = save(
        &server,
        &admin,
        id,
        0,
        "print('{{ org.backup_share }}')\n",
        "Share = {{org.backup_share}}\nTag = {{device.asset_tag}}\nbad line\n",
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::SEE_OTHER,
        "drafts with problems are saved: {}",
        r.body
    );
    let page = admin.get(&server, &format!("/scripts/{id}")).await.body;
    assert!(
        page.contains("Syntax checks are turned off on this server."),
        "{page}"
    );
    assert!(
        page.contains("Parameters, line 2: </strong>No custom field is named asset_tag."),
        "{page}"
    );
    assert!(page.contains("Parameters, line 3: "), "{page}");
    assert!(
        page.contains("Script, line 1: </strong>Values are never put into the script text"),
        "{page}"
    );
    assert!(
        page.contains("Backup share (backup_share): 1 organization(s) without a value"),
        "{page}"
    );

    // Once Acme has its value, another organization lacking one is no concern of Acme's script; a global script that
    // reads the field still names it.
    let other = admin.create_org(&server, "Other").await;
    let (field,): (Uuid,) =
        sqlx::query_as("SELECT id FROM field_definitions WHERE key = 'backup_share'")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    let r = admin
        .post(
            &server,
            &format!("/fields/{field}/value"),
            &[
                ("scope", "organization"),
                ("target", &org.to_string()),
                ("value", "\\\\nas\\acme"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let page = admin.get(&server, &format!("/scripts/{id}")).await.body;
    assert!(!page.contains("without a value"), "{page}");
    let global = create(&server, &admin, "Backup everywhere", "global", "python").await;
    let r = save(
        &server,
        &admin,
        global,
        0,
        "print(1)\n",
        "Share = {{org.backup_share}}\n",
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let page = admin.get(&server, &format!("/scripts/{global}")).await.body;
    assert!(
        page.contains("Backup share (backup_share): 1 organization(s) without a value"),
        "{page}"
    );
    let _ = other;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn metadata_that_is_not_text_is_refused_not_a_server_error() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let id = create(&server, &admin, "Notes", "global", "bash").await;
    let r = admin
        .post(
            &server,
            &format!("/scripts/{id}/revisions"),
            &[
                ("base", "0"),
                ("source", "echo kept\n"),
                ("parameters", ""),
                ("risk_class", "C0"),
                ("note", "a\0b"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    assert!(r.body.contains("echo kept"), "the text is kept: {}", r.body);
    assert_eq!(revisions(&server, id).await, 0);
    for (name, description) in [("a\0b", ""), ("ok name", "x\0y")] {
        let r = admin
            .post(
                &server,
                "/scripts",
                &[
                    ("name", name),
                    ("scope", "global"),
                    ("language", "bash"),
                    ("description", description),
                ],
            )
            .await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{name:?} {description:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn technicians_edit_global_and_their_own_scripts_and_never_see_others() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org_a = admin.create_org(&server, "Org A").await;
    let org_b = admin.create_org(&server, "Org B").await;
    let other = create(&server, &admin, "B only", &org_b.to_string(), "bash").await;
    assert_eq!(
        save(&server, &admin, other, 0, "echo b\n", "").await.status,
        StatusCode::SEE_OTHER
    );

    let tech = user(&server, &admin, "tech@example.com", "technician", org_a).await;
    let global = create(&server, &tech, "Everywhere", "global", "bash").await;
    assert_eq!(
        save(&server, &tech, global, 0, "echo all\n", "")
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    let own = create(&server, &tech, "Mine", &org_a.to_string(), "bash").await;
    assert_eq!(
        save(&server, &tech, own, 0, "echo a\n", "").await.status,
        StatusCode::SEE_OTHER
    );

    // Another organization's script is not there for them, whichever way they ask.
    let r = tech
        .post(
            &server,
            "/scripts",
            &[
                ("name", "Sneak"),
                ("scope", &org_b.to_string()),
                ("language", "bash"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    for path in [
        format!("/scripts/{other}"),
        format!("/scripts/{other}/revisions/1"),
        format!("/scripts/{other}/revisions/1/download"),
    ] {
        assert_eq!(
            tech.get(&server, &path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    assert_eq!(
        save(&server, &tech, other, 1, "echo pwned\n", "")
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(revisions(&server, other).await, 1);
    let list = tech.get(&server, "/scripts").await.body;
    assert!(
        list.contains("Everywhere") && list.contains("Mine") && !list.contains("B only"),
        "{list}"
    );
    assert!(tech
        .get(&server, "/")
        .await
        .body
        .contains("href=\"/scripts\""));

    // Read-only users do not use the library.
    let ro = user(&server, &admin, "ro@example.com", "readonly", org_a).await;
    assert_eq!(
        ro.get(&server, "/scripts").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        ro.get(&server, &format!("/scripts/{global}")).await.status,
        StatusCode::FORBIDDEN
    );
    assert!(!ro
        .get(&server, "/")
        .await
        .body
        .contains("href=\"/scripts\""));

    // Names are unique per organization (and among global scripts), not across them.
    let r = tech
        .post(
            &server,
            "/scripts",
            &[
                ("name", "mine"),
                ("scope", &org_a.to_string()),
                ("language", "bash"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    create(&server, &admin, "Mine", &org_b.to_string(), "bash").await;
}

/// What a script reads at a level sees that level and those above it only, so missing values are counted there.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn missing_values_are_counted_at_the_level_a_script_reads() {
    let mut config = test_config(&fresh_database().await);
    config.script_checks = false;
    let server = start(config).await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Acme").await;
    let token = admin.enrollment_token(&server, org, "60", "1").await;
    let agent = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let device = agent.device_id;
    std::mem::forget(agent);
    let (site,): (Uuid,) = sqlx::query_as("SELECT id FROM sites WHERE organization_id = $1")
        .bind(org)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    let (site_s, device_s, org_s) = (site.to_string(), device.to_string(), org.to_string());
    let r = admin
        .post(
            &server,
            &format!("/devices/{device}/edit"),
            &[
                ("display_name", ""),
                ("tags", ""),
                ("notes", ""),
                ("site", &site_s),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    for (key, scopes) in [
        ("printer", ["site", "device"]),
        ("share", ["organization", "site"]),
    ] {
        let mut form = vec![
            ("key", key),
            ("label", key),
            ("kind", "text"),
            ("required_at", "device"),
        ];
        form.extend(scopes.iter().map(|s| ("scope", *s)));
        let r = admin.post(&server, "/admin/fields", &form).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    }
    let field = |key: &'static str| {
        let db = server.state.db.clone();
        async move {
            sqlx::query_as::<_, (Uuid,)>("SELECT id FROM field_definitions WHERE key = $1")
                .bind(key)
                .fetch_one(&db)
                .await
                .unwrap()
                .0
        }
    };
    // Every device has its own printer, and the site has a share: both requirements are met.
    for (key, scope, target) in [("printer", "device", &device_s), ("share", "site", &site_s)] {
        let r = admin
            .post(
                &server,
                &format!("/fields/{}/value", field(key).await),
                &[
                    ("scope", scope),
                    ("target", target.as_str()),
                    ("value", "x"),
                ],
            )
            .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    }
    assert!(!admin
        .get(&server, "/admin/fields")
        .await
        .body
        .contains("device(s) missing"));

    let script = create(&server, &admin, "Levels", &org_s, "python").await;
    let page = |params: &'static str| {
        let (server, admin) = (&server, &admin);
        async move {
            let n: (i32,) = sqlx::query_as(
                "SELECT coalesce(max(number), 0) FROM script_revisions WHERE script_id = $1",
            )
            .bind(script)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
            let r = save(server, admin, script, n.0, "print(1)\n", params).await;
            assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
            admin.get(server, &format!("/scripts/{script}")).await.body
        }
    };
    // A site-level read cannot see the device's printer; an organization-level read cannot see the site's share.
    let body = page("P = {{site.printer}}\n").await;
    assert!(
        body.contains("printer (printer): 1 site(s) without a value"),
        "{body}"
    );
    let body = page("S = {{org.share}}\n").await;
    assert!(
        body.contains("share (share): 1 organization(s) without a value"),
        "{body}"
    );
    // Read where the values are, nothing is missing.
    let body = page("P = {{device.printer}}\nS = {{site.share}}\nT = {{device.share}}\n").await;
    assert!(!body.contains("without a value"), "{body}");
    // A global read of a field with no global value or default.
    let body = page("S = {{global.share}}\n").await;
    assert!(
        body.contains("share (share): no global value or default"),
        "{body}"
    );
    server.stop().await;
}
