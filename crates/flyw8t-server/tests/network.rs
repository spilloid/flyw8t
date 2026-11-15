//! The real NetViz v1 contract, site isolation, stale evidence and native access handoff.
mod common;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use common::*;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

async fn site(server: &TestServer, admin: &Browser, org: Uuid, name: &str) -> Uuid {
    let r = admin
        .post(
            server,
            &format!("/organizations/{org}/sites"),
            &[("name", name)],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    sqlx::query_as::<_, (Uuid,)>("SELECT id FROM sites WHERE organization_id=$1 AND name=$2")
        .bind(org)
        .bind(name)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}
async fn register(server: &TestServer, admin: &Browser, site: Uuid, cidr: &str) -> (Uuid, String) {
    let r = admin
        .post(
            server,
            &format!("/sites/{site}/network-collectors"),
            &[
                ("name", "Office discovery"),
                ("cidr", cidr),
                ("interval_secs", "60"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let key = extract(&r.body, r"(fw8n_[A-Za-z0-9_-]{43})").expect("key shown once");
    let id = extract(&r.body, r"/network/collectors/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    (id, key)
}
async fn push(server: &TestServer, path: &str, key: &str, body: Value) -> Response {
    server
        .request(
            Request::post(path)
                .header("x-probe-key", key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
}
fn observation(ip: &str, mac: &str, at: OffsetDateTime) -> Value {
    json!({"id":"untrusted-source-id","ip":ip,"mac":mac,"hostname":"Office printer","vendor":"Example","os":"","deviceType":"printer","status":"up","openPorts":[80,443,9100],"firstSeen":at.format(&time::format_description::well_known::Rfc3339).unwrap(),"lastSeen":at.format(&time::format_description::well_known::Rfc3339).unwrap()})
}
async fn assets(server: &TestServer, site: Uuid) -> Vec<Uuid> {
    sqlx::query_as::<_, (Uuid,)>(
        "SELECT id FROM network_assets WHERE site_id=$1 ORDER BY first_seen_at,id",
    )
    .bind(site)
    .fetch_all(&server.state.db)
    .await
    .unwrap()
    .into_iter()
    .map(|r| r.0)
    .collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn netviz_identity_is_site_scoped_and_history_survives_address_changes() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Network customer").await;
    let one = site(&server, &admin, org, "Office").await;
    let two = site(&server, &admin, org, "Branch").await;
    let (collector, key) = register(&server, &admin, one, "192.168.1.0/24").await;
    let (_, key2) = register(&server, &admin, two, "192.168.1.0/24").await;
    let at = OffsetDateTime::now_utc() - Duration::minutes(1);
    let o = observation("192.168.1.20", "", at);
    for (k, expected) in [(&key, 1), (&key, 0), (&key2, 1)] {
        let r = push(&server, "/probe/devices", k, json!({"devices":[o.clone()]})).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert_eq!(r.json()["created"], expected);
    }
    let id = assets(&server, one).await[0];
    assert_ne!(id, assets(&server, two).await[0]);
    let with_mac = observation(
        "192.168.1.20",
        "02-AA-BB-CC-DD-EE",
        at + Duration::seconds(1),
    );
    let r = push(
        &server,
        "/probe/devices",
        &key,
        json!({"devices":[with_mac.clone()]}),
    )
    .await;
    assert_eq!(r.json()["updated"], 1);
    assert_eq!(assets(&server, one).await, [id]);
    let moved = observation(
        "192.168.1.21",
        "02:aa:bb:cc:dd:ee",
        at + Duration::seconds(2),
    );
    assert_eq!(
        push(&server, "/probe/devices", &key, json!({"devices":[moved]}))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        push(
            &server,
            "/probe/devices",
            &key,
            json!({"devices":[with_mac]})
        )
        .await
        .status,
        StatusCode::OK
    );
    let a = admin.get(&server, &format!("/network/assets/{id}")).await;
    assert_eq!(a.status, StatusCode::OK);
    assert!(a.body.contains("192.168.1.21"));
    assert!(!a.body.contains(&key));
    let (address,count):(String,i64)=sqlx::query_as("SELECT ip,(SELECT count(*) FROM network_observations WHERE asset_id=$1) FROM network_assets WHERE id=$1").bind(id).fetch_one(&server.state.db).await.unwrap();
    assert_eq!(address, "192.168.1.21");
    assert_eq!(count, 3);
    let saved_hash: Vec<u8> =
        sqlx::query_as::<_, (Vec<u8>,)>("SELECT token_hash FROM network_collectors WHERE id=$1")
            .bind(collector)
            .fetch_one(&server.state.db)
            .await
            .unwrap()
            .0;
    assert_eq!(saved_hash, flyw8t_server::auth::digest(&key));
    assert_eq!(
        sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM devices")
            .fetch_one(&server.state.db)
            .await
            .unwrap()
            .0,
        0,
        "Network assets must not become agent endpoints"
    );
    let r = admin.get(&server, "/network?site=&q=printer").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("2 matching assets"));
    let site_page = admin.get(&server, &format!("/sites/{one}")).await;
    assert!(site_page.body.contains("1 assets · 1 collectors"));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn collector_keys_cannot_choose_tenancy_or_escape_their_range() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Bound collector").await;
    let s = site(&server, &admin, org, "Office").await;
    let (collector, key) = register(&server, &admin, s, "192.168.1.0/24").await;
    for wrong in ["", "fw8_fake", "fw8n_wrong"] {
        assert_eq!(
            push(&server, "/probe/devices", wrong, json!({"devices":[]}))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    let good = observation("192.168.1.20", "", OffsetDateTime::now_utc());
    let bad = observation("192.168.2.20", "", OffsetDateTime::now_utc());
    let r = push(
        &server,
        "/probe/devices",
        &key,
        json!({"devices":[good.clone(),bad]}),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        assets(&server, s).await.is_empty(),
        "Whole batch must roll back"
    );
    let r = push(
        &server,
        "/probe/heartbeat",
        &key,
        json!({"cidr":"192.168.2.0/24","version":"v1"}),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = push(
        &server,
        "/probe/heartbeat",
        &key,
        json!({"cidr":"192.168.1.0/24","version":"v1","status":"online"}),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = push(
        &server,
        "/probe/devices",
        &key,
        json!({"organization_id":Uuid::new_v4(),"site_id":Uuid::new_v4(),"devices":[good]}),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let saved_org =
        sqlx::query_as::<_, (Uuid,)>("SELECT organization_id FROM network_assets WHERE site_id=$1")
            .bind(s)
            .fetch_one(&server.state.db)
            .await
            .unwrap()
            .0;
    assert_eq!(saved_org, org);
    let r = admin
        .post(
            &server,
            &format!("/network/collectors/{collector}/revoke"),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    for (path, body) in [
        ("/probe/devices", json!({"devices":[]})),
        (
            "/probe/heartbeat",
            json!({"cidr":"192.168.1.0/24","version":"v1"}),
        ),
    ] {
        assert_eq!(
            push(&server, path, &key, body).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        assets(&server, s).await.len(),
        1,
        "Revocation retains existing evidence"
    );
    let audit = admin.get(&server, "/audit").await;
    assert!(!audit.body.contains(&key));
    server.stop().await;
}

async fn user(server: &TestServer, admin: &Browser, org: Uuid, role: &str) -> Browser {
    let email = format!("{role}@example.test");
    let r = admin
        .post(
            server,
            "/admin/users",
            &[
                ("email", &email),
                ("display_name", role),
                ("password", "test-password-123"),
                ("role", role),
                ("org", &org.to_string()),
            ],
        )
        .await;
    assert_eq!(r.location(), "/admin?m=user-created", "{}", r.body);
    server.login(&email, "test-password-123").await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn every_network_view_and_change_obeys_organization_scope_and_csrf() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let one = admin.create_org(&server, "Visible customer").await;
    let two = admin.create_org(&server, "Other customer").await;
    let s1 = site(&server, &admin, one, "Office").await;
    let s2 = site(&server, &admin, two, "Other office").await;
    let (_, key1) = register(&server, &admin, s1, "192.168.1.0/24").await;
    let (c2, key2) = register(&server, &admin, s2, "192.168.1.0/24").await;
    let o = observation("192.168.1.20", "", OffsetDateTime::now_utc());
    for k in [&key1, &key2] {
        assert_eq!(
            push(&server, "/probe/devices", k, json!({"devices":[o.clone()]}))
                .await
                .status,
            StatusCode::OK
        );
    }
    let a1 = assets(&server, s1).await[0];
    let a2 = assets(&server, s2).await[0];
    let tech = user(&server, &admin, one, "technician").await;
    let read = user(&server, &admin, one, "readonly").await;
    let page = tech.get(&server, "/network").await;
    assert!(page.body.contains("Visible customer"));
    assert!(!page.body.contains("Other customer"));
    assert!(!page.body.contains(&a2.to_string()));
    for path in [
        format!("/network?site={s2}"),
        format!("/network/assets/{a2}"),
        format!("/network/collectors/{c2}"),
    ] {
        assert_eq!(
            tech.get(&server, &path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    for (path, fields) in [
        (
            format!("/sites/{s2}/network-collectors"),
            vec![("name", "Wrong site"), ("cidr", "192.168.1.0/24")],
        ),
        (
            format!("/network/collectors/{c2}/access"),
            vec![("portglass_fingerprint", "")],
        ),
        (format!("/network/collectors/{c2}/revoke"), vec![]),
        (format!("/network/assets/{a2}/open"), vec![("port", "80")]),
    ] {
        assert_eq!(
            tech.post(&server, &path, &fields).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    assert_eq!(
        read.post(
            &server,
            &format!("/sites/{s1}/network-collectors"),
            &[("name", "Denied"), ("cidr", "192.168.1.0/24")]
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        read.post(
            &server,
            &format!("/network/assets/{a1}/open"),
            &[("port", "80")]
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let read_page = read.get(&server, &format!("/network/assets/{a1}")).await;
    assert!(!read_page.body.contains("Review in PortGlass"));
    let r = server
        .request(
            Request::post(format!("/sites/{s1}/network-collectors"))
                .header(header::COOKIE, &tech.cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("name=Forged&cidr=192.168.1.0/24"))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn access_requires_fresh_evidence_a_web_port_and_an_unambiguous_address() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Access customer").await;
    let s = site(&server, &admin, org, "Office").await;
    let (c, key) = register(&server, &admin, s, "192.168.1.0/24").await;
    let at = OffsetDateTime::now_utc() - Duration::seconds(5);
    push(
        &server,
        "/probe/devices",
        &key,
        json!({"devices":[observation("192.168.1.20","02:aa:bb:cc:dd:ee",at)]}),
    )
    .await;
    let id = assets(&server, s).await[0];
    let path = format!("/network/assets/{id}/open");
    assert_eq!(
        admin.post(&server, &path, &[("port", "80")]).await.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "No configured probe"
    );
    let fp = "ab".repeat(32);
    assert_eq!(
        admin
            .post(
                &server,
                &format!("/network/collectors/{c}/access"),
                &[("portglass_fingerprint", &fp)]
            )
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    for port in ["0", "22", "8080", "443;whoami"] {
        assert_eq!(
            admin.post(&server, &path, &[("port", port)]).await.status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let r = admin.post(&server, &path, &[("port", "443")]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(
        r.body.contains(&format!(
            "portglass://connect?fingerprint={fp}&amp;target=192.168.1.20:443&amp;scheme=https"
        )),
        "{}",
        r.body
    );
    assert!(r.body.contains("does not confirm a connection"));
    let audit:Value=sqlx::query_as::<_,(Value,)>("SELECT detail FROM audit_events WHERE action='network.access_requested' ORDER BY id DESC LIMIT 1").fetch_one(&server.state.db).await.unwrap().0;
    assert_eq!(audit["outcome"], "handoff_only");
    push(&server,"/probe/devices",&key,json!({"devices":[observation("192.168.1.20","02:11:22:33:44:55",at+Duration::seconds(1))]})).await;
    assert_eq!(
        admin.post(&server, &path, &[("port", "80")]).await.status,
        StatusCode::CONFLICT,
        "Another asset now owns the address"
    );
    sqlx::query("UPDATE network_assets SET collected_at=now()-interval '1 hour' WHERE id=$1")
        .bind(id)
        .execute(&server.state.db)
        .await
        .unwrap();
    let detail = admin.get(&server, &format!("/network/assets/{id}")).await;
    assert!(detail.body.contains("Stale observation"));
    assert_eq!(
        admin.post(&server, &path, &[("port", "80")]).await.status,
        StatusCode::CONFLICT
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn collector_restart_does_not_make_missing_devices_offline_and_history_is_bounded() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "History customer").await;
    let s = site(&server, &admin, org, "Office").await;
    let (_, key) = register(&server, &admin, s, "192.168.1.0/24").await;
    let at = OffsetDateTime::now_utc() - Duration::minutes(2);
    for n in 0..105 {
        let r = push(
            &server,
            "/probe/devices",
            &key,
            json!({"devices":[observation("192.168.1.20","",at+Duration::seconds(n))]}),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
    let id = assets(&server, s).await[0];
    assert_eq!(
        sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM network_observations WHERE asset_id=$1")
            .bind(id)
            .fetch_one(&server.state.db)
            .await
            .unwrap()
            .0,
        100
    );
    assert_eq!(
        push(&server, "/probe/devices", &key, json!({"devices":[]}))
            .await
            .status,
        StatusCode::OK
    );
    let status: String =
        sqlx::query_as::<_, (String,)>("SELECT status FROM network_assets WHERE id=$1")
            .bind(id)
            .fetch_one(&server.state.db)
            .await
            .unwrap()
            .0;
    assert_eq!(
        status, "up",
        "Absence from a snapshot is not evidence of an offline device"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL and FLYW8T_NETVIZ_PROBE pointing to a built netviz-probe binary"]
async fn a_real_netviz_probe_reports_discovery_to_flyw8t() {
    // The probe is a separate product's binary. Where there is none (CI), this checks nothing and says so; it must
    // not fail the suite that runs every ignored test.
    let Ok(binary) = std::env::var("FLYW8T_NETVIZ_PROBE") else {
        eprintln!("SKIPPED: FLYW8T_NETVIZ_PROBE is not set to a built netviz-probe; the real probe was not exercised");
        return;
    };
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Loopback integration").await;
    let s = site(&server, &admin, org, "Lab").await;
    let (_, key) = register(&server, &admin, s, "127.0.0.1/32").await;
    let device = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("probe.json");
    std::fs::write(&config,json!({"version":1,"cidr":"127.0.0.1/32","anchordesk_url":server.url(),"probe_key":key,"interval":"60s"}).to_string()).unwrap();
    let output = tokio::process::Command::new(binary)
        .arg("-config")
        .arg(&config)
        .arg("-once")
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = assets(&server, s).await;
    assert_eq!(rows.len(), 1);
    let page = admin
        .get(&server, &format!("/network/assets/{}", rows[0]))
        .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("127.0.0.1"));
    assert!(page.body.contains("8080"));
    drop(device);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn ingest_has_a_bounded_route_specific_body_budget() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Batch budget customer").await;
    let s = site(&server, &admin, org, "Office").await;
    let (_, key) = register(&server, &admin, s, "192.168.1.0/24").await;
    let r = push(
        &server,
        "/probe/devices",
        &key,
        json!({"devices":[],"padding":"x".repeat(300*1024)}),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "The NetViz route accepts more than the normal 256 KiB budget"
    );
    let r = push(
        &server,
        "/probe/heartbeat",
        &key,
        json!({"cidr":"192.168.1.0/24","version":"v1","padding":"x".repeat(300*1024)}),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "Other routes keep their existing body budget"
    );
    let r = push(
        &server,
        "/probe/devices",
        &key,
        json!({"devices":[],"padding":"x".repeat(1024*1024)}),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let row = observation("192.168.1.20", "", OffsetDateTime::now_utc());
    let r = push(
        &server,
        "/probe/devices",
        &key,
        json!({"devices":vec![row;1025]}),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(assets(&server, s).await.is_empty());
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn wrong_collector_keys_are_budgeted_and_good_ones_are_not() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Budget").await;
    let s = site(&server, &admin, org, "Lab").await;
    let (_, key) = register(&server, &admin, s, "192.168.50.0/24").await;
    let beat = json!({"cidr":"192.168.50.0/24","version":"1.0"});
    // A working collector reports as often as it likes.
    for _ in 0..40 {
        let r = push(&server, "/probe/heartbeat", &key, beat.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
    // Thirty wrong keys are each refused; after that the address waits, on either endpoint, whatever key it sends.
    for n in 0..30 {
        let wrong = format!("fw8n_{n:043}");
        let r = push(&server, "/probe/heartbeat", &wrong, beat.clone()).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "guess {n}");
    }
    let r = push(
        &server,
        "/probe/heartbeat",
        "fw8n_another-guess",
        beat.clone(),
    )
    .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let r = push(
        &server,
        "/probe/devices",
        "fw8n_another-guess",
        json!({"devices":[]}),
    )
    .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let r = push(&server, "/probe/heartbeat", &key, beat).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    server.stop().await;
}
