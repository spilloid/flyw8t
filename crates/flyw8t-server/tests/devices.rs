//! Managing devices from the console: names, tags, notes, sites, retiring, and
//! changes to many devices at once, each scoped like a read.

mod common;

use axum::http::StatusCode;
use common::*;
use uuid::Uuid;

/// An organization with `n` enrolled (never connected) devices.
async fn org_with_devices(
    server: &TestServer,
    admin: &Browser,
    name: &str,
    n: usize,
) -> (Uuid, Vec<Uuid>) {
    let org = admin.create_org(server, name).await;
    let token = admin
        .enrollment_token(server, org, "60", &n.max(1).to_string())
        .await;
    let mut devices = Vec::new();
    for _ in 0..n {
        let agent = TestAgent::enroll(&server.url(), &token).await.unwrap();
        devices.push(agent.device_id);
        // The state directory is not needed: these devices never connect.
        std::mem::forget(agent);
    }
    (org, devices)
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
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    server.login(email, "tech-password-123").await
}

async fn tags_of(server: &TestServer, device: Uuid) -> Vec<String> {
    sqlx::query_as::<_, (String,)>("SELECT tag FROM device_tags WHERE device_id = $1 ORDER BY tag")
        .bind(device)
        .fetch_all(&server.state.db)
        .await
        .unwrap()
        .into_iter()
        .map(|(t,)| t)
        .collect()
}

async fn batch_jobs(server: &TestServer, batch: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM jobs WHERE batch_id = $1::uuid")
        .bind(batch)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_device_can_be_named_tagged_annotated_and_sited() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let (org, devices) = org_with_devices(&server, &admin, "Contoso", 1).await;
    let (other, _) = org_with_devices(&server, &admin, "Fabrikam", 0).await;
    let d = devices[0];
    for (o, site) in [(org, "Main office"), (other, "Elsewhere")] {
        let r = admin
            .post(
                &server,
                &format!("/organizations/{o}/sites"),
                &[("name", site)],
            )
            .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    }
    let site = |name: &'static str| {
        let db = server.state.db.clone();
        async move {
            sqlx::query_as::<_, (Uuid,)>("SELECT id FROM sites WHERE name = $1")
                .bind(name)
                .fetch_one(&db)
                .await
                .unwrap()
                .0
        }
    };
    let main = site("Main office").await.to_string();
    let elsewhere = site("Elsewhere").await.to_string();

    let r = admin
        .post(
            &server,
            &format!("/devices/{d}/edit"),
            &[
                ("display_name", "Front desk PC"),
                ("tags", "Kiosk, finance kiosk"),
                ("site", &main),
                (
                    "notes",
                    "Under the counter.\nAsk Pat first. </textarea><b>x</b>",
                ),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(tags_of(&server, d).await, ["finance", "kiosk"]);
    let page = admin.get(&server, &format!("/devices/{d}")).await.body;
    assert!(page.contains("Front desk PC"));
    assert!(page.contains("Main office"));
    assert!(page.contains("Ask Pat first."));
    // Notes are shown in a textarea (which Leptos does not escape) and as text: neither becomes markup.
    assert!(!page.contains("<b>x</b>"), "{page}");
    assert!(
        page.contains("Ask Pat first. &lt;/textarea>&lt;b>x&lt;/b></textarea>"),
        "{page}"
    );

    // Found by name, by tag, and by the tag filter; not by a tag it lacks.
    for q in [
        "/devices?q=front",
        "/devices?q=finance",
        "/devices?tag=kiosk",
    ] {
        assert!(
            admin.get(&server, q).await.body.contains(&d.to_string()),
            "{q}"
        );
    }
    assert!(!admin
        .get(&server, "/devices?tag=nope")
        .await
        .body
        .contains(&d.to_string()));

    // A site of another organization, and a malformed tag, are refused; nothing changes.
    for fields in [
        vec![("site", elsewhere.as_str()), ("tags", "kiosk")],
        vec![("site", ""), ("tags", "bad tag!")],
    ] {
        let r = admin
            .post(&server, &format!("/devices/{d}/edit"), &fields)
            .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{fields:?}");
    }
    assert_eq!(tags_of(&server, d).await, ["finance", "kiosk"]);

    // Removing a tag and clearing the name.
    let r = admin
        .post(
            &server,
            &format!("/devices/{d}/edit"),
            &[
                ("display_name", ""),
                ("tags", "kiosk"),
                ("site", ""),
                ("notes", ""),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(tags_of(&server, d).await, ["kiosk"]);
    assert!(!admin
        .get(&server, &format!("/devices/{d}"))
        .await
        .body
        .contains("Front desk PC"));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn device_changes_respect_organization_scope_and_role() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let (org_a, a) = org_with_devices(&server, &admin, "Org A", 1).await;
    let (_, b) = org_with_devices(&server, &admin, "Org B", 1).await;
    let tech = technician(&server, &admin, "tech@example.test", org_a).await;

    // Tags used only in another organization are not offered to them.
    let r = admin
        .post(
            &server,
            &format!("/devices/{}/edit", b[0]),
            &[("tags", "secret-b")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(!tech
        .get(&server, "/devices")
        .await
        .body
        .contains("secret-b"));
    assert!(admin
        .get(&server, "/devices")
        .await
        .body
        .contains("secret-b"));

    // Their own organization's device: allowed.
    let r = tech
        .post(
            &server,
            &format!("/devices/{}/edit", a[0]),
            &[("tags", "mine")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);

    // Another organization's device does not exist for them, alone or in a selection.
    let r = tech
        .post(
            &server,
            &format!("/devices/{}/edit", b[0]),
            &[("tags", "theirs")],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let (a0, b0) = (a[0].to_string(), b[0].to_string());
    let r = tech
        .post(
            &server,
            "/devices/bulk",
            &[
                ("op", "tag-add"),
                ("tag", "sneaky"),
                ("device", &a0),
                ("device", &b0),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(tags_of(&server, b[0]).await, ["secret-b"]);
    assert_eq!(
        tags_of(&server, a[0]).await,
        ["mine"],
        "nothing partly applied"
    );

    // Retiring is for administrators.
    let r = tech
        .post(
            &server,
            &format!("/devices/{}/retire", a[0]),
            &[("confirm", "yes")],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = tech
        .post(
            &server,
            "/devices/bulk",
            &[("op", "retire"), ("device", &a0)],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn many_devices_are_tagged_and_run_as_one_confirmed_batch() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let (_, devices) = org_with_devices(&server, &admin, "Contoso", 3).await;
    let ids: Vec<String> = devices.iter().map(Uuid::to_string).collect();
    let mut picked: Vec<(&str, &str)> = ids.iter().map(|i| ("device", i.as_str())).collect();

    let mut fields = picked.clone();
    fields.extend([("op", "tag-add"), ("tag", "Pilot")]);
    let r = admin.post(&server, "/devices/bulk", &fields).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    for d in &devices {
        assert_eq!(tags_of(&server, *d).await, ["pilot"]);
    }

    // "All shown" means the rows the page displayed, not the filter run again: a device
    // that was not shown is untouched even though it matches.
    let page = admin.get(&server, "/devices?tag=pilot").await.body;
    for i in &ids {
        assert!(
            page.contains(&format!(r#"name="shown" value="{i}""#)),
            "{i} shown"
        );
    }
    let r = admin
        .post(
            &server,
            "/devices/bulk",
            &[
                ("op", "tag-add"),
                ("tag", "ring-1"),
                ("all", "1"),
                ("shown", &ids[0]),
                ("shown", &ids[2]),
                ("tag_filter", "pilot"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(tags_of(&server, devices[0]).await, ["pilot", "ring-1"]);
    assert_eq!(
        tags_of(&server, devices[1]).await,
        ["pilot"],
        "not shown, not changed"
    );
    assert_eq!(tags_of(&server, devices[2]).await, ["pilot", "ring-1"]);

    // Running asks first, naming every device.
    let mut fields = picked.clone();
    fields.push(("op", "run"));
    let r = admin.post(&server, "/devices/bulk", &fields).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("Run on 3 devices"));
    for i in &ids {
        assert!(r.body.contains(i.as_str()));
    }

    // A count that does not match the selection is refused, and creates nothing.
    picked.extend([("action", "system.info"), ("confirm", "yes")]);
    let mut wrong = picked.clone();
    wrong.push(("count", "2"));
    let r = admin.post(&server, "/devices/bulk/run", &wrong).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let (jobs,): (i64,) = sqlx::query_as("SELECT count(*) FROM jobs")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(jobs, 0);

    // One retired device is skipped; the rest run as one batch.
    let r = admin
        .post(
            &server,
            &format!("/devices/{}/retire", devices[0]),
            &[("confirm", "yes")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let mut right = picked.clone();
    right.push(("count", "3"));
    let r = admin.post(&server, "/devices/bulk/run", &right).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let batch = extract(&r.location(), r"/jobs\?batch=([0-9a-f-]{36})").unwrap();
    assert_eq!(batch_jobs(&server, &batch).await, 2);
    let page = admin.get(&server, &r.location()).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains(&format!("Batch {}", &batch[..8])),
        "{}",
        page.body
    );

    // Someone outside the batch's organizations cannot see it.
    let (other, _) = org_with_devices(&server, &admin, "Other", 0).await;
    let tech = technician(&server, &admin, "tech@example.test", other).await;
    assert_eq!(
        tech.get(&server, &r.location()).await.status,
        StatusCode::NOT_FOUND
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn retired_devices_leave_the_active_list_and_never_move() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let (_, devices) = org_with_devices(&server, &admin, "Contoso", 2).await;
    let (other, _) = org_with_devices(&server, &admin, "Fabrikam", 0).await;
    let (keep, gone) = (devices[0], devices[1]);

    // Retiring needs the confirmation, revokes the credential, and hides the device.
    let r = admin
        .post(&server, &format!("/devices/{gone}/retire"), &[])
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let gone_s = gone.to_string();
    let r = admin
        .post(
            &server,
            "/devices/bulk",
            &[("op", "retire"), ("device", &gone_s)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Retire 1 devices"));
    let r = admin
        .post(
            &server,
            "/devices/bulk/retire",
            &[("device", &gone_s), ("count", "1"), ("confirm", "yes")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let (revoked,): (bool,) = sqlx::query_as(
        "SELECT bool_and(revoked_at IS NOT NULL) FROM device_credentials WHERE device_id = $1",
    )
    .bind(gone)
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert!(revoked);
    assert!(!admin.get(&server, "/devices").await.body.contains(&gone_s));
    assert!(admin
        .get(&server, "/devices?status=retired")
        .await
        .body
        .contains(&gone_s));
    let r = admin
        .post(
            &server,
            &format!("/devices/{gone}/jobs"),
            &[("action", "system.info")],
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::CONFLICT,
        "a retired device runs nothing"
    );

    // A device never moves between organizations: its history stays where it ran.
    let r = admin
        .post(
            &server,
            &format!("/devices/{keep}/move"),
            &[("organization", &other.to_string())],
        )
        .await;
    assert!(
        matches!(
            r.status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ),
        "{}",
        r.status
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_batch_is_all_or_nothing_and_its_totals_are_scoped() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let (org_a, a) = org_with_devices(&server, &admin, "Org A", 2).await;
    let (_, b) = org_with_devices(&server, &admin, "Org B", 1).await;
    let mut ids: Vec<String> = a.iter().chain(&b).map(Uuid::to_string).collect();
    ids.sort();
    let run = |ids: &[String], count: &str| {
        let mut f: Vec<(String, String)> =
            ids.iter().map(|i| ("device".into(), i.clone())).collect();
        f.extend([
            ("action".into(), "system.info".into()),
            ("confirm".into(), "yes".into()),
            ("count".into(), count.into()),
        ]);
        f
    };
    let post = |f: Vec<(String, String)>| {
        let (admin, server) = (&admin, &server);
        async move {
            let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            admin.post(server, "/devices/bulk/run", &f).await
        }
    };

    // The database refuses the last device's job: nothing of the batch survives.
    sqlx::query(&format!(
        "CREATE FUNCTION refuse_job() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN IF NEW.device_id = '{}' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$",
        ids[2]
    ))
    .execute(&server.state.db)
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER refuse_job BEFORE INSERT ON jobs FOR EACH ROW EXECUTE FUNCTION refuse_job()")
        .execute(&server.state.db)
        .await
        .unwrap();
    let r = post(run(&ids, "3")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    let (jobs,): (i64,) = sqlx::query_as("SELECT count(*) FROM jobs")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(jobs, 0, "no partial batch");
    sqlx::query("DROP TRIGGER refuse_job ON jobs")
        .execute(&server.state.db)
        .await
        .unwrap();

    // Across two organizations, someone who sees one sees only its part of the batch.
    let r = post(run(&ids, "3")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let batch = extract(&r.location(), r"batch=([0-9a-f-]{36})").unwrap();
    assert_eq!(batch_jobs(&server, &batch).await, 3);
    let tech = technician(&server, &admin, "tech@example.test", org_a).await;
    let page = tech.get(&server, &r.location()).await.body;
    assert!(
        page.contains(r#"<span class="num">2</span> jobs"#),
        "{page}"
    );
    assert!(page.contains(&a[0].to_string()) && page.contains(&a[1].to_string()));
    assert!(
        !page.contains(&b[0].to_string()),
        "another organization's job leaked"
    );

    // A retirement confirmed with the wrong count retires nothing.
    let b0 = b[0].to_string();
    let r = admin
        .post(
            &server,
            "/devices/bulk/retire",
            &[("device", &b0), ("count", "2"), ("confirm", "yes")],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let (retired,): (bool,) =
        sqlx::query_as("SELECT retired_at IS NOT NULL FROM devices WHERE id = $1")
            .bind(b[0])
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert!(!retired);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn retiring_disconnects_and_cannot_interleave_with_a_new_job() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Contoso").await;
    let token = admin.enrollment_token(&server, org, "60", "2").await;
    let live = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let racing = TestAgent::enroll(&server.url(), &token).await.unwrap();

    // A connected device is disconnected by retiring it.
    let (_stop, session) = live.connect(&server.url());
    for _ in 0..100 {
        if server
            .state
            .registry
            .connected_since(live.device_id)
            .is_some()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        server
            .state
            .registry
            .connected_since(live.device_id)
            .is_some(),
        "connected"
    );
    let r = admin
        .post(
            &server,
            &format!("/devices/{}/retire", live.device_id),
            &[("confirm", "yes")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let ended = tokio::time::timeout(std::time::Duration::from_secs(10), session).await;
    assert!(ended.is_ok(), "the retired device's session was closed");
    assert!(server
        .state
        .registry
        .connected_since(live.device_id)
        .is_none());

    // A job requested while a retirement holds the device waits for it, then is refused.
    let mut tx = server.state.db.begin().await.unwrap();
    sqlx::query("SELECT id FROM devices WHERE id = $1 FOR UPDATE")
        .bind(racing.device_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let path = format!("/devices/{}/jobs", racing.device_id);
    let (r, _) = tokio::join!(
        admin.post(&server, &path, &[("action", "system.info")]),
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            sqlx::query("UPDATE devices SET retired_at = now() WHERE id = $1")
                .bind(racing.device_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
    );
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    server.stop().await;
}
