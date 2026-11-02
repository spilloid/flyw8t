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
                ("notes", "Under the counter.\nAsk Pat first."),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(tags_of(&server, d).await, ["finance", "kiosk"]);
    let page = admin.get(&server, &format!("/devices/{d}")).await.body;
    assert!(page.contains("Front desk PC"));
    assert!(page.contains("Main office"));
    assert!(page.contains("Ask Pat first."));

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
    assert!(tags_of(&server, b[0]).await.is_empty());
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

    // "All shown" takes the filter, not a list of ticks.
    let r = admin
        .post(
            &server,
            "/devices/bulk",
            &[
                ("op", "tag-add"),
                ("tag", "ring-1"),
                ("all", "1"),
                ("tag_filter", "pilot"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
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
