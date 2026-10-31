//! End-to-end tests: real server, real PostgreSQL, real agent executing real commands.
//! `cargo test -p flyw8t-server --test e2e -- --ignored` with FLYW8T_TEST_DATABASE_URL set.
//! Acceptance-test IDs refer to docs/acceptance-tests.md.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use std::time::Duration;
use uuid::Uuid;

const PG: &str = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL";

/// AT-01..AT-12, AT-15: the milestone vertical slice through the console.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn vertical_slice() {
    let _ = PG;
    let server = start_fresh().await;
    let (admin, org, agent) = enrolled(&server).await;

    // The device appears in inventory under the token's organization, never-connected.
    let (dev_org,): (Uuid,) = sqlx::query_as("SELECT organization_id FROM devices WHERE id = $1")
        .bind(agent.device_id)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(dev_org, org);
    let page = admin.get(&server, "/devices").await;
    assert!(page.body.contains("Never connected"), "{}", page.body);

    let (stop, task) = agent.connect(&server.url());
    wait_connected(&server, agent.device_id).await;
    let db = server.state.db.clone();
    let device = agent.device_id;
    wait_for("inventory", Duration::from_secs(15), || {
        let db = db.clone();
        async move {
            sqlx::query_as::<_, (i64,)>(
                "SELECT count(*) FROM inventory_snapshots WHERE device_id = $1",
            )
            .bind(device)
            .fetch_one(&db)
            .await
            .unwrap()
            .0 > 0
        }
    })
    .await;
    let page = admin.get(&server, &format!("/devices/{device}")).await;
    assert!(page.body.contains("Connected · live"));
    assert!(
        page.body.contains("Cached, not live"),
        "inventory must be labelled as cached"
    );
    assert!(page.body.contains("logical cores"));

    // A read-only diagnostic runs for real and its evidence is verified.
    let job = admin
        .run(&server, device, &[("action", "net.ipconfig")])
        .await;
    wait_state(&server, job, "completed", Duration::from_secs(30)).await;
    assert_eq!(
        job_state(&server, job).await,
        ("completed".into(), "verified".into())
    );
    let (stdout, exit): (Option<String>, Option<i32>) =
        sqlx::query_as("SELECT stdout, exit_code FROM jobs WHERE id = $1")
            .bind(job)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(exit, Some(0));
    // `ipconfig /all` says "IPv4"; `ip addr` says "inet".
    let out = stdout.unwrap().to_lowercase();
    assert!(
        out.contains("ipv4") || out.contains("inet"),
        "real adapter output expected: {out}"
    );
    let kinds = event_kinds(&server, job).await;
    for k in [
        "created",
        "authorized",
        "queued",
        "dispatched",
        "acknowledged",
        "started",
        "finished",
    ] {
        assert!(
            kinds.iter().any(|x| x == k),
            "missing lifecycle event {k}: {kinds:?}"
        );
    }
    let page = admin.get(&server, &format!("/jobs/{job}")).await;
    assert!(page.body.contains(">Succeeded<"));
    assert!(page.body.contains("Windows IP Configuration") || !cfg!(windows));

    // system.info: a structured result, verified, also recorded as inventory.
    let job2 = admin
        .run(&server, device, &[("action", "system.info")])
        .await;
    wait_state(&server, job2, "completed", Duration::from_secs(30)).await;
    assert_eq!(job_state(&server, job2).await.1, "verified");
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM inventory_snapshots WHERE device_id = $1 AND source = 'job'",
    )
    .bind(device)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(n, 1);

    // Audit history has the actors and actions.
    let audit = admin.get(&server, "/audit").await;
    for a in [
        "user.login",
        "organization.create",
        "enrollment_token.create",
        "device.enroll",
        "device.connect",
        "job.create",
    ] {
        assert!(audit.body.contains(a), "audit missing {a}");
    }
    // The history tables really are append-only.
    assert!(sqlx::query("UPDATE audit_events SET action = 'x'")
        .execute(&db)
        .await
        .is_err());
    assert!(sqlx::query("DELETE FROM job_events")
        .execute(&db)
        .await
        .is_err());

    stop.cancel();
    task.await.unwrap().unwrap();
    server.stop().await;
}

/// AT-13, AT-14: disconnect, queue while offline, reconnect; then a redelivered offer for an
/// already-finished job must not run again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn reconnect_and_duplicate_delivery_never_reexecutes() {
    let server = start_fresh().await;
    let (admin, _org, agent) = enrolled(&server).await;
    let device = agent.device_id;

    let (stop, task) = agent.connect(&server.url());
    wait_connected(&server, device).await;
    stop.cancel();
    task.await.unwrap().unwrap();
    let st = server.state.clone();
    wait_for("disconnect to register", Duration::from_secs(10), || {
        let st = st.clone();
        async move { st.registry.connected_since(device).is_none() }
    })
    .await;

    // Offline: the job is queued, not "sent".
    let job = admin
        .run(&server, device, &[("action", "net.ipconfig")])
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(job_state(&server, job).await.0, "queued");
    assert!(admin
        .get(&server, &format!("/jobs/{job}"))
        .await
        .body
        .contains(">Queued<"));

    // Reconnect: delivered and completed.
    let (stop, task) = agent.connect(&server.url());
    wait_state(&server, job, "completed", Duration::from_secs(30)).await;
    let (finished_first, started_first): (
        Option<time::OffsetDateTime>,
        Option<time::OffsetDateTime>,
    ) = sqlx::query_as("SELECT finished_at, started_at FROM jobs WHERE id = $1")
        .bind(job)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    stop.cancel();
    task.await.unwrap().unwrap();

    // Simulate a server that lost the device's acknowledgement (e.g. restored from a backup
    // taken mid-flight): the job is back to "dispatched", so the server offers it again.
    sqlx::query("UPDATE jobs SET state = 'dispatched', verification = 'pending' WHERE id = $1")
        .bind(job)
        .execute(&server.state.db)
        .await
        .unwrap();
    let (stop, task) = agent.connect(&server.url());
    wait_state(&server, job, "completed", Duration::from_secs(30)).await;
    let (finished_again, started_again, dispatches): (
        Option<time::OffsetDateTime>,
        Option<time::OffsetDateTime>,
        i32,
    ) = sqlx::query_as("SELECT finished_at, started_at, dispatch_count FROM jobs WHERE id = $1")
        .bind(job)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    // The device answered from its journal: identical timestamps, so nothing ran twice.
    assert_eq!(finished_first, finished_again);
    assert_eq!(started_first, started_again);
    assert!(dispatches >= 2, "the offer really was redelivered");
    let kinds = event_kinds(&server, job).await;
    assert!(kinds.iter().any(|k| k == "redelivered"), "{kinds:?}");
    assert_eq!(
        kinds.iter().filter(|k| *k == "started").count(),
        1,
        "device must report one start: {kinds:?}"
    );
    stop.cancel();
    task.await.unwrap().unwrap();
    server.stop().await;
}

/// AT-16: the agent dies mid-execution. The job becomes "outcome unknown" (never success,
/// never re-run), and the restarted agent's report is what says so.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn agent_crash_mid_job_is_outcome_unknown_and_not_rerun() {
    let server = start_fresh().await;
    let (admin, _org, agent) = enrolled(&server).await;
    let device = agent.device_id;
    let process = agent.spawn_process(&server.url());
    wait_connected(&server, device).await;

    // TEST-NET-1 never answers, so this runs for several seconds.
    let job = admin
        .run(
            &server,
            device,
            &[("action", "net.ping"), ("target", "192.0.2.1")],
        )
        .await;
    wait_state(&server, job, "running", Duration::from_secs(15)).await;

    // Crash: every agent task (session, job, child process) dies at once.
    process.crash();
    let (stop2, task2) = agent.connect(&server.url());
    wait_state(&server, job, "outcome_unknown", Duration::from_secs(20)).await;
    let (note,): (Option<String>,) = sqlx::query_as("SELECT state_note FROM jobs WHERE id = $1")
        .bind(job)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert!(
        note.unwrap().contains("may or may not"),
        "the reason is recorded"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let kinds = event_kinds(&server, job).await;
    assert_eq!(
        kinds.iter().filter(|k| *k == "started").count(),
        1,
        "never restarted: {kinds:?}"
    );
    assert_eq!(job_state(&server, job).await.0, "outcome_unknown");
    assert!(admin
        .get(&server, &format!("/jobs/{job}"))
        .await
        .body
        .contains("Outcome unknown"));
    stop2.cancel();
    let _ = task2.await;
    server.stop().await;
}

/// AT-17: the server restarts with work queued; nothing is lost and it completes afterwards.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn server_restart_preserves_queued_work() {
    let db_url = fresh_database().await;
    let server = start(test_config(&db_url)).await;
    let (admin, _org, agent) = enrolled(&server).await;
    let job = admin
        .run(
            &server,
            agent.device_id,
            &[("action", "process.top"), ("limit", "5")],
        )
        .await;
    assert_eq!(job_state(&server, job).await.0, "queued");
    server.stop().await;

    let server = start(test_config(&db_url)).await;
    let (stop, task) = agent.connect(&server.url());
    wait_state(&server, job, "completed", Duration::from_secs(30)).await;
    assert_eq!(job_state(&server, job).await.1, "verified");
    stop.cancel();
    task.await.unwrap().unwrap();
    server.stop().await;
}

/// AT-18: cancel before dispatch guarantees no execution; cancel while running stops it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn cancellation_before_and_during_execution() {
    let server = start_fresh().await;
    let (admin, _org, agent) = enrolled(&server).await;
    let device = agent.device_id;

    let queued = admin
        .run(&server, device, &[("action", "net.ipconfig")])
        .await;
    let r = admin
        .post(&server, &format!("/jobs/{queued}/cancel"), &[])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        job_state(&server, queued).await,
        ("cancelled".into(), "not_applicable".into())
    );

    let (stop, task) = agent.connect(&server.url());
    wait_connected(&server, device).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        event_kinds(&server, queued)
            .await
            .iter()
            .filter(|k| *k == "dispatched")
            .count(),
        0,
        "a cancelled job is never sent"
    );

    let running = admin
        .run(
            &server,
            device,
            &[("action", "net.ping"), ("target", "192.0.2.1")],
        )
        .await;
    wait_state(&server, running, "running", Duration::from_secs(15)).await;
    admin
        .post(&server, &format!("/jobs/{running}/cancel"), &[])
        .await;
    wait_state(&server, running, "cancelled", Duration::from_secs(15)).await;
    let (note,): (Option<String>,) = sqlx::query_as("SELECT state_note FROM jobs WHERE id = $1")
        .bind(running)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert!(note.unwrap().contains("while running"));
    // A second cancel is refused rather than pretending to do something.
    assert_eq!(
        admin
            .post(&server, &format!("/jobs/{running}/cancel"), &[])
            .await
            .status,
        StatusCode::CONFLICT
    );
    stop.cancel();
    task.await.unwrap().unwrap();
    server.stop().await;
}

/// AT-19: a job whose device never connects expires, and says it did not run.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn undeliverable_job_expires_without_claiming_execution() {
    let mut cfg = test_config(&fresh_database().await);
    cfg.delivery_window = Duration::from_secs(1);
    let server = start(cfg).await;
    let (admin, _org, agent) = enrolled(&server).await;
    let job = admin
        .run(&server, agent.device_id, &[("action", "net.ipconfig")])
        .await;
    wait_state(&server, job, "expired", Duration::from_secs(10)).await;
    assert_eq!(job_state(&server, job).await.1, "not_applicable");
    assert!(admin
        .get(&server, &format!("/jobs/{job}"))
        .await
        .body
        .contains("It did not run"));
    server.stop().await;
}

/// AT-20: tenant isolation for a technician, and token scopes that only narrow.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn tenant_isolation_and_token_scopes() {
    let server = start_fresh().await;
    let (admin, org_a, agent_a) = enrolled(&server).await;
    let org_b = admin.create_org(&server, "Org B").await;
    let token_b = admin.enrollment_token(&server, org_b, "60", "1").await;
    let agent_b = TestAgent::enroll(&server.url(), &token_b).await.unwrap();

    let r = admin
        .post(
            &server,
            "/admin/users",
            &[
                ("email", "tech@example.test"),
                ("display_name", "Tech"),
                ("password", "tech-password-123"),
                ("role", "technician"),
                ("org", &org_a.to_string()),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let tech = server.login("tech@example.test", "tech-password-123").await;

    let list = tech.get(&server, "/devices").await;
    assert!(list.body.contains(&agent_a.device_id.to_string()));
    assert!(
        !list.body.contains(&agent_b.device_id.to_string()),
        "org B device leaked into org A technician's list"
    );
    assert_eq!(
        tech.get(&server, &format!("/devices/{}", agent_b.device_id))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let r = tech
        .post(
            &server,
            &format!("/devices/{}/jobs", agent_b.device_id),
            &[("action", "net.ipconfig")],
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "cross-tenant job creation must look like a missing device"
    );
    assert_eq!(
        tech.get(&server, "/admin").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        tech.get(&server, "/audit").await.status,
        StatusCode::FORBIDDEN
    );
    // A technician can still act inside their own organization.
    tech.run(&server, agent_a.device_id, &[("action", "net.ipconfig")])
        .await;

    // Missing or wrong CSRF token: refused.
    let mut forged = server.login("tech@example.test", "tech-password-123").await;
    forged.csrf = "forged".into();
    assert_eq!(
        forged
            .post(
                &server,
                &format!("/devices/{}/jobs", agent_a.device_id),
                &[("action", "net.ipconfig")]
            )
            .await
            .status,
        StatusCode::FORBIDDEN
    );

    // API token with only `read`: can list, cannot run.
    let r = admin
        .post(
            &server,
            "/admin/tokens",
            &[("name", "ro"), ("scope", "read"), ("ttl_days", "30")],
        )
        .await;
    let ro = extract(&r.body, r"(fw8_[A-Za-z0-9_-]{43})").expect("token revealed once");
    let r = server
        .api(Method::GET, "/api/v1/devices", &ro, None, None)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json().as_array().unwrap().len(), 2);
    let body = serde_json::json!({ "action": "net.ipconfig" });
    let r = server
        .api(
            Method::POST,
            &format!("/api/v1/devices/{}/jobs", agent_a.device_id),
            &ro,
            Some(body.clone()),
            Some("k1"),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // jobs:run token: needs an Idempotency-Key, and the same key returns the same job.
    let r = admin
        .post(
            &server,
            "/admin/tokens",
            &[
                ("name", "rw"),
                ("scope", "read"),
                ("scope", "jobs:run"),
                ("ttl_days", "30"),
            ],
        )
        .await;
    let rw = extract(&r.body, r"(fw8_[A-Za-z0-9_-]{43})").unwrap();
    let path = format!("/api/v1/devices/{}/jobs", agent_a.device_id);
    assert_eq!(
        server
            .api(Method::POST, &path, &rw, Some(body.clone()), None)
            .await
            .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let first = server
        .api(
            Method::POST,
            &path,
            &rw,
            Some(body.clone()),
            Some("same-key"),
        )
        .await;
    assert_eq!(first.status, StatusCode::ACCEPTED, "{}", first.body);
    let again = server
        .api(
            Method::POST,
            &path,
            &rw,
            Some(body.clone()),
            Some("same-key"),
        )
        .await;
    assert_eq!(first.json()["job_id"], again.json()["job_id"]);
    let other = serde_json::json!({ "action": "system.info" });
    assert_eq!(
        server
            .api(Method::POST, &path, &rw, Some(other), Some("same-key"))
            .await
            .status,
        StatusCode::CONFLICT
    );
    // Unknown actions never become jobs.
    let shell = serde_json::json!({ "action": "shell.exec", "params": { "cmd": "whoami" } });
    assert_eq!(
        server
            .api(Method::POST, &path, &rw, Some(shell), Some("k2"))
            .await
            .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // No token, bad token: 401.
    assert_eq!(
        server
            .api(Method::GET, "/api/v1/devices", "fw8_nope", None, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    server.stop().await;
}

/// AT-21: enrollment tokens are single-use, expire, and can be revoked; a revoked device
/// credential stops the device connecting.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn enrollment_and_device_revocation() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin.create_org(&server, "Acme").await;
    let token = admin.enrollment_token(&server, org, "60", "1").await;
    let agent = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let reuse = TestAgent::enroll(&server.url(), &token).await;
    assert!(
        reuse.unwrap_err().to_string().contains("refused"),
        "a single-use token works once"
    );
    assert!(TestAgent::enroll(&server.url(), "fw8e_not-a-real-token")
        .await
        .is_err());

    let expiring = admin.enrollment_token(&server, org, "15", "5").await;
    sqlx::query("UPDATE enrollment_tokens SET expires_at = now() - interval '1 second', created_at = now() - interval '1 hour' WHERE uses = 0")
        .execute(&server.state.db)
        .await
        .unwrap();
    assert!(
        TestAgent::enroll(&server.url(), &expiring).await.is_err(),
        "expired token refused"
    );

    let (stop, task) = agent.connect(&server.url());
    wait_connected(&server, agent.device_id).await;
    let r = admin
        .post(
            &server,
            &format!("/devices/{}/revoke", agent.device_id),
            &[("confirm", "yes")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let ended = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("revocation closes the live connection");
    assert!(ended.unwrap().is_err());
    stop.cancel();
    let err = agent
        .load(&server.url())
        .run_session(&tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("revoked"), "{err:#}");
    let job_attempt = admin
        .post(
            &server,
            &format!("/devices/{}/jobs", agent.device_id),
            &[("action", "net.ipconfig")],
        )
        .await;
    assert_eq!(job_attempt.status, StatusCode::CONFLICT);
    server.stop().await;
}

/// AT-22: the server UI and API refuse to claim liveness after the connection is gone.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn disconnected_device_is_not_shown_as_live() {
    let server = start_fresh().await;
    let (admin, _org, agent) = enrolled(&server).await;
    let (stop, task) = agent.connect(&server.url());
    wait_connected(&server, agent.device_id).await;
    stop.cancel();
    task.await.unwrap().unwrap();
    let st = server.state.clone();
    let id = agent.device_id;
    wait_for("disconnect", Duration::from_secs(10), || {
        let st = st.clone();
        async move { st.registry.connected_since(id).is_none() }
    })
    .await;
    let page = admin.get(&server, &format!("/devices/{id}")).await;
    assert!(!page.body.contains("Connected · live"));
    assert!(page.body.contains("Offline · seen"));
    server.stop().await;
}

/// ADR-0009 step 2: two server instances share one database. A job and a cancel created on B
/// reach a device connected to A at once, through the database's dispatch announcements.
/// Both sweepers are slowed to an hour, so only the announcement can deliver in time.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn work_created_on_one_instance_reaches_a_device_on_another() {
    let db = fresh_database().await;
    let slow = |url: &str| {
        let mut c = test_config(url);
        c.sweep_interval = Duration::from_secs(3600);
        c.redelivery_after = Duration::from_secs(3600);
        c
    };
    let a = start(slow(&db)).await;
    let b = start(slow(&db)).await;
    let (_admin_a, _org, agent) = enrolled(&a).await;
    let device = agent.device_id;
    let (stop, task) = agent.connect(&a.url());
    wait_connected(&a, device).await;
    assert!(
        b.state.registry.current_conn(device).is_none(),
        "the device is on A only"
    );

    let admin_b = b.admin().await;
    let job = admin_b.run(&b, device, &[("action", "net.ipconfig")]).await;
    wait_state(&b, job, "completed", Duration::from_secs(10)).await;

    let running = admin_b
        .run(
            &b,
            device,
            &[("action", "net.ping"), ("target", "192.0.2.1")],
        )
        .await;
    wait_state(&b, running, "running", Duration::from_secs(10)).await;
    let r = admin_b
        .post(&b, &format!("/jobs/{running}/cancel"), &[])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    wait_state(&b, running, "cancelled", Duration::from_secs(10)).await;

    stop.cancel();
    task.await.unwrap().unwrap();
    b.stop().await;
    a.stop().await;
}
