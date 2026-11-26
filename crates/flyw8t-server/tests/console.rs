//! The console's working lists: the audit log with its filters, pages and export; the jobs list in pages; and
//! renaming organizations and sites. Every read keeps to the caller's organizations.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

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

/// Rows in the page's table.
fn rows(body: &str) -> usize {
    body.matches(r#"<td data-label="Action""#).count()
}

async fn seed(server: &TestServer, sql: &str) {
    sqlx::query(sql).execute(&server.state.db).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn device_activity_combines_scoped_audit_and_recorded_job_events() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin.create_org(&server, "Acme").await;
    let foreign = admin.create_org(&server, "Other organization").await;
    let tech = technician(&server, &admin, "tech@example.test", acme).await;
    let readonly = admin
        .post(
            &server,
            "/admin/users",
            &[
                ("email", "readonly@example.test"),
                ("display_name", "Read-only"),
                ("password", "readonly-password-123"),
                ("role", "readonly"),
                ("org", &acme.to_string()),
            ],
        )
        .await;
    assert_eq!(readonly.location(), "/admin?m=user-created");
    let readonly = server
        .login("readonly@example.test", "readonly-password-123")
        .await;
    let token = admin.enrollment_token(&server, acme, "60", "1").await;
    let agent = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let id = agent.device_id;
    let (stop, session) = agent.connect(&server.url());
    wait_connected(&server, id).await;
    let device_path = format!("/devices/{id}");
    let refresh = tech
        .post(
            &server,
            &format!("{device_path}/jobs"),
            &[("action", "system.info"), ("return_to_device", "yes")],
        )
        .await;
    let location = refresh.location();
    assert!(location.starts_with(&format!("{device_path}?m=inventory-queued&refresh=")));
    let job: Uuid = location.split_once("&refresh=").unwrap().1.parse().unwrap();
    wait_state(&server, job, "completed", Duration::from_secs(15)).await;
    let updated = tech.get(&server, &location).await;
    assert!(updated.body.contains("Refresh data"));
    assert!(updated
        .body
        .contains("Memory used, readings from oldest to newest"));
    stop.cancel();
    let _ = session.await.unwrap();

    sqlx::query("INSERT INTO audit_events (actor_type, actor_label, channel, organization_id, action, target_type, target_id, outcome)
                 VALUES ('user', 'foreign-event@example.test', 'web', $1, 'device.update', 'device', $2, 'success')")
        .bind(foreign).bind(id).execute(&server.state.db).await.unwrap();
    let path = format!("{device_path}/activity");
    assert!(admin.get(&server, &device_path).await.body.contains(&path));
    assert!(tech.get(&server, &device_path).await.body.contains(&path));
    assert!(!readonly
        .get(&server, &device_path)
        .await
        .body
        .contains(&path));
    let page = admin.get(&server, &path).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("Agent authenticated"));
    assert!(page.body.contains("Agent reported job completion"));
    assert!(page.body.contains("Job requested"));
    assert!(page.body.contains("tech@example.test"));
    assert!(page.body.contains(&format!("/jobs/{job}")));
    assert!(!page.body.contains("foreign-event@example.test"));
    let tech_activity = tech.get(&server, &path).await;
    assert_eq!(
        tech_activity.status,
        StatusCode::OK,
        "{}",
        tech_activity.body
    );
    assert!(tech_activity.body.contains("Agent reported job completion"));
    assert!(!tech_activity.body.contains("foreign-event@example.test"));
    assert_eq!(
        tech.get(&server, "/audit").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        readonly.get(&server, &path).await.status,
        StatusCode::FORBIDDEN
    );
    let foreign_token = admin.enrollment_token(&server, foreign, "60", "1").await;
    let foreign_agent = TestAgent::enroll(&server.url(), &foreign_token)
        .await
        .unwrap();
    assert_eq!(
        tech.get(
            &server,
            &format!("/devices/{}/activity", foreign_agent.device_id),
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        admin
            .get(&server, &format!("{path}?before=bad"))
            .await
            .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // The rows share a timestamp. The cursor must use their IDs, so exactly five of these
    // 55 events remain on the second page even when all of the timestamps compare equal.
    sqlx::query("INSERT INTO audit_events (actor_type, actor_label, channel, organization_id, action, target_type, target_id, outcome)
                 SELECT 'user', 'fixture-actor-' || n, 'web', $1, 'device.update', 'device', $2, 'success'
                   FROM generate_series(1, 55) n")
        .bind(acme).bind(id).execute(&server.state.db).await.unwrap();
    let page = admin.get(&server, &path).await;
    assert_eq!(page.body.matches("fixture-actor-").count(), 50);
    let older = extract(&page.body, r#"href="([^"]+/activity\?before=[^"]+)""#).unwrap();
    let page = admin.get(&server, &older).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(page.body.matches("fixture-actor-").count(), 5);
    assert!(page.body.contains("Job requested"));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn the_audit_log_filters_by_who_what_result_where_and_when() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let _acme = admin.create_org(&server, "Acme").await;
    let bolt = admin.create_org(&server, "Bolt").await;
    // A refused sign-in, by someone the console does not know.
    let r = server
        .request(
            server
                .login_request("Nobody@Example.com", "wrong-password-1")
                .await,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    seed(
        &server,
        "INSERT INTO audit_events (actor_type, actor_label, channel, action, outcome, at)
         VALUES ('system', 'system', 'system', 'test.old', 'success', '2020-03-04T12:00:00Z'),
                ('system', 'system', 'system', 'test.late', 'success', '2020-03-04T23:59:59Z'),
                ('system', 'system', 'system', 'test.next', 'success', '2020-03-05T00:00:00Z'),
                ('system', 'system', 'system', 'testXfill', 'success', now())",
    )
    .await;
    let get = |query: &str| {
        let (admin, server, path) = (&admin, &server, format!("/audit?{query}"));
        async move { admin.get(server, &path).await }
    };

    // What: an action, or the start of one.
    let page = get("action=organization.").await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(rows(&page.body), 2, "the two organizations made above");
    assert!(page.body.contains("organization.create"));
    assert!(!page.body.contains("user.login"));
    // The filter is text, not a pattern: `_` and `%` match only themselves.
    assert_eq!(rows(&get("action=test_fill").await.body), 0);
    assert_eq!(rows(&get("action=%25").await.body), 0);
    assert_eq!(rows(&get("action=testXfill").await.body), 1);
    assert!(get("action=test_fill")
        .await
        .body
        .contains("No events match."));

    // Who: part of the actor's label, in any case.
    let page = get("actor=NOBODY").await;
    assert_eq!(rows(&page.body), 1);
    assert!(page.body.contains("nobody@example.com"));
    assert_eq!(rows(&get("actor=%25").await.body), 0);

    // Result.
    let page = get("outcome=denied").await;
    assert!(rows(&page.body) >= 1);
    assert!(
        !page.body.contains(r#"class="badge good""#),
        "a success among the denied"
    );

    // Where.
    let page = get(&format!("org={bolt}")).await;
    assert_eq!(rows(&page.body), 1);
    assert!(page.body.contains("[Bolt]"));

    // When: whole UTC days, both ends included.
    assert_eq!(rows(&get("from=2020-03-04&to=2020-03-04").await.body), 2);
    assert_eq!(rows(&get("from=2020-03-05&to=2020-03-05").await.body), 1);
    assert_eq!(rows(&get("to=2020-03-04").await.body), 2);
    assert_eq!(rows(&get("from=2020-03-01&to=2020-03-03").await.body), 0);

    // Filters combine, and are shown back in the form.
    let page = get("action=test.&from=2020-03-05&to=2020-03-05").await;
    assert_eq!(rows(&page.body), 1);
    assert!(page.body.contains(r#"name="action" value="test.""#));
    assert!(page.body.contains(r#"name="from" value="2020-03-05""#));

    // The form's empty boxes are no filter; anything the page does not offer is refused.
    let page = get("actor=&action=&outcome=&org=&from=&to=").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(rows(&page.body) >= 7);
    for bad in [
        "from=yesterday",
        "to=2026-02-30",
        "outcome=maybe",
        "org=acme",
        "before=x",
    ] {
        assert_eq!(
            get(bad).await.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{bad}"
        );
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn the_audit_log_pages_back_through_everything_that_matches() {
    let server = start_fresh().await;
    let admin = server.admin().await;
    seed(
        &server,
        "INSERT INTO audit_events (actor_type, actor_label, channel, action, outcome, detail)
         SELECT 'system', 'system', 'system', 'test.fill', 'success', jsonb_build_object('n', n)
           FROM generate_series(1, 250) n",
    )
    .await;
    let mut path = "/audit?action=test.fill".to_string();
    let mut seen = Vec::new();
    for expected in [100, 100, 50] {
        let page = admin.get(&server, &path).await;
        assert_eq!(page.status, StatusCode::OK);
        assert_eq!(rows(&page.body), expected, "{path}");
        let re = regex_lite::Regex::new(r#"\{&quot;n&quot;:(\d+)\}|\{"n":(\d+)\}"#).unwrap();
        for c in re.captures_iter(&page.body) {
            let n: u32 = c.get(1).or(c.get(2)).unwrap().as_str().parse().unwrap();
            seen.push(n);
        }
        match extract(
            &page.body,
            r#"href="(/audit\?action=test\.fill&(?:amp;)?before=\d+)""#,
        ) {
            Some(next) => path = next.replace("&amp;", "&"),
            None => {
                assert_eq!(expected, 50, "only the last page has no older one");
                assert!(!page.body.contains("Older events"));
            }
        }
    }
    // Every event once, newest first.
    let newest_first: Vec<u32> = (1..=250).rev().collect();
    assert_eq!(seen, newest_first);
    // Exactly one page of matches offers no older page.
    let page = admin.get(&server, "/audit?action=user.").await;
    assert!(rows(&page.body) < 100);
    assert!(!page.body.contains("Older events"));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn the_audit_export_holds_the_filtered_events_and_cannot_run_as_a_formula() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin.create_org(&server, "Acme").await;
    seed(
        &server,
        r#"INSERT INTO audit_events (actor_type, actor_label, channel, action, outcome, client_ip, credential, detail)
           VALUES ('device', '=HYPERLINK("http://x.example","open")', 'agent', 'test.formula', 'denied',
                   '203.0.113.9', 'session:abcd1234', '{"note": "a, b"}')"#,
    )
    .await;
    seed(
        &server,
        "INSERT INTO audit_events (actor_type, actor_label, channel, action, outcome)
         SELECT 'system', 'system', 'system', 'test.many', 'success' FROM generate_series(1, 10050)",
    )
    .await;

    let r = admin.get(&server, "/audit.csv?action=test.formula").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["content-type"], "text/csv; charset=utf-8");
    let disposition = r.headers["content-disposition"].to_str().unwrap();
    assert!(
        regex_lite::Regex::new(r#"^attachment; filename="flyw8t-audit-\d{8}-\d{6}\.csv"$"#)
            .unwrap()
            .is_match(disposition),
        "{disposition}"
    );
    let lines: Vec<&str> = r.body.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines[0],
        "id,at,actor,channel,credential,client_ip,action,target_type,target_id,outcome,organization,detail"
    );
    assert_eq!(lines.len(), 2, "{}", r.body);
    assert!(
        lines[1].contains(r#","'=HYPERLINK(""http://x.example"",""open"")","agent","session:abcd1234","203.0.113.9","test.formula","#),
        "{}",
        lines[1]
    );
    assert!(
        lines[1].ends_with(r#","denied","","{""note"":""a, b""}""#),
        "{}",
        lines[1]
    );

    // Taking a copy is recorded, with what was asked for and how much was given.
    let (detail,): (Value,) = sqlx::query_as(
        "SELECT detail FROM audit_events WHERE action = 'audit.export' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(detail["events"], 1);
    assert_eq!(detail["truncated"], false);
    assert_eq!(detail["filters"], "action=test.formula");

    // At most 10,000 events, and the record says the file is not everything.
    let r = admin.get(&server, "/audit.csv?action=test.many").await;
    let lines = r.body.split("\r\n").filter(|l| !l.is_empty()).count();
    assert_eq!(lines, 10_001, "the header and 10,000 events");
    let (detail,): (Value,) = sqlx::query_as(
        "SELECT detail FROM audit_events WHERE action = 'audit.export' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(detail["events"], 10_000);
    assert_eq!(detail["truncated"], true);

    // Whatever someone who has not signed in calls themselves is kept short, so the log cannot be stuffed.
    let long = format!("{}@example.com", "a".repeat(5000));
    let r = server
        .request(server.login_request(&long, "wrong-password-1").await)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let (longest,): (i32,) = sqlx::query_as("SELECT max(length(actor_label)) FROM audit_events")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(longest, 254);

    // The audit log, on the page or as a file, is for those allowed to read it.
    let tech = technician(&server, &admin, "tech@example.com", acme).await;
    assert_eq!(
        tech.get(&server, "/audit").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        tech.get(&server, "/audit.csv").await.status,
        StatusCode::FORBIDDEN
    );
    server.stop().await;
}

/// An organization with one enrolled device that never connects, and one job for it.
async fn org_with_job(server: &TestServer, admin: &Browser, name: &str) -> (Uuid, Uuid) {
    let org = admin.create_org(server, name).await;
    let token = admin.enrollment_token(server, org, "60", "1").await;
    let agent = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let device = agent.device_id;
    std::mem::forget(agent);
    let job = admin
        .run(server, device, &[("action", "net.ipconfig")])
        .await;
    (org, job)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn the_jobs_list_pages_through_every_job_in_scope() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (acme, job) = org_with_job(&server, &admin, "Acme").await;
    let (_bolt, _) = org_with_job(&server, &admin, "Bolt").await;
    // 229 more finished jobs for Acme's device, each a second older; every tenth is another action.
    sqlx::query(
        "INSERT INTO jobs
         SELECT (jsonb_populate_record(j, jsonb_build_object(
                    'id', gen_random_uuid(),
                    'state', 'completed',
                    'created_at', j.created_at - make_interval(secs => n),
                    'terminal_at', j.created_at,
                    'action', CASE WHEN n % 10 = 0 THEN 'system.info' ELSE 'net.ipconfig' END))).*
           FROM jobs j, generate_series(1, 229) n WHERE j.id = $1",
    )
    .bind(job)
    .execute(&server.state.db)
    .await
    .unwrap();
    let job_rows = |body: &str| body.matches(r#"<td data-label="Job""#).count();

    // 231 jobs in all: 100, 100, 31.
    let first = admin.get(&server, "/jobs").await;
    assert_eq!(job_rows(&first.body), 100);
    assert!(
        first.body.contains(r#"href="/jobs?page=2""#),
        "an older page is offered"
    );
    assert!(!first.body.contains(">Newer<"));
    let second = admin.get(&server, "/jobs?page=2").await;
    assert_eq!(job_rows(&second.body), 100);
    assert!(second.body.contains(r#"href="/jobs?page=1""#));
    assert!(second.body.contains(r#"href="/jobs?page=3""#));
    let third = admin.get(&server, "/jobs?page=3").await;
    assert_eq!(job_rows(&third.body), 31);
    assert!(!third.body.contains(">Older<"));
    // No job appears on two pages.
    let ids = |body: &str| -> Vec<String> {
        regex_lite::Regex::new(r#"href="/jobs/([0-9a-f-]{36})""#)
            .unwrap()
            .captures_iter(body)
            .map(|c| c[1].to_string())
            .collect()
    };
    let mut all: Vec<String> = [&first, &second, &third]
        .iter()
        .flat_map(|p| ids(&p.body))
        .collect();
    assert_eq!(all.len(), 231);
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 231, "a job was shown twice");
    assert_eq!(job_rows(&admin.get(&server, "/jobs?page=4").await.body), 0);

    // An action narrows the list, and the page links keep it. Anything that is not a catalog action is no filter.
    let info = admin.get(&server, "/jobs?action=system.info").await;
    assert_eq!(job_rows(&info.body), 22);
    assert!(info
        .body
        .contains(r#"<option value="system.info" selected"#));
    let ip = admin
        .get(&server, "/jobs?action=net.ipconfig&state=completed")
        .await;
    assert_eq!(job_rows(&ip.body), 100);
    assert!(
        ip.body
            .contains("/jobs?page=2&amp;state=completed&amp;action=net.ipconfig")
            || ip
                .body
                .contains("/jobs?page=2&state=completed&action=net.ipconfig"),
        "the older page keeps the filters"
    );
    let unknown = admin.get(&server, "/jobs?action=rm+-rf").await;
    assert_eq!(job_rows(&unknown.body), 100);

    // A technician pages through their own organization's jobs only.
    let tech = technician(&server, &admin, "tech@example.com", acme).await;
    let mut total = 0;
    for page in 1..=3 {
        let p = tech.get(&server, &format!("/jobs?page={page}")).await;
        assert!(!p.body.contains("Bolt"));
        total += job_rows(&p.body);
    }
    assert_eq!(total, 230, "Acme's jobs, without Bolt's one");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn organizations_and_sites_are_renamed_by_administrators_and_keep_their_identity() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let acme = admin.create_org(&server, "Acme").await;
    let bolt = admin.create_org(&server, "Bolt").await;
    let (site,): (Uuid,) = sqlx::query_as("SELECT id FROM sites WHERE organization_id = $1")
        .bind(acme)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    let r = admin
        .post(
            &server,
            &format!("/organizations/{acme}/sites"),
            &[("name", "Depot")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let audit = |action: &'static str| {
        let server = &server;
        async move {
            sqlx::query_as::<_, (Option<Uuid>, Option<Uuid>, Value)>(
                "SELECT organization_id, target_id, detail FROM audit_events WHERE action = $1 ORDER BY id DESC LIMIT 1",
            )
            .bind(action)
            .fetch_one(&server.state.db)
            .await
            .unwrap()
        }
    };

    // The organization: same id, new name, old and new recorded.
    let r = admin
        .post(
            &server,
            &format!("/organizations/{acme}/rename"),
            &[("name", "  Acme Ltd ")],
        )
        .await;
    assert_eq!(
        r.location(),
        format!("/organizations/{acme}?m=org-renamed"),
        "{}",
        r.body
    );
    let page = admin.get(&server, &format!("/organizations/{acme}")).await;
    assert!(page.body.contains("<h1>Acme Ltd</h1>"), "{}", page.body);
    let (org, target, detail) = audit("organization.rename").await;
    assert_eq!((org, target), (Some(acme), Some(acme)));
    assert_eq!(
        detail,
        serde_json::json!({ "from": "Acme", "to": "Acme Ltd" })
    );
    // The same name again is not a change.
    let before = audit("organization.rename").await;
    admin
        .post(
            &server,
            &format!("/organizations/{acme}/rename"),
            &[("name", "Acme Ltd")],
        )
        .await;
    let (count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM audit_events WHERE action = 'organization.rename'")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(count, 1, "{before:?}");
    // Another organization's name, an empty one, an unknown organization.
    for (path, name, status) in [
        (
            format!("/organizations/{acme}/rename"),
            "Bolt",
            StatusCode::CONFLICT,
        ),
        (
            format!("/organizations/{acme}/rename"),
            "  ",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            format!("/organizations/{}/rename", Uuid::new_v4()),
            "Ghost",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let r = admin.post(&server, &path, &[("name", name)]).await;
        assert_eq!(r.status, status, "{path} {name:?}");
    }

    // The site.
    let r = admin
        .post(
            &server,
            &format!("/sites/{site}/rename"),
            &[("name", "Head office")],
        )
        .await;
    assert_eq!(
        r.location(),
        format!("/sites/{site}?m=site-renamed"),
        "{}",
        r.body
    );
    let page = admin.get(&server, &format!("/sites/{site}")).await;
    assert!(page.body.contains("<h1>Head office</h1>"), "{}", page.body);
    let (org, target, detail) = audit("site.rename").await;
    assert_eq!((org, target), (Some(acme), Some(site)));
    assert_eq!(
        detail,
        serde_json::json!({ "from": "Main", "to": "Head office" })
    );
    for (path, name, status) in [
        (
            format!("/sites/{site}/rename"),
            "Depot",
            StatusCode::CONFLICT,
        ),
        (
            format!("/sites/{site}/rename"),
            "",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            format!("/sites/{}/rename", Uuid::new_v4()),
            "Ghost",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let r = admin.post(&server, &path, &[("name", name)]).await;
        assert_eq!(r.status, status, "{path} {name:?}");
    }

    // Technicians see the names and are not offered, or allowed, the change. The CSRF token is required.
    let tech = technician(&server, &admin, "tech@example.com", acme).await;
    let page = tech.get(&server, &format!("/organizations/{acme}")).await;
    assert!(page.body.contains("Acme Ltd"));
    assert!(!page.body.contains("/rename"));
    for path in [
        format!("/organizations/{acme}/rename"),
        format!("/sites/{site}/rename"),
        format!("/organizations/{bolt}/rename"),
    ] {
        assert_eq!(
            tech.post(&server, &path, &[("name", "Mine")]).await.status,
            StatusCode::FORBIDDEN,
            "{path}"
        );
        let mut forged = admin.clone_for_test();
        forged.csrf = "x".repeat(43);
        assert_eq!(
            forged
                .post(&server, &path, &[("name", "Mine")])
                .await
                .status,
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    let (names,): (Vec<String>,) =
        sqlx::query_as("SELECT array_agg(name ORDER BY name) FROM organizations")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(names, ["Acme Ltd", "Bolt"]);
    server.stop().await;
}
