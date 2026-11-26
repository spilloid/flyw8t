//! Real Windows agent executable, authenticated HTTP console, outbound agent socket and PostgreSQL.
#![cfg(windows)]

mod common;

use common::*;
use reqwest::{header, StatusCode};
use std::{path::PathBuf, time::Duration};
use tokio::process::Command;
use uuid::Uuid;

/// The English hosted runner's built-in session utility provides a second check for an
/// affirmative physical login. Never print its output, which contains account names.
async fn independently_observed_active_console() -> bool {
    let quser = PathBuf::from(std::env::var_os("SystemRoot").expect("Windows system root"))
        .join("System32")
        .join("quser.exe");
    let mut cmd = Command::new(quser);
    cmd.kill_on_drop(true);
    let Ok(Ok(output)) = tokio::time::timeout(Duration::from_secs(5), cmd.output()).await else {
        return false;
    };
    output.status.success()
        && String::from_utf8_lossy(&output.stdout).lines().any(|line| {
            let mut fields = line.split_whitespace();
            // USERNAME SESSIONNAME ID STATE ...; quser marks the current user with '>'.
            fields.next().is_some()
                && fields
                    .next()
                    .is_some_and(|s| s.eq_ignore_ascii_case("console"))
                && fields
                    .next()
                    .is_some_and(|s| s.parse::<u32>().is_ok_and(|id| id > 0))
                && fields
                    .next()
                    .is_some_and(|s| s.eq_ignore_ascii_case("active"))
        })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a real Windows agent executable and a disposable PostgreSQL database"]
async fn enrolled_windows_binary_answers_the_physical_console_form() {
    let binary = std::env::var_os("FLYW8T_TEST_AGENT_BINARY").expect("path to built Windows agent");
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let org = admin.create_org(&server, "Windows runner").await;
    let token = admin.enrollment_token(&server, org, "15", "1").await;
    let dir = tempfile::tempdir().unwrap();
    let mut enroll = Command::new(&binary);
    enroll
        .arg("--state-dir")
        .arg(dir.path())
        .args(["enroll", "--server"])
        .arg(server.url())
        .env("FLYW8T_ENROLL_TOKEN", token)
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(30), enroll.status())
        .await
        .expect("enrollment deadline")
        .expect("start agent enrollment");
    assert!(status.success(), "agent enrollment exited with {status}");
    let device = flyw8t_agent::AgentConfig::load(dir.path())
        .unwrap()
        .device_id
        .unwrap();
    let mut child = Command::new(&binary)
        .arg("--state-dir")
        .arg(dir.path())
        .arg("run")
        .env_remove("FLYW8T_ENROLL_TOKEN")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_connected(&server, device).await;
    // The service loop sends inventory before processing requests. Wait for that actual
    // startup milestone so a slow runner's inventory collection cannot consume the probe deadline.
    wait_for(
        "first real Windows inventory",
        Duration::from_secs(60),
        || async {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM inventory_snapshots WHERE device_id=$1)",
            )
            .bind(device)
            .fetch_one(&server.state.db)
            .await
            .unwrap()
        },
    )
    .await;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let page = format!("{}/devices/{device}", server.url());
    let form_page = http
        .get(&page)
        .header(header::COOKIE, &admin.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(form_page.status(), StatusCode::OK);
    let form_page = form_page.text().await.unwrap();
    assert!(form_page.contains(&format!("/devices/{device}/physical-console/check")));
    let csrf = extract(&form_page, r#"name="csrf" value="([^"]+)""#).expect("form CSRF");
    let active_before = independently_observed_active_console().await;
    let result = http
        .post(format!("{page}/physical-console/check"))
        .header(header::COOKIE, &admin.cookie)
        .header(header::ORIGIN, server.url())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form(&[("csrf", &csrf)]))
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    let html = result.text().await.unwrap();
    let rows: Vec<(String, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT action, (detail->>'request_id')::uuid, detail->>'status' FROM audit_events
         WHERE organization_id=$1 AND target_id=$2 AND actor_type='user' AND outcome='success'
           AND action IN ('device.physical_console.requested','device.physical_console.result') ORDER BY id",
    ).bind(org).bind(device).fetch_all(&server.state.db).await.unwrap();
    assert_eq!(rows.len(), 2, "one successful request and result");
    assert_eq!(rows[0].0, "device.physical_console.requested");
    assert_eq!(rows[1].0, "device.physical_console.result");
    assert!(!rows[0].1.is_nil());
    assert_eq!(rows[0].1, rows[1].1);
    assert!(rows[0].2.is_none());
    let state = rows[1].2.as_deref().unwrap();
    let active_after = independently_observed_active_console().await;
    let expected_text = match state {
        "active_console" => {
            assert!(
                active_before && active_after,
                "an active physical login needs independent Windows evidence"
            );
            "A user is signed in at the Windows physical console."
        }
        "no_interactive_user" | "no_console" => {
            assert!(
                !(active_before && active_after),
                "Windows independently reported a stable physical login"
            );
            if state == "no_console" {
                "Windows reported no attached physical console."
            } else {
                "Windows reported no active login at the physical console."
            }
        }
        "unavailable" => "Windows could not determine the physical console state.",
        other => panic!("the console received no valid observation from the agent: {other}"),
    };
    assert!(
        html.contains(expected_text),
        "audited and rendered observations differ"
    );
    println!("Enrolled Windows agent observation: {state}");
    child.kill().await.expect("stop the test agent");
    server.stop().await;
}
