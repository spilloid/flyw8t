//! Verify the console-generated enrollment package and the Windows service on a disposable runner.
#![cfg(windows)]

mod common;

use common::*;
use flyw8t_agent::{config, service, AgentConfig};
use reqwest::{header, StatusCode};
use std::{
    path::{Path, PathBuf},
    process::Output,
    time::Duration,
};
use tokio::process::Command;
use uuid::Uuid;

struct Installation {
    state: PathBuf,
    program: PathBuf,
}

impl Drop for Installation {
    fn drop(&mut self) {
        if service::status().ok().flatten().is_some() {
            let _ = service::uninstall();
        }
        let _ = std::fs::remove_dir_all(&self.state);
        let _ = std::fs::remove_dir_all(&self.program);
    }
}

async fn setup(executable: &Path, flag: &str) -> Output {
    let mut command = Command::new(executable);
    command.arg(flag);
    run_fixture_command(command, "quiet setup").await
}

fn powershell(script: &str) -> Command {
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    command
}

async fn run_fixture_command(mut command: Command, description: &str) -> Output {
    command.kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(150), command.output())
        .await
        .unwrap_or_else(|_| panic!("{description} exceeded its deadline"))
        .unwrap_or_else(|error| panic!("could not start {description}: {error}"))
}

fn assert_success(output: &Output, description: &str) {
    assert!(
        output.status.success(),
        "{description} returned {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn setup_as_system(executable: &Path) -> Output {
    // Exercise the installer itself in the System context used by managed Windows deployments.
    // The task runs the EXE directly so LastTaskResult is the installer's real exit status.
    let mut command = powershell(
        r#"
$ErrorActionPreference = 'Stop'
$name = 'Flyw8t quiet installer test ' + [Guid]::NewGuid()
$action = New-ScheduledTaskAction -Execute $env:FLYW8T_TEST_PACKAGE_PATH -Argument '--quiet'
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 130)
Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
try {
    $previousRun = (Get-ScheduledTaskInfo -TaskName $name).LastRunTime
    Start-ScheduledTask -TaskName $name
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Milliseconds 250
        $info = Get-ScheduledTaskInfo -TaskName $name
        $state = (Get-ScheduledTask -TaskName $name).State
        # The task summary can still report Running or Has Not Yet Run while it catches up.
        $resultReady = $info.LastTaskResult -notin @(0x41301, 0x41303)
        if ($info.LastRunTime -ne $previousRun -and $state -eq 'Ready' -and $resultReady) {
            if ($info.LastTaskResult -ne 0) {
                throw ('LocalSystem quiet setup returned task result 0x{0:X8} ({0})' -f $info.LastTaskResult)
            }
            exit 0
        }
    } while ($timer.Elapsed.TotalSeconds -lt 135)
    throw 'LocalSystem quiet setup exceeded its deadline.'
} finally {
    Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
}
"#,
    );
    command.env("FLYW8T_TEST_PACKAGE_PATH", executable);
    run_fixture_command(command, "LocalSystem quiet setup").await
}

async fn verify_local_terminal_policy(
    server: &TestServer,
    admin: &Browser,
    exe: &Path,
    device: Uuid,
) {
    let path = format!("/devices/{device}/background-terminal/check");
    let default = admin.post(server, &path, &[]).await;
    assert_eq!(default.status, StatusCode::OK);
    assert!(default.body.contains("Local policy is disabled"));

    for (action, expected) in [
        ("enable", "Local policy is enabled"),
        ("disable", "Local policy is disabled"),
    ] {
        let mut command = Command::new(exe);
        command.args(["terminal-policy", action]);
        let output = run_fixture_command(command, "changing local terminal policy").await;
        assert_success(&output, "changing local terminal policy");
        let observed = admin.post(server, &path, &[]).await;
        assert_eq!(observed.status, StatusCode::OK);
        assert!(observed.body.contains(expected));
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the service on a disposable Windows runner backed by PostgreSQL"]
async fn quiet_windows_package_enrolls_at_its_site_and_retries_without_reenrolling() {
    let binary = PathBuf::from(
        std::env::var_os("FLYW8T_TEST_AGENT_BINARY").expect("path to the built Windows agent"),
    );
    let baseline = std::fs::read(&binary).unwrap();
    let state_dir = config::default_state_dir().unwrap();
    let state_root = state_dir.parent().unwrap();
    let installed = service::install_path().unwrap();
    assert!(
        service::status().unwrap().is_none(),
        "a disposable machine without the service is required"
    );
    assert!(
        !state_root.try_exists().unwrap() && !installed.parent().unwrap().try_exists().unwrap(),
        "a disposable machine without Flyw8t state is required"
    );

    let empty = setup(&binary, "--quiet").await;
    assert_eq!(empty.status.code(), Some(87));
    assert!(!state_root.exists());
    let _installation = Installation {
        state: state_root.to_owned(),
        program: installed.parent().unwrap().to_owned(),
    };

    // The package stores the configured public URL, so give the test server a real loopback port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = test_config(&fresh_database().await);
    config.bind = addr;
    config.public_url = format!("http://localhost:{}", addr.port());
    drop(listener);
    let server = start(config).await;
    server
        .state
        .windows_agent_template
        .set(baseline.clone())
        .unwrap();
    let admin = server.admin_sudo().await;
    let org = admin.create_org(&server, "Quiet setup fixture").await;
    let site: Uuid = sqlx::query_scalar(
        "INSERT INTO sites (organization_id, name) VALUES ($1, 'Deployment Lab') RETURNING id",
    )
    .bind(org)
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("Flyw8t-Setup-x64.exe");

    let _ = rustls::crypto::ring::default_provider().install_default();
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!(
            "{}/organizations/{org}/enrollment-tokens",
            server.url()
        ))
        .header(header::COOKIE, &admin.cookie)
        .header(header::ORIGIN, &server.state.config.public_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form(&[
            ("csrf", admin.csrf.as_str()),
            ("download", "windows"),
            ("site", &site.to_string()),
            ("ttl_minutes", "60"),
            ("max_uses", "1"),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    std::fs::write(&package, response.bytes().await.unwrap()).unwrap();

    let first = setup_as_system(&package).await;
    assert_success(&first, "LocalSystem quiet installation");
    assert_eq!(
        std::fs::read(&installed).unwrap(),
        baseline,
        "the service image contains only the original agent bytes"
    );
    let initial = AgentConfig::load(&state_dir).unwrap();
    let device = initial.device_id.unwrap();
    let key = std::fs::read(initial.key_path()).unwrap();
    let enrollment: (Uuid, Option<Uuid>) =
        sqlx::query_as("SELECT organization_id, site_id FROM devices WHERE id = $1")
            .bind(device)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(enrollment, (org, Some(site)));
    wait_for(
        "quietly installed service to connect",
        Duration::from_secs(60),
        || async { server.state.registry.connected_since(device).is_some() },
    )
    .await;
    verify_local_terminal_policy(&server, &admin, &installed, device).await;

    let repeated = setup(&package, "/quiet").await;
    assert_success(&repeated, "quiet retry");
    assert!(String::from_utf8_lossy(&repeated.stdout).contains("already installed and running"));

    let stop = powershell("Stop-Service -Name 'flyw8t-agent' -ErrorAction Stop");
    let stopped = run_fixture_command(stop, "stopping the installed service").await;
    assert_success(&stopped, "stopping the installed service");
    wait_for(
        "stopped service to disconnect",
        Duration::from_secs(15),
        || async { server.state.registry.connected_since(device).is_none() },
    )
    .await;
    let resumed = setup(&package, "--quiet").await;
    assert_success(&resumed, "quiet retry with a stopped service");
    wait_for(
        "restarted service to reconnect under the same device",
        Duration::from_secs(60),
        || async { server.state.registry.connected_since(device).is_some() },
    )
    .await;

    // The one-use package is spent. A service-only retry keeps the original identity and site.
    service::uninstall().unwrap();
    wait_for(
        "service record to be removed",
        Duration::from_secs(15),
        || async { service::status().is_ok_and(|state| state.is_none()) },
    )
    .await;
    let resumed = setup(&package, "--quiet").await;
    assert_success(&resumed, "quiet retry after service removal");
    let current = AgentConfig::load(&state_dir).unwrap();
    assert_eq!(current.device_id, Some(device));
    assert_eq!(std::fs::read(current.key_path()).unwrap(), key);
    let uses: i32 =
        sqlx::query_scalar("SELECT uses FROM enrollment_tokens WHERE organization_id = $1")
            .bind(org)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(uses, 1);
    server.stop().await;
}
