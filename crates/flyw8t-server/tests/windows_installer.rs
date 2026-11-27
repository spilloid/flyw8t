//! Verify the console-generated enrollment package and the Windows service on a disposable runner.
#![cfg(windows)]

mod common;
#[path = "common/intune_bundle.rs"]
mod intune_bundle;

use common::*;
use flyw8t_agent::{config, service, AgentConfig};
use flyw8t_protocol::{enrollment_package::EnrollmentPackage, messages::EnrollmentScope};
use reqwest::{header, StatusCode};
use std::{
    io::Cursor,
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

async fn run_as_system(executable: &Path, arguments: &str, description: &str) -> Output {
    // The task runs the EXE directly so LastTaskResult is the executable's real exit status.
    let mut command = powershell(
        r#"
$ErrorActionPreference = 'Stop'
$name = 'Flyw8t LocalSystem acceptance test ' + [Guid]::NewGuid()
$action = New-ScheduledTaskAction -Execute $env:FLYW8T_TEST_EXECUTABLE -Argument $env:FLYW8T_TEST_ARGUMENTS
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
                throw ('LocalSystem acceptance returned task result 0x{0:X8} ({0})' -f $info.LastTaskResult)
            }
            exit 0
        }
    } while ($timer.Elapsed.TotalSeconds -lt 135)
    throw 'LocalSystem acceptance exceeded its deadline.'
} finally {
    Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
}
"#,
    );
    command.env("FLYW8T_TEST_EXECUTABLE", executable);
    command.env("FLYW8T_TEST_ARGUMENTS", arguments);
    run_fixture_command(command, description).await
}

async fn verify_local_terminal_policy(
    server: &TestServer,
    admin: &Browser,
    exe: &Path,
    device: Uuid,
) {
    let path = format!("/devices/{device}/background-terminal/check");
    for (action, expected) in [
        (None, "disabled"),
        (Some("enable"), "enabled"),
        (Some("disable"), "disabled"),
    ] {
        if let Some(action) = action {
            let mut command = Command::new(exe);
            command.args(["terminal-policy", action]);
            let output = run_fixture_command(command, "changing local terminal policy").await;
            assert_success(&output, "changing local terminal policy");
        }
        let mut command = Command::new(exe);
        command.args(["terminal-policy", "status"]);
        let output = run_fixture_command(command, "reading local terminal policy").await;
        assert_success(&output, "reading local terminal policy");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            format!("Background terminal policy {expected} locally."),
        );
        let observed = admin.post(server, &path, &[]).await;
        assert_eq!(observed.status, StatusCode::OK);
        assert!(observed
            .body
            .contains(&format!("Local policy is {expected}")));
    }
}

async fn assert_intune_detection(detector: &Path, expect_detected: bool) {
    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ]);
    command.arg(detector);
    let output = run_fixture_command(command, "running the Intune detector").await;
    let (exit_code, response) = if expect_detected {
        (0, "Flyw8t enrollment detected")
    } else {
        (1, "")
    };
    assert_eq!(output.status.code(), Some(exit_code));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), response);
    assert!(output.stderr.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the service on a disposable Windows runner backed by PostgreSQL"]
async fn intune_package_enrolls_quietly_and_preserves_its_identity_on_retry() {
    let binary = PathBuf::from(
        std::env::var_os("FLYW8T_TEST_AGENT_BINARY").expect("path to the built Windows agent"),
    );
    let expect_signed = std::env::var("FLYW8T_TEST_EXPECT_SIGNED_INSTALL").as_deref() == Ok("1");
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
    let detector = temp.path().join("Detect-Flyw8t.ps1");
    let path = format!("/organizations/{org}/enrollment-tokens");
    let expected_detector = admin
        .post(
            &server,
            &path,
            &[
                ("site", &site.to_string()),
                ("download", "intune-detection"),
            ],
        )
        .await;
    assert_eq!(expected_detector.status, StatusCode::OK);

    let _ = rustls::crypto::ring::default_provider().install_default();
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}{path}", server.url()))
        .header(header::COOKIE, &admin.cookie)
        .header(header::ORIGIN, &server.state.config.public_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form(&[
            ("csrf", admin.csrf.as_str()),
            ("download", "intune"),
            ("site", &site.to_string()),
            ("ttl_minutes", "60"),
            ("max_uses", "1"),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=Flyw8t-Intune.zip"
    );
    let files = intune_bundle::unpack(&response.bytes().await.unwrap(), &expected_detector.body);
    let (original_length, _) = EnrollmentPackage::read(&mut Cursor::new(&files.installer))
        .unwrap()
        .expect("packaged executable is missing its enrollment trailer");
    assert_eq!(original_length, baseline.len() as u64);
    assert!(
        files.installer.starts_with(&baseline),
        "the bundled executable must embed the exact fixture binary"
    );
    std::fs::write(&package, files.installer).unwrap();
    std::fs::write(&detector, files.detector).unwrap();
    std::fs::write(temp.path().join("Uninstall-Flyw8t.cmd"), files.uninstall).unwrap();

    let first = run_as_system(&package, "--quiet", "LocalSystem quiet installation").await;
    assert_success(&first, "LocalSystem quiet installation");
    assert!(
        std::fs::read(&installed).unwrap() == baseline,
        "the service image contains only the original agent bytes"
    );
    let initial = AgentConfig::load(&state_dir).unwrap();
    assert_eq!(
        initial.enrollment_scope,
        Some(EnrollmentScope {
            organization_id: org,
            site_id: Some(site),
        })
    );
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
    assert_intune_detection(&detector, expect_signed).await;
    let terminal = run_as_system(
        &installed,
        "terminal-check --powershell --require-session-zero",
        "LocalSystem PowerShell check",
    )
    .await;
    assert_success(&terminal, "LocalSystem PowerShell check");
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
    let mut uninstall = Command::new("cmd.exe");
    uninstall
        .current_dir(temp.path())
        .args(["/d", "/c", "Uninstall-Flyw8t.cmd"]);
    let removed = run_fixture_command(uninstall, "running the Intune uninstall command").await;
    assert_success(&removed, "Intune uninstall");
    wait_for(
        "service record to be removed",
        Duration::from_secs(15),
        || async {
            service::status().is_ok_and(|state| state.is_none())
                && server.state.registry.connected_since(device).is_none()
        },
    )
    .await;
    assert_intune_detection(&detector, false).await;
    let saved = AgentConfig::load(&state_dir).unwrap();
    assert_eq!(saved.device_id, Some(device));
    assert_eq!(saved.enrollment_scope, initial.enrollment_scope);
    assert!(
        std::fs::read(saved.key_path()).unwrap() == key,
        "uninstall changed the device key"
    );
    let resumed = setup(&package, "--quiet").await;
    assert_success(&resumed, "quiet retry after service removal");
    wait_for(
        "reinstalled service to reconnect under the same device",
        Duration::from_secs(60),
        || async { server.state.registry.connected_since(device).is_some() },
    )
    .await;
    let current = AgentConfig::load(&state_dir).unwrap();
    assert_eq!(current.device_id, Some(device));
    assert_eq!(current.enrollment_scope, initial.enrollment_scope);
    assert!(
        std::fs::read(current.key_path()).unwrap() == key,
        "reinstall changed the device key"
    );
    assert_intune_detection(&detector, expect_signed).await;
    let uses: i32 =
        sqlx::query_scalar("SELECT uses FROM enrollment_tokens WHERE organization_id = $1")
            .bind(org)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(uses, 1);
    server.stop().await;
}
