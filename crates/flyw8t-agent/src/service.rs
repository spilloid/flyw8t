//! Windows service integration: install, uninstall, and the service control loop.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "flyw8t-agent";
const DISPLAY_NAME: &str = "flyw8t Agent";
const DESCRIPTION: &str =
    "flyw8t remote monitoring and management agent (https://github.com/spilloid/flyw8t)";

static STATE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Register the service to start automatically as LocalSystem, restarting on failure, and
/// restrict the state directory (which holds the device key) to SYSTEM and Administrators.
pub fn install(state_dir: &std::path::Path) -> Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .context("opening the service manager (run as Administrator)")?;
    let exe = std::env::current_exe()?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            "service".into(),
            "run".into(),
            "--state-dir".into(),
            state_dir.as_os_str().to_os_string(),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("creating the service")?;
    service.set_description(DESCRIPTION)?;
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(10),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(60),
            },
        ]),
    })?;
    restrict_state_dir(state_dir)?;
    service
        .start::<OsString>(&[])
        .context("starting the service")?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
    }
    service.delete()?;
    Ok(())
}

/// Replace inherited permissions on the state directory with SYSTEM + Administrators only.
fn restrict_state_dir(dir: &std::path::Path) -> Result<()> {
    let status = std::process::Command::new("icacls")
        .arg(dir)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)F",
        ])
        .status()
        .context("running icacls")?;
    anyhow::ensure!(
        status.success(),
        "icacls failed to restrict {}",
        dir.display()
    );
    Ok(())
}

/// Hand control to the Service Control Manager. Blocks until the service stops.
pub fn run_dispatcher(state_dir: PathBuf) -> Result<()> {
    let _ = STATE_DIR.set(state_dir);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("starting service dispatcher")?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %format!("{e:#}"), "service failed");
    }
}

fn run_service() -> Result<()> {
    let shutdown = CancellationToken::new();
    let stop = shutdown.clone();
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let status = |state, accept, code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    ))?;

    let state_dir = STATE_DIR
        .get()
        .cloned()
        .unwrap_or_else(crate::config::default_state_dir);
    let result = tokio::runtime::Runtime::new()?.block_on(async {
        let cfg = crate::AgentConfig::load(&state_dir)?;
        let agent = crate::Agent::new(cfg)?;
        agent.run(shutdown).await.map_err(anyhow::Error::from)
    });
    // A nonzero exit makes the SCM apply the restart actions; a revoked credential is
    // reported the same way and will fail again on restart, visibly, in the event log.
    let code = if result.is_ok() { 0 } else { 1 };
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        code,
    ))?;
    result
}
