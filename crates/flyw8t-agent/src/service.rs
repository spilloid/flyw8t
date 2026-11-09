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

/// Where the service's program lives: `flyw8t\flyw8t-agent.exe` under Windows' Program Files folder.
pub fn install_path() -> Result<PathBuf> {
    Ok(crate::winsec::program_files()?
        .join("flyw8t")
        .join("flyw8t-agent.exe"))
}

/// Register the service to start automatically as LocalSystem, restarting on failure.
///
/// The service runs a copy of this program in Program Files, never the file `install` was run from: that is often a
/// download folder other accounts can write to, and whatever is there would run as SYSTEM. The copy is made from
/// `source`, a handle to this program opened when it started, so the file cannot be swapped by name in between. The
/// program folder is created owned by Administrators (Users may read and run it); an existing one must already be
/// exactly that and hold nothing but the agent. The state folder (which holds the device key) is never repaired:
/// it must be as `enroll` made it, or install refuses. Only the default state folder may be used: the folders above
/// a custom one are not checked, and could be swapped under a service running as SYSTEM.
pub fn install(state_dir: &std::path::Path, source: std::fs::File) -> Result<()> {
    use crate::winsec::{check_tree, ensure_dir, READABLE};
    let default = crate::config::default_state_dir()?;
    anyhow::ensure!(
        crate::config::is_default_state_dir(state_dir)?,
        "the service uses only the default state folder, {}; enroll without --state-dir (got {})",
        default.display(),
        state_dir.display()
    );
    // Windows' own spelling from here on.
    let state_dir = default.as_path();
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .context("opening the service manager (run as Administrator)")?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(_) => anyhow::bail!(
            "the {SERVICE_NAME} service is already installed; run `flyw8t-agent service uninstall` first"
        ),
        // Only "no such service" means it is absent; anything else (access denied, say) stops here.
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => {}
        Err(e) => return Err(e).context("checking whether the service is already installed"),
    }
    // %ProgramData%\flyw8t\agent: the flyw8t folder above it must be ours too.
    let state_root = state_dir.parent().context("state folder has no parent")?;
    check_tree(state_root, false).with_context(|| {
        format!(
            "{} is not as `enroll` made it (owned by Administrators, open only to SYSTEM and Administrators, no links). \
             Check what is in it, delete it, and enroll again",
            state_root.display()
        )
    })?;

    let exe = install_path()?;
    let program_dir = exe.parent().context("install path has no folder")?;
    anyhow::ensure!(
        ensure_dir(program_dir, READABLE)?,
        "run as Administrator: {} must be created owned by Administrators",
        program_dir.display()
    );
    for entry in std::fs::read_dir(program_dir)? {
        let name = entry?.file_name();
        anyhow::ensure!(
            name == "flyw8t-agent.exe",
            "{} holds {:?}, which flyw8t did not put there. Check it, delete the folder, and install again",
            program_dir.display(),
            name
        );
    }
    {
        let mut src = source;
        let mut dst =
            std::fs::File::create(&exe).with_context(|| format!("writing {}", exe.display()))?;
        std::io::copy(&mut src, &mut dst)?;
        dst.sync_all()?;
    }
    check_tree(program_dir, true)?;

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
    // Also when the service stops itself with an error (exit code 1), not only when it crashes.
    service.set_failure_actions_on_non_crash_failures(true)?;
    service
        .start::<OsString>(&[])
        .context("starting the service")?;
    Ok(())
}

/// Stop the service, wait until it has stopped, and remove it. The program and state folders are left in place.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while service.query_status()?.current_state != ServiceState::Stopped {
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "the service did not stop within 30 seconds"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    service.delete()?;
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

    let state_dir = STATE_DIR.get().cloned();
    let result = tokio::runtime::Runtime::new()?.block_on(async {
        let state_dir = match state_dir {
            Some(d) => d,
            None => crate::config::default_state_dir()?,
        };
        let cfg = crate::AgentConfig::load(&state_dir)?;
        let agent = crate::Agent::new(cfg)?;
        agent.run(shutdown).await.map_err(anyhow::Error::from)
    });
    // A nonzero exit makes the SCM apply the restart actions; a revoked credential is
    // reported the same way and will fail again on restart, visibly, in the agent's log
    // (`logs\agent.log` in the state directory). A crash shows in the System event log (7031).
    let code = if result.is_ok() { 0 } else { 1 };
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        code,
    ))?;
    result
}
