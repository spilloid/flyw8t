use crate::windows_setup_mode::FINISH;
use anyhow::{ensure, Context, Result};
use flyw8t_agent::{config, identity::DeviceKey, service, winsec, AgentConfig};
use flyw8t_protocol::enrollment_package::EnrollmentPackage;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::ptr::{null, null_mut};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use windows_service::service::ServiceState;
use windows_sys::Win32::{
    Foundation::{
        ERROR_CANCELLED, ERROR_ELEVATION_REQUIRED, ERROR_INVALID_PARAMETER, HWND, LPARAM, LRESULT,
        WPARAM,
    },
    Graphics::Gdi::COLOR_BTNFACE,
    Storage::FileSystem::FILE_SHARE_READ,
    System::{
        Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE},
        Console::{GetConsoleProcessList, GetConsoleWindow},
        LibraryLoader::GetModuleHandleW,
    },
    UI::{Shell::*, WindowsAndMessaging::*},
};

const TITLE: &str = "Flyw8t Setup";

pub fn run_quiet(source: io::Result<File>) -> i32 {
    let package = source
        .context("Could not open the enrollment installer.")
        .and_then(|mut source| {
            let (length, package) = EnrollmentPackage::read(&mut source)?.context(
                "Use a Windows enrollment installer downloaded from your Flyw8t console.",
            )?;
            config::ws_url(&package.server_url)?;
            Ok((source, length, package))
        });
    let (source, length, package) = match package {
        Ok(package) => package,
        Err(error) => {
            eprintln!("{TITLE}: {error:#}");
            return ERROR_INVALID_PARAMETER as i32;
        }
    };
    if unsafe { IsUserAnAdmin() } == 0 {
        eprintln!("{TITLE}: Run quiet setup as SYSTEM or from an elevated administrator process.");
        return ERROR_ELEVATION_REQUIRED as i32;
    }
    match enroll_and_install(source, length, package, true, |text| {
        println!("{TITLE}: {text}")
    }) {
        Ok(detail) => {
            println!("{detail}");
            0
        }
        Err(error) => {
            eprintln!("{TITLE}: {error:#}");
            1
        }
    }
}

pub fn run(source: io::Result<File>, finish: bool) -> Result<()> {
    // Explorer creates a console for this executable. Preserve the caller's console for CLI use.
    unsafe {
        let mut process = 0;
        if GetConsoleProcessList(&mut process, 1) == 1 {
            ShowWindow(GetConsoleWindow(), SW_HIDE);
        }
    }
    let result = run_setup(source, finish);
    if let Err(ref error) = result {
        message(
            null_mut(),
            &format!("Setup could not finish.\n\n{error:#}"),
            MB_OK | MB_ICONERROR,
        );
    }
    result
}

fn run_setup(source: io::Result<File>, finish: bool) -> Result<()> {
    let mut source = source.context("Open the installer again from your Downloads folder.")?;
    let Some((original_length, package)) = EnrollmentPackage::read(&mut source)? else {
        message(null_mut(), "Get a Windows installer from Devices → Enroll a Windows device in your Flyw8t console. Choose an organization and site, then open the downloaded installer on this PC.", MB_OK | MB_ICONINFORMATION);
        return Ok(());
    };
    config::ws_url(&package.server_url)?;
    let destination = match &package.site {
        Some(site) => format!("{} · {site}", package.organization),
        None => package.organization.clone(),
    };
    if !finish && message(null_mut(), &format!(
        "Set up this PC for {destination}?\n\nConsole: {}\n\nSetup enrolls this PC and starts the Flyw8t Windows service. Windows may ask for administrator approval.",
        package.server_url,
    ), MB_YESNO | MB_ICONINFORMATION | MB_DEFBUTTON2) != IDYES {
        return Ok(());
    }
    if unsafe { IsUserAnAdmin() } == 0 {
        ensure!(
            !finish,
            "Administrator approval is required to enroll and install the service."
        );
        return elevate();
    }

    let progress = Progress::new(&destination)?;
    let (stages, stage) = mpsc::channel();
    let work = std::thread::spawn(move || {
        enroll_and_install(source, original_length, package, false, |text| {
            let _ = stages.send(text);
        })
    });
    while !work.is_finished() {
        for text in stage.try_iter() {
            progress.set_text(text);
        }
        progress.pump();
        std::thread::sleep(Duration::from_millis(25));
    }
    let result = work.join().map_err(|_| {
        anyhow::anyhow!(
            "Setup stopped unexpectedly. Check Flyw8t in Windows Services before trying again."
        )
    })?;
    match result {
        Ok(detail) => {
            message(progress.window, &detail, MB_OK | MB_ICONINFORMATION);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn elevate() -> Result<()> {
    let path = std::env::current_exe()?
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect::<Vec<_>>();
    let verb = wide("runas");
    let argument = wide(FINISH);
    let mut request = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: path.as_ptr(),
        lpParameters: argument.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    let com = unsafe {
        CoInitializeEx(
            null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    let result = if unsafe { ShellExecuteExW(&mut request) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    if com >= 0 {
        unsafe { CoUninitialize() };
    }
    if result
        .as_ref()
        .is_err_and(|error| error.raw_os_error() == Some(ERROR_CANCELLED as i32))
    {
        message(null_mut(), "Windows administrator approval was canceled. Open the installer again when you're ready.", MB_OK | MB_ICONINFORMATION);
        return Ok(());
    }
    result.context("Windows could not open setup with administrator privileges.")
}

fn enroll_and_install(
    source: File,
    original_length: u64,
    package: EnrollmentPackage,
    resume_enrollment: bool,
    mut stage: impl FnMut(&'static str),
) -> Result<String> {
    let state_dir = config::default_state_dir()?;
    if state_dir.try_exists()? {
        winsec::check_private_dir(state_dir.parent().context("state folder has no parent")?)?;
        winsec::check_private_dir(&state_dir)?;
    } else {
        super::prepare_state_dir(&state_dir)?;
    }
    let lock = state_dir.join("setup.lock");
    if lock.try_exists()? {
        winsec::check_private_file(&lock)?;
    }
    let _setup_lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .open(lock)
        .context("Another setup may already be running. Close it before trying again.")?;
    let cfg = AgentConfig {
        server_url: package.server_url,
        device_id: None,
        ca_cert_pem: None,
        state_dir,
    };
    let current_service = service::status()?;
    let state_dir = cfg.state_dir.clone();
    let config_path = cfg.state_dir.join("agent.json");
    let id = if config_path.try_exists()? || cfg.key_path().try_exists()? {
        winsec::check_private_file(&config_path)
            .context("Check the existing Flyw8t configuration before retrying setup.")?;
        winsec::check_private_file(&cfg.key_path())
            .context("Check the existing Flyw8t device key before retrying setup.")?;
        let existing = AgentConfig::load(&cfg.state_dir).context("This PC has existing Flyw8t state. Preserve its enrollment and check the agent configuration before retrying.")?;
        ensure!(existing.ws_url()? == cfg.ws_url()?, "This PC is enrolled with a different Flyw8t console. Open that console to manage the existing device.");
        let id = existing.device_id.context("The existing enrollment is incomplete. Preserve the files and follow agent recovery in the deployment guide.")?;
        DeviceKey::load(&existing.key_path()).context("The existing device key could not be read. Preserve the files and follow agent recovery in the deployment guide.")?;
        if current_service == Some(ServiceState::Running) {
            if resume_enrollment {
                service::resume_installation()?;
                wait_for_service()?;
            }
            return Ok("Flyw8t is already installed and running. Open Devices in your console to see this PC and its current site.".into());
        }
        ensure!(resume_enrollment, "This PC already has an enrollment. To keep its current site and identity, finish service setup using the signed agent and the deployment guide.");
        id
    } else {
        ensure!(current_service.is_none(), "The Flyw8t service already exists. Check it in Windows Services before enrolling this PC.");
        stage("Enrolling this PC with your Flyw8t console…");
        let (id, _) = super::runtime()?.block_on(async {
            tokio::time::timeout(Duration::from_secs(90), flyw8t_agent::enroll(cfg, &package.token)).await
        }).context("Setup timed out while enrolling. Check connectivity and look for this PC in Devices before retrying.")?
            .context("Enrollment failed. Verify the installer is still valid in the console and that this PC can reach it.")?;
        id
    };
    stage("Installing and starting the Windows service…");
    if current_service.is_some() {
        service::resume_installation().context("Could not resume the existing Flyw8t service.")?;
    } else {
        // Copy exactly the original release bytes so the service image carries no token.
        service::install(&state_dir, source.take(original_length)).context("This PC enrolled successfully. To finish, follow Windows service installation in the deployment guide.")?;
    }
    wait_for_service()?;
    Ok(format!("This PC is enrolled and the Flyw8t service is running.\n\nOpen Devices in your console to confirm check-in.\nDevice ID: {id}"))
}

fn wait_for_service() -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if service::status()? == Some(ServiceState::Running) {
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "This PC enrolled, but Windows has not confirmed that the service is running. Check Flyw8t in Windows Services.");
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16()
        .filter(|ch| *ch != 0)
        .chain([0])
        .collect()
}

fn message(parent: HWND, body: &str, flags: MESSAGEBOX_STYLE) -> i32 {
    unsafe { MessageBoxW(parent, wide(body).as_ptr(), wide(TITLE).as_ptr(), flags) }
}

struct Progress {
    window: HWND,
    label: HWND,
}

unsafe extern "system" fn window_proc(window: HWND, event: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if event == WM_CLOSE {
        return 0;
    }
    unsafe { DefWindowProcW(window, event, w, l) }
}

impl Progress {
    fn new(destination: &str) -> Result<Self> {
        unsafe {
            let instance = GetModuleHandleW(null());
            let class = wide("Flyw8tSetupProgress");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(window_proc),
                hInstance: instance,
                hCursor: LoadCursorW(null_mut(), IDC_ARROW),
                hbrBackground: (COLOR_BTNFACE + 1) as _,
                lpszClassName: class.as_ptr(),
                ..Default::default()
            };
            ensure!(
                RegisterClassW(&wc) != 0,
                "Windows could not initialize the setup window."
            );
            let window = CreateWindowExW(
                WS_EX_APPWINDOW,
                class.as_ptr(),
                wide(TITLE).as_ptr(),
                WS_CAPTION,
                (GetSystemMetrics(SM_CXSCREEN) - 520) / 2,
                (GetSystemMetrics(SM_CYSCREEN) - 150) / 2,
                520,
                150,
                null_mut(),
                null_mut(),
                instance,
                null(),
            );
            ensure!(
                !window.is_null(),
                "Windows could not open the setup window."
            );
            let mut progress = Self {
                window,
                label: null_mut(),
            };
            progress.label = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                wide(&format!("Setting up this PC for {destination}…")).as_ptr(),
                WS_CHILD | WS_VISIBLE,
                24,
                28,
                456,
                58,
                window,
                null_mut(),
                instance,
                null(),
            );
            ensure!(
                !progress.label.is_null(),
                "Windows could not display setup progress."
            );
            let font = windows_sys::Win32::Graphics::Gdi::GetStockObject(
                windows_sys::Win32::Graphics::Gdi::DEFAULT_GUI_FONT,
            );
            SendMessageW(progress.label, WM_SETFONT, font as usize, 1);
            ShowWindow(window, SW_SHOW);
            Ok(progress)
        }
    }

    fn set_text(&self, text: &str) {
        unsafe {
            SetWindowTextW(self.label, wide(text).as_ptr());
        }
    }

    fn pump(&self) {
        let mut message = MSG::default();
        unsafe {
            while PeekMessageW(&mut message, self.window, 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        unsafe {
            DestroyWindow(self.window);
        }
    }
}
