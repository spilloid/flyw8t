//! Locally exercise Windows PowerShell through a pseudoconsole with fixed diagnostic input.

use anyhow::{anyhow, ensure, Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Console::{COORD, HPCON};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTF_USESTDHANDLES,
    STARTUPINFOEXW,
};

fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let (mut read, mut write): (HANDLE, HANDLE) = (null_mut(), null_mut());
    // SAFETY: both output pointers are writable. The handles are private to this process.
    if unsafe { CreatePipe(&mut read, &mut write, null(), 0) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: CreatePipe transferred ownership of both handles.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}

type CreateConsole = unsafe extern "system" fn(COORD, HANDLE, HANDLE, u32, *mut HPCON) -> i32;
type CloseConsole = unsafe extern "system" fn(HPCON);
type KernelSymbol = unsafe extern "system" fn() -> isize;

fn load_pseudoconsole_api() -> Result<(CreateConsole, CloseConsole)> {
    let module: Vec<u16> = "kernel32.dll".encode_utf16().chain([0]).collect();
    // SAFETY: this process already loads kernel32, and the library name is NUL-terminated.
    let module = unsafe { GetModuleHandleW(module.as_ptr()) };
    ensure!(
        !module.is_null(),
        "Windows did not return the kernel32 module"
    );
    // SAFETY: the module will remain loaded for the process lifetime, and both names are valid.
    let create = unsafe { GetProcAddress(module, c"CreatePseudoConsole".as_ptr().cast()) };
    let close = unsafe { GetProcAddress(module, c"ClosePseudoConsole".as_ptr().cast()) };
    let (Some(create), Some(close)) = (create, close) else {
        anyhow::bail!("PowerShell diagnostics require Windows 10 version 1809 or Windows Server 2019 or newer");
    };
    // SAFETY: the symbols above are looked up by their exact names and use these Win32 signatures.
    Ok(unsafe {
        (
            std::mem::transmute::<KernelSymbol, CreateConsole>(create),
            std::mem::transmute::<KernelSymbol, CloseConsole>(close),
        )
    })
}

struct Pseudoconsole {
    handle: HPCON,
    close: CloseConsole,
}

impl Drop for Pseudoconsole {
    fn drop(&mut self) {
        // SAFETY: the read thread drains final output until the pseudoconsole closes its pipe.
        unsafe { (self.close)(self.handle) };
    }
}

struct Attributes(LPPROC_THREAD_ATTRIBUTE_LIST);

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: the attribute list was initialized and its backing memory is still live.
        unsafe { DeleteProcThreadAttributeList(self.0) };
    }
}

fn kill_on_close_job() -> Result<OwnedHandle> {
    // SAFETY: null arguments create an unnamed, non-inheritable job.
    let handle = unsafe { CreateJobObjectW(null(), null()) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error()).context("creating the PowerShell job");
    }
    // SAFETY: CreateJobObjectW returned a new owned handle.
    let job = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: the job handle is live and the data matches the information class.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("configuring the PowerShell job");
    }
    Ok(job)
}

fn spawn(shell: &Pseudoconsole, job: &OwnedHandle) -> Result<(OwnedHandle, u32)> {
    let mut size = 0;
    // SAFETY: the null list asks Windows to report the required size.
    unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size) };
    ensure!(size != 0, "Windows did not size the attribute list");
    let mut buffer = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let list = buffer.as_mut_ptr().cast();
    // SAFETY: the aligned buffer is at least as large as Windows requested.
    if unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let jobs = [job.as_raw_handle()];
    let attrs = Attributes(list);
    // SAFETY: the list and pseudoconsole are live. This attribute takes the handle as lpValue.
    if unsafe {
        UpdateProcThreadAttribute(
            attrs.0,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            shell.handle as _,
            std::mem::size_of::<HPCON>(),
            null_mut(),
            null(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("attaching the PowerShell console");
    }
    // SAFETY: both the job handle and its backing array outlive the attribute list.
    if unsafe {
        UpdateProcThreadAttribute(
            attrs.0,
            0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            jobs.as_ptr().cast(),
            std::mem::size_of_val(&jobs),
            null_mut(),
            null(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("attaching the PowerShell job");
    }
    let startup = STARTUPINFOEXW {
        StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
            // Explicit null handles prevent Windows from copying redirected streams
            // from the agent or its caller into the pseudoconsole client.
            dwFlags: STARTF_USESTDHANDLES,
            ..Default::default()
        },
        lpAttributeList: attrs.0,
    };
    let system = crate::winsec::system_folder()?;
    let exe = system
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let application: Vec<_> = exe.as_os_str().encode_wide().chain([0]).collect();
    let mut command: Vec<_> = format!("\"{}\" -NoLogo -NoProfile", exe.display())
        .encode_utf16()
        .chain([0])
        .collect();
    let cwd: Vec<_> = system.as_os_str().encode_wide().chain([0]).collect();
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: all pointers refer to the corresponding live buffers or optional null inputs.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            null(),
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: CreateProcessW transferred both handles to this process.
    unsafe { drop(OwnedHandle::from_raw_handle(info.hThread)) };
    // SAFETY: the process handle is also owned by the caller after CreateProcessW.
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    Ok((process, info.dwProcessId))
}

const OUTPUT_LIMIT: usize = 256 * 1024;

fn process_session(pid: u32) -> Result<u32> {
    let mut session = 0;
    // SAFETY: session is a writable output slot.
    if unsafe { ProcessIdToSessionId(pid, &mut session) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("reading the Windows session ID for process {pid}"));
    }
    Ok(session)
}

struct ConsoleOutput {
    chunks: Receiver<Result<Vec<u8>>>,
    pending: Vec<u8>,
}

impl ConsoleOutput {
    fn read_until(&mut self, marker: &str) -> Result<String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(start) = self
                .pending
                .windows(marker.len())
                .position(|bytes| bytes == marker.as_bytes())
            {
                // Preserve bytes after the marker. One read can contain multiple markers.
                let matched: Vec<_> = self.pending.drain(..start + marker.len()).collect();
                return Ok(String::from_utf8_lossy(&matched).into_owned());
            }
            let chunk = self
                .chunks
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .with_context(|| {
                    format!(
                        "waiting for PowerShell marker {marker:?} ({} bytes received)",
                        self.pending.len()
                    )
                })??;
            self.pending.extend(chunk);
        }
    }
}

#[test]
fn console_marker_reads_preserve_the_tail_across_pipe_chunks() -> Result<()> {
    let (events, chunks) = channel();
    events.send(Ok(b"one-two-th".to_vec()))?;
    events.send(Ok(b"ree".to_vec()))?;
    drop(events);
    let mut output = ConsoleOutput {
        chunks,
        pending: Vec::new(),
    };
    assert_eq!(output.read_until("one")?, "one");
    assert_eq!(output.read_until("two")?, "-two");
    assert_eq!(output.read_until("three")?, "-three");
    Ok(())
}

/// Prove that local PowerShell handles input, interruption, normal exit, and forced cleanup.
pub fn check(require_session_zero: bool) -> Result<()> {
    probe(require_session_zero, Shutdown::Graceful)?;
    probe(require_session_zero, Shutdown::AtPrompt)
}

enum Shutdown {
    Graceful,
    AtPrompt,
}

fn probe(require_session_zero: bool, shutdown: Shutdown) -> Result<()> {
    let session = process_session(std::process::id())?;
    ensure!(
        !require_session_zero || session == 0,
        "the diagnostic is running in Windows session {session}, expected session 0"
    );
    let (create_console, close_console) = load_pseudoconsole_api()?;
    let job_handle = kill_on_close_job()?;
    let (console_input, input) = pipe()?;
    let (output, console_output) = pipe()?;
    let (events, chunks) = channel();
    let mut received = ConsoleOutput {
        chunks,
        pending: Vec::new(),
    };
    let reader = std::thread::spawn(move || {
        let mut output = File::from(output);
        let mut buffer = [0; 4096];
        let mut remaining = Some(OUTPUT_LIMIT);
        while let Ok(n @ 1..) = output.read(&mut buffer) {
            // Continue draining during teardown, including after a failed assertion.
            if let Some(budget) = remaining {
                remaining = budget.checked_sub(n);
                let event = match remaining {
                    Some(_) => Ok(buffer[..n].to_vec()),
                    None => Err(anyhow!("too much PowerShell diagnostic output")),
                };
                let _ = events.send(event);
            }
        }
    });
    let mut handle = 0;
    // SAFETY: both pipe ends and the writable handle slot are live.
    let result = unsafe {
        create_console(
            COORD { X: 120, Y: 30 },
            console_input.as_raw_handle(),
            console_output.as_raw_handle(),
            0,
            &mut handle,
        )
    };
    ensure!(
        result >= 0,
        "CreatePseudoConsole failed with HRESULT {result:#x}"
    );
    let console = Pseudoconsole {
        handle,
        close: close_console,
    };
    // Drop the job before closing the pseudoconsole, including on a diagnostic failure.
    let job = job_handle;
    let child = spawn(&console, &job);
    drop((console_input, console_output));
    let (child, pid) = child?;
    let child_session = process_session(pid)?;
    ensure!(
        child_session == session,
        "PowerShell started in Windows session {child_session}, expected session {session}"
    );
    let mut assigned = 0;
    // SAFETY: both handles are live and assigned points to a writable BOOL.
    if unsafe { IsProcessInJob(child.as_raw_handle(), job.as_raw_handle(), &mut assigned) } == 0 {
        return Err(std::io::Error::last_os_error()).context("checking the PowerShell job");
    }
    ensure!(assigned != 0, "PowerShell was not assigned to its job");
    let mut input = File::from(input);

    match shutdown {
        Shutdown::Graceful => {
            check_interaction(&mut input, &mut received, &child)?;
            drop(job);
        }
        Shutdown::AtPrompt => {
            input.write_all(b"Read-Host ('flyw8t' + '-disconnect')\r")?;
            received.read_until("flyw8t-disconnect")?;
            // SAFETY: the child process handle remains live across both waits.
            ensure!(
                unsafe { WaitForSingleObject(child.as_raw_handle(), 0) } == WAIT_TIMEOUT,
                "PowerShell exited before the disconnect check"
            );
            // Keep the input pipe and pseudoconsole open so only job teardown stops PowerShell.
            drop(job);
            // SAFETY: the child process handle is still live after closing the job.
            ensure!(
                unsafe { WaitForSingleObject(child.as_raw_handle(), 5_000) } == WAIT_OBJECT_0,
                "PowerShell stayed alive after its job closed"
            );
        }
    }
    drop((input, console));
    reader
        .join()
        .map_err(|_| anyhow!("the PowerShell output reader stopped unexpectedly"))?;
    Ok(())
}

fn check_interaction(
    input: &mut File,
    received: &mut ConsoleOutput,
    child: &OwnedHandle,
) -> Result<()> {
    // Build markers at runtime to distinguish command output from echoed keystrokes.
    input.write_all(b"function prompt { 'flyw8t' + '-prompt> ' }\r")?;
    received.read_until("flyw8t-prompt>")?;
    input.write_all(
        b"$label='flyw8t'; '{0}-started' -f $label; Start-Sleep 60; '{0}-unexpected' -f $label\r",
    )?;
    received.read_until("flyw8t-started")?;
    input.write_all(b"\x03")?;
    let interrupted = received.read_until("flyw8t-prompt>")?;
    input.write_all(b"'{0}-resumed' -f $label\r")?;
    let resumed = received.read_until("flyw8t-resumed")?;
    ensure!(
        !interrupted.contains("flyw8t-unexpected") && !resumed.contains("flyw8t-unexpected"),
        "the command ran past Ctrl+C"
    );

    input.write_all(b"$answer=Read-Host ('confirm' + '-input'); '{0}-answer' -f $answer\r")?;
    received.read_until("confirm-input")?;
    input.write_all(b"yes\r")?;
    received.read_until("yes-answer")?;

    input.write_all(b"exit 0\r")?;
    let mut code = 1;
    // SAFETY: the process handle is live and code is a writable output slot.
    let exited = unsafe {
        WaitForSingleObject(child.as_raw_handle(), 15_000) == WAIT_OBJECT_0
            && GetExitCodeProcess(child.as_raw_handle(), &mut code) != 0
    };
    ensure!(exited && code == 0, "PowerShell did not exit cleanly");
    Ok(())
}

#[test]
fn background_powershell_keeps_state_and_interrupts_a_running_command() -> Result<()> {
    check(false)
}
