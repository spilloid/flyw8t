//! Running an admitted PowerShell script (ADR-0015 section 6). The checks are done before this is called; this is
//! only the containment: a fresh job folder, a fixed wrapper that binds named parameters, the process created
//! inside a Job Object, a minimal environment, completion when the Job Object is empty, and secrets redacted from
//! what is captured before anything else sees it.

use flyw8t_protocol::messages::{CapturedStream, ExecOutcome, Finished};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

/// The wrapper, compiled in and reviewed as part of the agent. It reads values as strict UTF-8 strings, parses the
/// script inside the containment, requires its `param()` block to declare exactly the names given (as plain
/// `[string]` parameters, nothing else), and calls it with a splatted hashtable, so every value binds by name.
pub const WRAPPER: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
function Read-Strings([string]$text) {
    $h = @{}
    if ($text.Trim().Length -eq 0) { return $h }
    $o = ConvertFrom-Json -InputObject $text
    foreach ($p in $o.PSObject.Properties) {
        if ($p.Value -isnot [string]) { throw "flyw8t: value $($p.Name) is not a string" }
        if ($h.ContainsKey($p.Name)) { throw "flyw8t: $($p.Name) given twice" }
        $h[$p.Name] = $p.Value
    }
    return $h
}
try {
    $values = Read-Strings ([System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'values.json'), $utf8))
    $in = [Console]::OpenStandardInput()
    $buf = New-Object System.IO.MemoryStream
    $in.CopyTo($buf)
    $secrets = Read-Strings ($utf8.GetString($buf.ToArray()))
    foreach ($k in @($secrets.Keys)) {
        if ($values.ContainsKey($k)) { throw "flyw8t: $k given twice" }
        $values[$k] = $secrets[$k]
    }
    $script = Join-Path $PSScriptRoot 'script.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw "flyw8t: the script does not parse: $($errors[0].Message)" }
    if ($ast.DynamicParamBlock) { throw "flyw8t: dynamicparam is not allowed" }
    $declared = @()
    if ($ast.ParamBlock) {
        if ($ast.ParamBlock.Attributes.Count -gt 0) { throw "flyw8t: the param block may not carry attributes" }
        foreach ($p in $ast.ParamBlock.Parameters) {
            $n = $p.Name.VariablePath.UserPath
            if ($p.DefaultValue) { throw "flyw8t: parameter $n has a default value" }
            foreach ($a in $p.Attributes) {
                $plain = ($a -is [System.Management.Automation.Language.TypeConstraintAst]) -and
                         (@('string', 'System.String') -contains $a.TypeName.FullName)
                if (-not $plain) { throw "flyw8t: parameter $n may be at most [string]" }
            }
            $declared += $n
        }
    }
    $given = @($values.Keys)
    foreach ($n in $declared) {
        if (-not ($given | Where-Object { $_ -ieq $n })) { throw "flyw8t: parameter $n has no value" }
    }
    foreach ($n in $given) {
        if (-not ($declared | Where-Object { $_ -ieq $n })) { throw "flyw8t: a value was given for $n, which the script does not declare" }
    }
    $global:LASTEXITCODE = 0
    & $script @values
    exit $global:LASTEXITCODE
} catch {
    [Console]::Error.WriteLine($_.ToString())
    exit 1
}
"#;

pub struct Run<'a> {
    /// The protected state folder; the job folder is made under `run\` inside it.
    pub state_dir: &'a Path,
    pub job_id: uuid::Uuid,
    pub source: &'a str,
    /// Plain values, written to the job folder.
    pub values: Vec<(String, String)>,
    /// Secret values, given on standard input and removed from what is captured.
    pub secrets: Vec<(String, String)>,
    pub timeout: Duration,
    pub cancel: Arc<AtomicBool>,
}

/// Remove every secret from `s`, and any secret's beginning left at its end by truncation.
pub fn redact(s: &str, secrets: &[&str]) -> String {
    let mut out = s.to_string();
    let mut sorted: Vec<&str> = secrets.iter().copied().filter(|x| !x.is_empty()).collect();
    // Longest first, so a secret that contains another is removed whole.
    sorted.sort_by_key(|x| std::cmp::Reverse(x.len()));
    for sec in &sorted {
        out = out.replace(sec, "[redacted]");
    }
    for sec in &sorted {
        for cut in (1..sec.len()).rev() {
            if sec.is_char_boundary(cut) && out.ends_with(&sec[..cut]) {
                out.truncate(out.len() - cut);
                out.push_str("[redacted]");
                break;
            }
        }
    }
    out
}

fn stream(data: &[u8], total: u64, secrets: &[&str]) -> CapturedStream {
    CapturedStream {
        data: redact(&String::from_utf8_lossy(data), secrets),
        total_bytes: total,
        truncated: total > data.len() as u64,
    }
}

pub fn run(r: Run<'_>, started_at: OffsetDateTime) -> Finished {
    let secrets: Vec<&str> = r.secrets.iter().map(|(_, v)| v.as_str()).collect();
    let fail = |error: String| Finished {
        outcome: ExecOutcome::Failed {
            error: redact(&error, &secrets),
        },
        started_at: Some(started_at),
        finished_at: OffsetDateTime::now_utc(),
        stdout: None,
        stderr: None,
        structured: None,
    };
    let dir = match job_folder(r.state_dir, r.job_id) {
        Ok(d) => d,
        Err(e) => return fail(format!("could not make the job folder: {e:#}")),
    };
    let result = (|| -> anyhow::Result<Finished> {
        let mut script = String::from("\u{feff}");
        script.push_str(r.source);
        create_new(&dir.join("script.ps1"), script.as_bytes())?;
        create_new(
            &dir.join("wrapper.ps1"),
            format!("\u{feff}{WRAPPER}").as_bytes(),
        )?;
        let values: serde_json::Map<String, serde_json::Value> = r
            .values
            .iter()
            .map(|(k, v)| (k.clone(), v.clone().into()))
            .collect();
        create_new(
            &dir.join("values.json"),
            serde_json::to_string(&values)?.as_bytes(),
        )?;
        let secrets_json: serde_json::Map<String, serde_json::Value> = r
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), v.clone().into()))
            .collect();
        let stdin = serde_json::to_vec(&secrets_json)?;
        let out = platform::spawn_and_wait(&dir, &stdin, r.timeout, &r.cancel)?;
        let outcome = match out.end {
            End::Exited(code) => ExecOutcome::Exited { code },
            End::TimedOut => ExecOutcome::TimedOut,
            End::Cancelled => ExecOutcome::Cancelled { started: true },
        };
        Ok(Finished {
            outcome,
            started_at: Some(started_at),
            finished_at: OffsetDateTime::now_utc(),
            stdout: Some(stream(&out.stdout.0, out.stdout.1, &secrets)),
            stderr: Some(stream(&out.stderr.0, out.stderr.1, &secrets)),
            structured: None,
        })
    })();
    let _ = remove_folder(&dir);
    result.unwrap_or_else(|e| fail(format!("{e:#}")))
}

pub enum End {
    Exited(i32),
    TimedOut,
    Cancelled,
}

pub struct Output {
    pub end: End,
    pub stdout: (Vec<u8>, u64),
    pub stderr: (Vec<u8>, u64),
}

/// `run\<job id>` in the state folder, made new: an existing one fails the job.
fn job_folder(state_dir: &Path, job: uuid::Uuid) -> anyhow::Result<PathBuf> {
    let parent = state_dir.join("run");
    match std::fs::create_dir(&parent) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let meta = std::fs::symlink_metadata(&parent)?;
    if !meta.is_dir() || is_reparse(&meta) {
        anyhow::bail!("{} is not a plain folder", parent.display());
    }
    let dir = parent.join(job.to_string());
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

#[cfg(windows)]
fn is_reparse(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(m: &std::fs::Metadata) -> bool {
    m.file_type().is_symlink()
}

fn create_new(p: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Remove the job folder without following reparse points: only plain files directly inside it are deleted.
fn remove_folder(dir: &Path) -> std::io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let m = std::fs::symlink_metadata(e.path())?;
        if m.is_dir() || is_reparse(&m) {
            // A script left a folder or a link here: leave it, rather than follow it.
            continue;
        }
        let _ = std::fs::remove_file(e.path());
    }
    let _ = std::fs::remove_dir(dir);
    Ok(())
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn spawn_and_wait(
        _: &Path,
        _: &[u8],
        _: Duration,
        _: &AtomicBool,
    ) -> anyhow::Result<Output> {
        anyhow::bail!("scripts run on Windows only in this version")
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use flyw8t_protocol::MAX_STREAM_BYTES;
    use std::ffi::OsStr;
    use std::io::Read;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
        LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_JOB_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };

    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: a handle this module opened and still owns.
                unsafe { CloseHandle(self.0) };
            }
        }
    }
    impl Owned {
        fn take(&mut self) -> HANDLE {
            std::mem::replace(&mut self.0, std::ptr::null_mut())
        }
    }

    fn last<T>() -> anyhow::Result<T> {
        Err(std::io::Error::last_os_error().into())
    }

    /// A pipe whose child end is inheritable and whose parent end is not.
    fn pipe(child_reads: bool) -> anyhow::Result<(Owned, Owned)> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: out-pointers to locals.
        if unsafe { CreatePipe(&mut r, &mut w, &sa, 0) } == 0 {
            return last();
        }
        let (r, w) = (Owned(r), Owned(w));
        let (child, parent) = if child_reads { (r, w) } else { (w, r) };
        // SAFETY: a handle just made.
        if unsafe { SetHandleInformation(parent.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return last();
        }
        Ok((child, parent))
    }

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain([0]).collect()
    }

    fn environment(dir: &Path, system: &Path, windows: &Path, program_files: &Path) -> Vec<u16> {
        let d = dir.display().to_string();
        let sys = system.display().to_string();
        let win = windows.display().to_string();
        let pf = program_files.display().to_string();
        let vars = [
            ("ComSpec", format!("{sys}\\cmd.exe")),
            (
                "PATH",
                format!("{sys};{win};{sys}\\Wbem;{sys}\\WindowsPowerShell\\v1.0"),
            ),
            (
                "PSModulePath",
                format!("{pf}\\WindowsPowerShell\\Modules;{sys}\\WindowsPowerShell\\v1.0\\Modules"),
            ),
            ("ProgramFiles", pf.clone()),
            ("SystemDrive", win.chars().take(2).collect()),
            ("SystemRoot", win.clone()),
            ("TEMP", d.clone()),
            ("TMP", d.clone()),
            ("APPDATA", d.clone()),
            ("LOCALAPPDATA", d),
            ("windir", win),
        ];
        let mut out: Vec<u16> = Vec::new();
        for (k, v) in vars {
            out.extend(OsStr::new(&format!("{k}={v}")).encode_wide());
            out.push(0);
        }
        out.push(0);
        out
    }

    fn reader(h: HANDLE) -> std::thread::JoinHandle<(Vec<u8>, u64)> {
        // SAFETY: the parent end of a pipe, now owned by this File.
        let mut f = unsafe { std::fs::File::from_raw_handle(h as _) };
        std::thread::spawn(move || {
            let (mut kept, mut total) = (Vec::new(), 0u64);
            let mut buf = [0u8; 8192];
            while let Ok(n) = f.read(&mut buf) {
                if n == 0 {
                    break;
                }
                total += n as u64;
                let room = MAX_STREAM_BYTES.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
            (kept, total)
        })
    }

    fn active(job: HANDLE) -> u32 {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: a valid job handle and a buffer of the right size.
        let ok = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            0
        } else {
            info.ActiveProcesses
        }
    }

    pub fn spawn_and_wait(
        dir: &Path,
        stdin_bytes: &[u8],
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> anyhow::Result<Output> {
        let system = crate::winsec::system_folder()?;
        let windows = crate::winsec::windows_folder()?;
        let program_files = crate::winsec::program_files()?;
        let exe = system
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let wrapper = dir.join("wrapper.ps1");

        // SAFETY: plain Win32 calls; every handle is owned by an `Owned` and closed on every path.
        let job = Owned(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) });
        if job.0.is_null() {
            return last();
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        // Kill everything when the handle closes; no breakaway (its flag is not set); no error dialogs.
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return last();
        }

        let (in_child, mut in_parent) = pipe(true)?;
        let (out_child, mut out_parent) = pipe(false)?;
        let (err_child, mut err_parent) = pipe(false)?;

        // Only the three pipe ends are inherited, and the process starts inside the job.
        let inherit = [in_child.0, out_child.0, err_child.0];
        let mut size = 0usize;
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size) };
        let mut attr_buf = vec![0u8; size];
        let attrs = attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        if unsafe { InitializeProcThreadAttributeList(attrs, 2, 0, &mut size) } == 0 {
            return last();
        }
        struct AttrList(LPPROC_THREAD_ATTRIBUTE_LIST);
        impl Drop for AttrList {
            fn drop(&mut self) {
                // SAFETY: initialized above.
                unsafe { DeleteProcThreadAttributeList(self.0) };
            }
        }
        let _attr_guard = AttrList(attrs);
        let job_list = [job.0];
        if unsafe {
            UpdateProcThreadAttribute(
                attrs,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherit.as_ptr() as *const _,
                std::mem::size_of_val(&inherit),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
            || unsafe {
                UpdateProcThreadAttribute(
                    attrs,
                    0,
                    PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                    job_list.as_ptr() as *const _,
                    std::mem::size_of_val(&job_list),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            } == 0
        {
            return last();
        }

        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = in_child.0;
        si.StartupInfo.hStdOutput = out_child.0;
        si.StartupInfo.hStdError = err_child.0;
        si.lpAttributeList = attrs;

        let app = wide(exe.as_os_str());
        let mut cmd = wide(OsStr::new(&format!(
            "\"{}\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\"",
            exe.display(),
            wrapper.display()
        )));
        let env = environment(dir, &system, &windows, &program_files);
        let cwd = wide(dir.as_os_str());
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            CreateProcessW(
                app.as_ptr(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                env.as_ptr() as *const _,
                cwd.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            )
        };
        drop((in_child, out_child, err_child));
        if ok == 0 {
            return last();
        }
        let process = Owned(pi.hProcess);
        drop(Owned(pi.hThread));

        let out_reader = reader(out_parent.take());
        let err_reader = reader(err_parent.take());
        {
            use std::io::Write;
            // SAFETY: the parent end of the stdin pipe, owned by this File and closed when it drops.
            let mut f = unsafe { std::fs::File::from_raw_handle(in_parent.take() as _) };
            let _ = f.write_all(stdin_bytes);
        }

        // Complete when the job is empty, not when PowerShell exits: anything it started is waited for, under
        // the same timeout, and whatever is left at the timeout is terminated.
        let deadline = std::time::Instant::now() + timeout;
        let end = loop {
            if cancel.load(Ordering::SeqCst) {
                unsafe { TerminateJobObject(job.0, 1) };
                break Some(End::Cancelled);
            }
            if std::time::Instant::now() >= deadline {
                unsafe { TerminateJobObject(job.0, 1) };
                break Some(End::TimedOut);
            }
            if active(job.0) == 0 {
                break None;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        // Wait for the tree to be gone before reading the last output and cleaning up.
        while active(job.0) != 0 {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = unsafe { WaitForSingleObject(process.0, 5000) } == WAIT_OBJECT_0;
        let mut code: u32 = 0;
        unsafe { GetExitCodeProcess(process.0, &mut code) };
        let stdout = out_reader.join().unwrap_or_default();
        let stderr = err_reader.join().unwrap_or_default();
        Ok(Output {
            end: end.unwrap_or(End::Exited(code as i32)),
            stdout,
            stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_redacted_whole_and_at_a_cut() {
        assert_eq!(redact("key=hunter2 ok", &["hunter2"]), "key=[redacted] ok");
        assert_eq!(redact("abcabc", &["abc", "abcabc"]), "[redacted]");
        assert_eq!(redact("tail hunt", &["hunter2"]), "tail [redacted]");
        assert_eq!(redact("nothing", &["", "x"]), "nothing");
    }

    #[cfg(windows)]
    fn run_ps(
        source: &str,
        values: &[(&str, &str)],
        secrets: &[(&str, &str)],
        timeout: u64,
    ) -> Finished {
        let dir = tempfile::tempdir().unwrap();
        run(
            Run {
                state_dir: dir.path(),
                job_id: uuid::Uuid::new_v4(),
                source,
                values: values
                    .iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect(),
                secrets: secrets
                    .iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect(),
                timeout: Duration::from_secs(timeout),
                cancel: Arc::new(AtomicBool::new(false)),
            },
            OffsetDateTime::now_utc(),
        )
    }

    #[cfg(windows)]
    #[test]
    fn values_bind_by_name_only_and_secrets_never_show() {
        let f = run_ps(
            "param([string]$Path, $Mode, [string]$Key)\n\"path=$Path mode=$Mode key=$Key\"\n$Key | Out-Host\nexit 3\n",
            &[("Path", "-Force"), ("Mode", "a b; Remove-Item C:\\x")],
            &[("Key", "s3cr3t-value")],
            60,
        );
        assert_eq!(f.outcome, ExecOutcome::Exited { code: 3 }, "{f:?}");
        let out = f.stdout.unwrap().data;
        assert!(
            out.contains("path=-Force mode=a b; Remove-Item C:\\x"),
            "{out}"
        );
        assert!(
            !out.contains("s3cr3t") && out.contains("[redacted]"),
            "{out}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn anything_but_plain_declared_parameters_is_refused() {
        for (source, values) in [
            ("param([string]$A)\n'ran'\n", vec![("A", "1"), ("B", "2")]),
            ("'ran'\n", vec![("A", "1")]),
            ("param([string]$A = 'd')\n'ran'\n", vec![("A", "1")]),
            (
                "param([ValidateScript({$true})][string]$A)\n'ran'\n",
                vec![("A", "1")],
            ),
            ("param([scriptblock]$A)\n'ran'\n", vec![("A", "1")]),
            ("param([string]$A, [string]$B)\n'ran'\n", vec![("A", "1")]),
        ] {
            let f = run_ps(source, &values, &[], 60);
            assert_eq!(f.outcome, ExecOutcome::Exited { code: 1 }, "{source}");
            assert!(!f.stdout.unwrap().data.contains("ran"), "{source}");
        }
        let f = run_ps("'ran'\n", &[], &[], 60);
        assert!(f.stdout.unwrap().data.contains("ran"));
    }

    #[cfg(windows)]
    #[test]
    fn a_run_ends_when_everything_it_started_has_ended_or_the_timeout() {
        // A child that outlives the script is waited for...
        let started = std::time::Instant::now();
        let f = run_ps("Start-Process -FilePath ping.exe -ArgumentList '-n','4','127.0.0.1' -WindowStyle Hidden\n'parent done'\n", &[], &[], 60);
        assert_eq!(f.outcome, ExecOutcome::Exited { code: 0 }, "{f:?}");
        assert!(
            started.elapsed() >= Duration::from_secs(2),
            "waited for the child"
        );
        // ...but not past the timeout: then the whole tree goes.
        let started = std::time::Instant::now();
        let f = run_ps("Start-Process -FilePath ping.exe -ArgumentList '-n','60','127.0.0.1' -WindowStyle Hidden\n'parent done'\n", &[], &[], 3);
        assert_eq!(f.outcome, ExecOutcome::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(20));
    }
}
