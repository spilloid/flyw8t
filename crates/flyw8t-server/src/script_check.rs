//! Syntax checks for script revisions (ADR-0014 section 2): the language's own parser reads the source and reports
//! problems by line. Parsing never runs the script: PowerShell's `Parser.ParseInput`, `bash -n`, Python's `compile()`.
//!
//! Each checker is its own process with an empty environment, the source on standard input and nothing else, a time
//! limit, a memory limit (`setrlimit` on Unix, a Job Object on Windows; .NET's own heap limit for PowerShell on Unix,
//! whose runtime reserves more address space than any useful limit) and capped output. At most two run at once, and a
//! save waits only briefly for a turn: when the server is busy it says so rather than queueing without bound. When no
//! checker is installed, or one does not finish, the result says the source was not checked; it never claims the source
//! is fine. A clean check says nothing about what a script does.
//!
//! Not yet: running without network access, or as an identity without the server's credentials. PowerShell resolves
//! `using module` and `using assembly` while parsing (it may look for, and load, what they name), so a script with
//! either is not given to it.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

const TIME_LIMIT: Duration = Duration::from_secs(15);
/// How long a save waits for a checker to be free before saying the server is busy.
const ADMISSION_WAIT: Duration = Duration::from_secs(5);
/// Memory a checker may use: several times what the largest allowed script needs (Python: about 240 MiB for 256 KiB).
const MEMORY_LIMIT: u64 = 768 * 1024 * 1024;
const OUTPUT_CAP: u64 = 64 * 1024;
const MAX_PROBLEMS: usize = 100;
const MAX_MESSAGE: usize = 300;
static RUNNING: Semaphore = Semaphore::const_new(2);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    pub line: Option<u32>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntaxCheck {
    /// What checked it (`bash -n`, ...), or `None`: the source was not checked.
    pub checker: Option<String>,
    /// Why it was not checked, or did not finish (no checker installed, turned off, time limit).
    pub unchecked: Option<String>,
    pub problems: Vec<Problem>,
}

/// Every checker was in use for longer than a save should wait: try again shortly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Busy;

impl SyntaxCheck {
    fn unchecked(why: impl Into<String>) -> Self {
        SyntaxCheck {
            checker: None,
            unchecked: Some(why.into()),
            problems: vec![],
        }
    }
}

struct Checker {
    label: &'static str,
    programs: &'static [&'static str],
    args: &'static [&'static str],
    /// Exit codes that mean "parsed; problems (if any) are in the output".
    parsed: &'static [i32],
    parse: fn(&str) -> Vec<Problem>,
    /// A .NET program: its memory is limited through the runtime's heap limit on Unix, not the address space.
    dotnet: bool,
}

// Reads the source from standard input and prints `line<TAB>message` for each parse error. Single quotes only: the
// whole script is one command-line argument.
const PS_CHECK: &str = "try { [Console]::InputEncoding = [Text.Encoding]::UTF8; [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}; \
$s = [Console]::In.ReadToEnd(); $t = $null; $e = $null; \
[void][System.Management.Automation.Language.Parser]::ParseInput($s, [ref]$t, [ref]$e); \
foreach ($x in $e) { '{0}{1}{2}' -f $x.Extent.StartLineNumber, [char]9, $x.Message }";

const PY_CHECK: &str = "import sys\n\
src = sys.stdin.buffer.read()\n\
try:\n    compile(src, '<script>', 'exec', dont_inherit=True)\n\
except SyntaxError as e:\n    sys.stdout.write('%s\\t%s\\n' % (e.lineno or '', e.msg))\n";

fn checker(language: &str) -> Option<Checker> {
    match language {
        "powershell" => Some(Checker {
            label: "PowerShell parser",
            programs: if cfg!(windows) {
                &["pwsh", "powershell"]
            } else {
                &["pwsh"]
            },
            args: &[
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                PS_CHECK,
            ],
            parsed: &[0],
            parse: tabbed,
            dotnet: true,
        }),
        "bash" => Some(Checker {
            label: "bash -n",
            programs: &["bash"],
            args: &["--norc", "--noprofile", "-n"],
            parsed: &[0, 1, 2],
            parse: bash_messages,
            dotnet: false,
        }),
        "python" => Some(Checker {
            label: "Python compile()",
            programs: if cfg!(windows) {
                &["python3", "python"]
            } else {
                &["python3"]
            },
            args: &["-I", "-S", "-c", PY_CHECK],
            parsed: &[0],
            parse: tabbed,
            dotnet: false,
        }),
        _ => None,
    }
}

/// `line<TAB>message` lines, as the PowerShell and Python checks print them.
fn tabbed(out: &str) -> Vec<Problem> {
    out.lines()
        .filter_map(|l| {
            let (n, msg) = l.split_once('\t')?;
            Some(Problem {
                line: n.trim().parse().ok(),
                message: msg.trim().to_string(),
            })
        })
        .collect()
}

/// bash prints `bash: line 3: syntax error near unexpected token ...`, then the offending text quoted on its own line.
fn bash_messages(out: &str) -> Vec<Problem> {
    out.lines()
        .filter_map(|l| {
            let rest = &l[l.find("line ")? + 5..];
            let (n, msg) = rest.split_once(':')?;
            let msg = msg.trim();
            if msg.starts_with('`') && msg.ends_with('\'') {
                return None; // the echo of the offending text
            }
            Some(Problem {
                line: n.trim().parse().ok(),
                message: msg.to_string(),
            })
        })
        .collect()
}

/// A program on PATH, skipping stand-ins that would not be the real parser: on Windows, the WSL `bash.exe` in System32
/// and the Microsoft Store `python.exe` aliases.
fn find(program: &str) -> Option<PathBuf> {
    let name = if cfg!(windows) {
        format!("{program}.exe")
    } else {
        program.to_string()
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(&name))
        .find(|c| c.is_file() && !stand_in(c))
}

fn stand_in(p: &Path) -> bool {
    if !cfg!(windows) {
        return false;
    }
    let s = p.to_string_lossy().to_lowercase();
    s.contains("\\windowsapps\\") || (s.ends_with("\\system32\\bash.exe"))
}

fn clip(s: &str) -> String {
    match s.char_indices().nth(MAX_MESSAGE) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

/// `using module` or `using assembly` anywhere (case and spacing as PowerShell allows): PowerShell resolves these while
/// parsing, so such a script is not parsed here. A false alarm only means "not checked".
pub fn resolves_while_parsing(source: &str) -> bool {
    let lower = source.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| c.is_whitespace() || c == ';' || c == '`')
        .filter(|w| !w.is_empty())
        .collect();
    words
        .windows(2)
        .any(|w| w[0] == "using" && (w[1] == "module" || w[1] == "assembly"))
}

pub async fn check(enabled: bool, language: &str, source: &str) -> Result<SyntaxCheck, Busy> {
    if !enabled {
        return Ok(SyntaxCheck::unchecked(
            "Syntax checks are turned off on this server.",
        ));
    }
    let Some(c) = checker(language) else {
        return Ok(SyntaxCheck::unchecked("No checker for this language."));
    };
    if c.dotnet && resolves_while_parsing(source) {
        return Ok(SyntaxCheck::unchecked(
            "Not checked: the script has `using module` or `using assembly`, which PowerShell resolves while parsing.",
        ));
    }
    let Some(program) = c.programs.iter().find_map(|p| find(p)) else {
        return Ok(SyntaxCheck::unchecked(format!(
            "Not checked: no {} on this server.",
            c.label
        )));
    };
    let _slot = admit(&RUNNING, ADMISSION_WAIT).await?;
    Ok(outcome(&c, run(&program, &c, MEMORY_LIMIT, source).await))
}

/// A turn on a checker, or `Busy` if none frees up in time: waiting saves never pile up without bound.
async fn admit(
    running: &Semaphore,
    wait: Duration,
) -> Result<tokio::sync::SemaphorePermit<'_>, Busy> {
    match tokio::time::timeout(wait, running.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        _ => Err(Busy),
    }
}

/// What a checker's run means: problems only when it parsed the source; anything else is "not checked", never clean.
fn outcome(c: &Checker, run: Result<(Option<i32>, String), String>) -> SyntaxCheck {
    match run {
        Ok((code, out)) if code.is_some_and(|code| c.parsed.contains(&code)) => {
            let mut problems: Vec<Problem> = (c.parse)(&out)
                .into_iter()
                .map(|p| Problem {
                    line: p.line,
                    message: clip(&p.message),
                })
                .collect();
            if code != Some(0) && problems.is_empty() {
                return SyntaxCheck::unchecked(format!(
                    "Not checked: the {} failed without saying why.",
                    c.label
                ));
            }
            problems.truncate(MAX_PROBLEMS);
            SyntaxCheck {
                checker: Some(c.label.to_string()),
                unchecked: None,
                problems,
            }
        }
        Ok(_) => SyntaxCheck::unchecked(format!("Not checked: the {} failed.", c.label)),
        Err(why) => SyntaxCheck::unchecked(format!("Not checked: {why}.")),
    }
}

/// Run a checker: the source on standard input, standard output and error together (each capped), within the time and
/// memory limits.
async fn run(
    program: &Path,
    c: &Checker,
    memory: u64,
    source: &str,
) -> Result<(Option<i32>, String), String> {
    let tmp = std::env::temp_dir();
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(c.args)
        .env_clear()
        .current_dir(&tmp)
        .env("HOME", &tmp)
        .env("TMPDIR", &tmp)
        .env("POWERSHELL_TELEMETRY_OPTOUT", "1")
        .env("POWERSHELL_UPDATECHECK", "Off")
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if cfg!(windows) {
        for k in ["SystemRoot", "windir", "TEMP", "TMP"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
    }
    if c.dotnet {
        // .NET's own limit on its heap, honored by PowerShell 7 everywhere (hex bytes).
        cmd.env("DOTNET_GCHeapHardLimit", format!("{memory:x}"));
    }
    #[cfg(unix)]
    {
        let address_space = (!c.dotnet).then_some(memory);
        let cpu_seconds = TIME_LIMIT.as_secs();
        // SAFETY: between fork and exec only setrlimit (async-signal-safe) is called, and nothing is allocated.
        unsafe {
            cmd.pre_exec(move || {
                let cpu = libc::rlimit {
                    rlim_cur: cpu_seconds as libc::rlim_t,
                    rlim_max: cpu_seconds as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_CPU, &cpu) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(bytes) = address_space {
                    let mem = libc::rlimit {
                        rlim_cur: bytes as libc::rlim_t,
                        rlim_max: bytes as libc::rlim_t,
                    };
                    if libc::setrlimit(libc::RLIMIT_AS, &mem) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|_| "the checker could not start".to_string())?;
    // Held until the child is done; dropping it ends the process if it still runs. If the limit cannot be put in place,
    // the checker is stopped before it is given any input.
    #[cfg(windows)]
    let _job = match job::contain(&child, memory) {
        Some(j) => j,
        None => {
            let _ = child.start_kill();
            return Err("the checker's memory could not be limited".into());
        }
    };
    let mut stdin = child.stdin.take().ok_or("no input")?;
    let (stdout, stderr) = (
        child.stdout.take().ok_or("no output")?,
        child.stderr.take().ok_or("no output")?,
    );
    let input = source.as_bytes().to_vec();
    let work = async {
        let write = async move {
            // A checker that stops reading early (a parse error in the first line) closes the pipe: not an error here.
            let _ = stdin.write_all(&input).await;
            drop(stdin);
        };
        let read = |r: Box<dyn tokio::io::AsyncRead + Unpin + Send>| async move {
            let mut buf = Vec::new();
            let _ = r.take(OUTPUT_CAP).read_to_end(&mut buf).await;
            buf
        };
        let ((), out, err) = tokio::join!(write, read(Box::new(stdout)), read(Box::new(stderr)));
        let status = child
            .wait()
            .await
            .map_err(|_| "the checker could not be waited for".to_string())?;
        let mut text = String::from_utf8_lossy(&out).into_owned();
        text.push('\n');
        text.push_str(&String::from_utf8_lossy(&err));
        Ok::<_, String>((status.code(), text))
    };
    tokio::time::timeout(TIME_LIMIT, work)
        .await
        .map_err(|_| "the checker took too long".to_string())?
}

#[cfg(windows)]
mod job {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };

    pub struct Job(HANDLE);

    // SAFETY: a job handle may be used and closed from any thread.
    unsafe impl Send for Job {}

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: the handle came from CreateJobObjectW and is closed once. Closing it kills the job's processes.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Put the process in a new job that caps each process's committed memory and kills them when the job is dropped.
    pub fn contain(child: &tokio::process::Child, memory: u64) -> Option<Job> {
        let process = child.raw_handle()? as HANDLE;
        // SAFETY: plain Win32 calls on a handle we own (the job) and the child's live process handle; the limit
        // structure is zeroed, then filled, and passed with its own size.
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return None;
            }
            let job = Job(handle);
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            info.ProcessMemoryLimit = usize::try_from(memory).ok()?;
            let set = SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if set == 0 || AssignProcessToJobObject(job.0, process) == 0 {
                return None;
            }
            Some(job)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checker_output_becomes_problems_by_line() {
        assert_eq!(
            tabbed("3\tMissing closing '}'.\n\nnoise\n\tno line\n"),
            vec![
                Problem {
                    line: Some(3),
                    message: "Missing closing '}'.".into()
                },
                Problem {
                    line: None,
                    message: "no line".into()
                },
            ]
        );
        assert_eq!(
            bash_messages(
                "bash: line 4: syntax error near unexpected token `fi'\nbash: line 4: `fi'\n"
            ),
            vec![Problem {
                line: Some(4),
                message: "syntax error near unexpected token `fi'".into()
            }]
        );
    }

    #[test]
    fn only_a_finished_parse_counts_as_checked() {
        let bash = checker("bash").unwrap();
        let clean = outcome(&bash, Ok((Some(0), String::new())));
        assert!(clean.checker.is_some() && clean.problems.is_empty());
        let found = outcome(&bash, Ok((Some(2), "bash: line 3: syntax error\n".into())));
        assert_eq!(found.problems.len(), 1);
        for failed in [
            Ok((Some(2), "something went wrong\n".to_string())), // a parse exit code, but nothing parsed
            Ok((Some(127), String::new())),                      // not a parse exit code
            Ok((None, String::new())),                           // killed by a signal
            Ok((None, "bash: line 3: syntax error\n".to_string())), // killed partway: incomplete
            Err("the checker took too long".to_string()),
        ] {
            let r = outcome(&bash, failed.clone());
            assert!(
                r.checker.is_none() && r.unchecked.is_some(),
                "{failed:?} → {r:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_save_waits_briefly_for_a_checker_then_is_told_the_server_is_busy() {
        let running = Semaphore::new(2);
        let wait = Duration::from_millis(200);
        let (a, b) = (
            admit(&running, wait).await.unwrap(),
            admit(&running, wait).await.unwrap(),
        );
        let started = std::time::Instant::now();
        assert_eq!(admit(&running, wait).await.err(), Some(Busy));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(a);
        assert!(admit(&running, wait).await.is_ok());
        drop(b);
    }

    #[test]
    fn long_messages_are_clipped() {
        assert_eq!(clip(&"é".repeat(400)).chars().count(), MAX_MESSAGE + 1);
        assert_eq!(clip("short"), "short");
    }

    #[tokio::test]
    async fn turned_off_or_unknown_is_unchecked_never_clean() {
        let off = check(false, "bash", "echo hi").await.unwrap();
        assert!(off.checker.is_none() && off.unchecked.is_some());
        let unknown = check(true, "cobol", "x").await.unwrap();
        assert!(unknown.checker.is_none() && unknown.unchecked.is_some());
    }

    #[tokio::test]
    async fn powershell_never_parses_what_it_would_resolve() {
        for s in [
            "using module \\\\host\\share\\M.psm1\nWrite-Output x",
            "USING   Assembly C:\\x.dll",
            "using namespace System;using module Foo",
            "using `\n module Foo",
        ] {
            assert!(resolves_while_parsing(s), "{s:?}");
            let r = check(true, "powershell", s).await.unwrap();
            assert!(
                r.checker.is_none() && r.unchecked.unwrap().contains("using module"),
                "{s:?}"
            );
        }
        assert!(!resolves_while_parsing(
            "using namespace System.IO\n# a module, using it"
        ));
    }

    /// A checker that needs more memory than its limit is stopped and reported as not checked; the same checker under
    /// the same limit still parses a small script.
    #[tokio::test]
    async fn checkers_stop_at_their_memory_limit() {
        let c = checker("python").unwrap();
        let Some(program) = c.programs.iter().find_map(|p| find(p)) else {
            return; // no Python here: covered where it is installed
        };
        let limit = 128 * 1024 * 1024;
        let small = outcome(&c, run(&program, &c, limit, "print(1)\n").await);
        assert!(small.checker.is_some(), "{small:?}");
        // About 240 MiB to compile.
        let big = outcome(
            &c,
            run(&program, &c, limit, &"x\n".repeat(128 * 1024)).await,
        );
        assert!(big.checker.is_none() && big.unchecked.is_some(), "{big:?}");
    }

    /// Runs only where the parser is installed; otherwise it must say so. `FLYW8T_TEST_REQUIRE_CHECKERS=bash,python,...`
    /// makes a missing one fail.
    #[tokio::test]
    async fn real_parsers_find_errors_without_running_anything() {
        let marker = std::env::temp_dir().join(format!("flyw8t-check-{}", std::process::id()));
        let m = marker.display().to_string().replace('\\', "/");
        let cases = [
            (
                "bash",
                format!("touch '{m}'\nif true; then\n  echo x\n"),
                format!("touch '{m}'\necho ok\n"),
            ),
            (
                "python",
                format!("open(r'{m}', 'w')\ndef f(:\n  pass\n"),
                format!("open(r'{m}', 'w')\nprint('ok')\n"),
            ),
            (
                "powershell",
                format!("New-Item -Path '{m}'\nfunction f {{\n"),
                format!("New-Item -Path '{m}'\nWrite-Output ok\n"),
            ),
        ];
        for (lang, bad, good) in cases {
            let b = check(true, lang, &bad).await.unwrap();
            let g = check(true, lang, &good).await.unwrap();
            match &b.checker {
                None => {
                    assert!(b.unchecked.is_some(), "{lang}: unchecked must say why");
                    // Where the parsers are known to be installed (CI), a missing one is a failure, not a skip.
                    let required =
                        std::env::var("FLYW8T_TEST_REQUIRE_CHECKERS").unwrap_or_default();
                    assert!(!required.split(',').any(|r| r == lang), "{lang}: {b:?}");
                }
                Some(_) => {
                    assert!(!b.problems.is_empty(), "{lang}: {b:?}");
                    assert!(
                        b.problems.iter().all(|p| p.line.is_some_and(|l| l >= 2)),
                        "{lang}: {b:?}"
                    );
                    assert!(
                        g.checker.is_some() && g.problems.is_empty(),
                        "{lang}: {g:?}"
                    );
                }
            }
            assert!(!marker.exists(), "{lang}: the check ran the script");
        }
    }
}
