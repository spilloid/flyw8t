//! Syntax checks for script revisions (ADR-0014 section 2): the language's own parser reads the source and reports
//! problems by line. Parsing never runs the script: PowerShell's `Parser.ParseInput`, `bash -n`, Python's `compile()`.
//!
//! Each checker is its own process with an empty environment, the source on standard input and nothing else, a time
//! limit and capped output, and at most two run at once. When no checker is installed, or one does not finish, the
//! result says the source was not checked; it never claims the source is fine. A clean check says nothing about what a
//! script does.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

const TIME_LIMIT: Duration = Duration::from_secs(15);
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
        }),
        "bash" => Some(Checker {
            label: "bash -n",
            programs: &["bash"],
            args: &["--norc", "--noprofile", "-n"],
            parsed: &[0, 1, 2],
            parse: bash_messages,
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

pub async fn check(enabled: bool, language: &str, source: &str) -> SyntaxCheck {
    if !enabled {
        return SyntaxCheck::unchecked("Syntax checks are turned off on this server.");
    }
    let Some(c) = checker(language) else {
        return SyntaxCheck::unchecked("No checker for this language.");
    };
    let Some(program) = c.programs.iter().find_map(|p| find(p)) else {
        return SyntaxCheck::unchecked(format!("Not checked: no {} on this server.", c.label));
    };
    let _slot = RUNNING.acquire().await;
    outcome(&c, run(&program, c.args, source).await)
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

/// Run a checker: the source on standard input, standard output and error together (each capped), within the limit.
async fn run(program: &Path, args: &[&str], source: &str) -> Result<(Option<i32>, String), String> {
    let tmp = std::env::temp_dir();
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
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
    let mut child = cmd
        .spawn()
        .map_err(|_| "the checker could not start".to_string())?;
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

    #[test]
    fn long_messages_are_clipped() {
        assert_eq!(clip(&"é".repeat(400)).chars().count(), MAX_MESSAGE + 1);
        assert_eq!(clip("short"), "short");
    }

    #[tokio::test]
    async fn turned_off_or_unknown_is_unchecked_never_clean() {
        let off = check(false, "bash", "echo hi").await;
        assert!(off.checker.is_none() && off.unchecked.is_some());
        let unknown = check(true, "cobol", "x").await;
        assert!(unknown.checker.is_none() && unknown.unchecked.is_some());
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
            let b = check(true, lang, &bad).await;
            let g = check(true, lang, &good).await;
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
