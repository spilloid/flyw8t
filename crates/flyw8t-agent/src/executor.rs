//! Runs one catalog action with a time limit and a cancellation token.
//!
//! There is no shell anywhere in this file. Child processes are fixed binaries at absolute
//! paths with argument vectors built from validated parameters.

use flyw8t_protocol::messages::{CapturedStream, ExecOutcome, Finished};
use flyw8t_protocol::{Action, MAX_STREAM_BYTES};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::sync::CancellationToken;

/// How long to wait for a killed child's pipes to drain before giving up on them.
const DRAIN_GRACE: Duration = Duration::from_secs(5);

pub async fn execute(
    action: &Action,
    timeout: Duration,
    cancel: CancellationToken,
    started_at: OffsetDateTime,
) -> Finished {
    // The server validated this, but the agent never relies on that.
    if let Err(e) = action.validate() {
        return finished(
            started_at,
            ExecOutcome::Failed {
                error: e.to_string(),
            },
            None,
            None,
            None,
        );
    }
    match action {
        Action::SystemInfo => {
            in_process(started_at, timeout, cancel, || {
                serde_json::to_value(crate::collect::inventory()).map_err(|e| e.to_string())
            })
            .await
        }
        Action::ProcessTop { limit } => {
            let limit = *limit;
            in_process(started_at, timeout, cancel, move || {
                serde_json::to_value(crate::collect::process_top(limit)).map_err(|e| e.to_string())
            })
            .await
        }
        Action::NetIpconfig => match ipconfig_command() {
            Some((program, args)) => run_process(started_at, program, args, timeout, cancel).await,
            None => unavailable(
                started_at,
                "no network configuration tool found on this system",
            ),
        },
        Action::NetPing { target } => match ping_command(target) {
            Some((program, args)) => run_process(started_at, program, args, timeout, cancel).await,
            None => unavailable(started_at, "no ping tool found on this system"),
        },
    }
}

fn finished(
    started_at: OffsetDateTime,
    outcome: ExecOutcome,
    stdout: Option<CapturedStream>,
    stderr: Option<CapturedStream>,
    structured: Option<serde_json::Value>,
) -> Finished {
    Finished {
        outcome,
        started_at: Some(started_at),
        finished_at: OffsetDateTime::now_utc(),
        stdout,
        stderr,
        structured,
    }
}

fn unavailable(started_at: OffsetDateTime, why: &str) -> Finished {
    finished(
        started_at,
        ExecOutcome::Failed { error: why.into() },
        None,
        None,
        None,
    )
}

/// Run a read-only collector on a blocking thread. A collector that overruns its time limit
/// cannot be killed (it is a thread, not a process); it is abandoned and the job reports
/// `TimedOut`. Collectors are read-only, so abandoning one is safe.
async fn in_process<F>(
    started_at: OffsetDateTime,
    timeout: Duration,
    cancel: CancellationToken,
    f: F,
) -> Finished
where
    F: FnOnce() -> Result<serde_json::Value, String> + Send + 'static,
{
    let task = tokio::task::spawn_blocking(f);
    tokio::select! {
        r = task => match r {
            Ok(Ok(value)) => finished(started_at, ExecOutcome::Collected, None, None, Some(value)),
            Ok(Err(e)) => finished(started_at, ExecOutcome::Failed { error: e }, None, None, None),
            Err(e) => finished(started_at, ExecOutcome::Failed { error: format!("collector panicked: {e}") }, None, None, None),
        },
        _ = tokio::time::sleep(timeout) => finished(started_at, ExecOutcome::TimedOut, None, None, None),
        _ = cancel.cancelled() => finished(started_at, ExecOutcome::Cancelled { started: true }, None, None, None),
    }
}

async fn run_process(
    started_at: OffsetDateTime,
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    cancel: CancellationToken,
) -> Finished {
    let mut cmd = tokio::process::Command::new(&program);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return unavailable(
                started_at,
                &format!("could not start {}: {e}", program.display()),
            );
        }
    };
    let out = tokio::spawn(read_bounded(child.stdout.take()));
    let err = tokio::spawn(read_bounded(child.stderr.take()));

    let outcome = tokio::select! {
        status = child.wait() => match status {
            Ok(s) => match s.code() {
                Some(code) => ExecOutcome::Exited { code },
                None => ExecOutcome::Failed { error: format!("process ended without an exit code ({s})") },
            },
            Err(e) => ExecOutcome::Failed { error: format!("waiting for process: {e}") },
        },
        _ = tokio::time::sleep(timeout) => {
            let _ = child.kill().await;
            ExecOutcome::TimedOut
        }
        _ = cancel.cancelled() => {
            let _ = child.kill().await;
            ExecOutcome::Cancelled { started: true }
        }
    };

    let stdout = drain(out).await;
    let stderr = drain(err).await;
    finished(started_at, outcome, Some(stdout), Some(stderr), None)
}

async fn drain(handle: tokio::task::JoinHandle<CapturedStream>) -> CapturedStream {
    match tokio::time::timeout(DRAIN_GRACE, handle).await {
        Ok(Ok(s)) => s,
        _ => CapturedStream {
            data: String::new(),
            total_bytes: 0,
            truncated: true,
        },
    }
}

/// Read a stream to its end, keeping at most `MAX_STREAM_BYTES` and counting the rest.
async fn read_bounded<R: AsyncRead + Unpin>(stream: Option<R>) -> CapturedStream {
    let mut kept = Vec::new();
    let mut total: u64 = 0;
    if let Some(mut s) = stream {
        let mut buf = [0u8; 8192];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n as u64;
                    let room = MAX_STREAM_BYTES.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
    }
    CapturedStream {
        truncated: total > kept.len() as u64,
        data: String::from_utf8_lossy(&kept).into_owned(),
        total_bytes: total,
    }
}

#[cfg(windows)]
fn system32(exe: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join(exe)
}

fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| p.is_file())
}

fn ipconfig_command() -> Option<(PathBuf, Vec<String>)> {
    #[cfg(windows)]
    {
        Some((system32("ipconfig.exe"), vec!["/all".into()]))
    }
    #[cfg(not(windows))]
    {
        first_existing(&["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"])
            .map(|p| (p, vec!["addr".into()]))
    }
}

/// `target` has been validated as an IP address or hostname and cannot start with `-`.
fn ping_command(target: &str) -> Option<(PathBuf, Vec<String>)> {
    #[cfg(windows)]
    {
        let _ = first_existing;
        Some((
            system32("PING.EXE"),
            vec![
                "-n".into(),
                "4".into(),
                "-w".into(),
                "2000".into(),
                target.into(),
            ],
        ))
    }
    #[cfg(not(windows))]
    {
        first_existing(&["/usr/bin/ping", "/bin/ping"]).map(|p| {
            (
                p,
                vec![
                    "-c".into(),
                    "4".into(),
                    "-W".into(),
                    "2".into(),
                    "--".into(),
                    target.into(),
                ],
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[tokio::test]
    async fn ipconfig_runs_and_captures_output() {
        let f = execute(
            &Action::NetIpconfig,
            Duration::from_secs(30),
            CancellationToken::new(),
            now(),
        )
        .await;
        assert_eq!(f.outcome, ExecOutcome::Exited { code: 0 }, "{f:?}");
        assert!(!f.stdout.unwrap().data.trim().is_empty());
    }

    #[tokio::test]
    async fn invalid_params_never_reach_a_process() {
        let f = execute(
            &Action::NetPing {
                target: "-t".into(),
            },
            Duration::from_secs(5),
            CancellationToken::new(),
            now(),
        )
        .await;
        assert!(matches!(f.outcome, ExecOutcome::Failed { .. }));
        assert!(f.stdout.is_none());
    }

    #[tokio::test]
    async fn timeout_stops_the_process_and_keeps_partial_output() {
        // TEST-NET-1 never answers, so four pings take ~8s; a 1s limit must stop it.
        let started = std::time::Instant::now();
        let f = execute(
            &Action::NetPing {
                target: "192.0.2.1".into(),
            },
            Duration::from_secs(1),
            CancellationToken::new(),
            now(),
        )
        .await;
        assert_eq!(f.outcome, ExecOutcome::TimedOut, "{f:?}");
        assert!(
            started.elapsed() < Duration::from_secs(7),
            "kill did not take effect"
        );
        assert!(f.stdout.is_some());
    }

    #[tokio::test]
    async fn cancellation_stops_the_process() {
        let cancel = CancellationToken::new();
        let c2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            c2.cancel();
        });
        let f = execute(
            &Action::NetPing {
                target: "192.0.2.1".into(),
            },
            Duration::from_secs(30),
            cancel,
            now(),
        )
        .await;
        assert_eq!(f.outcome, ExecOutcome::Cancelled { started: true });
    }

    #[tokio::test]
    async fn read_bounded_truncates_and_counts() {
        let data = vec![b'x'; MAX_STREAM_BYTES + 100];
        let s = read_bounded(Some(&data[..])).await;
        assert!(s.truncated);
        assert_eq!(s.total_bytes, (MAX_STREAM_BYTES + 100) as u64);
        assert_eq!(s.data.len(), MAX_STREAM_BYTES);
    }
}
