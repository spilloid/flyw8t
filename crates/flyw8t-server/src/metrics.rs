//! Prometheus text exposition at `/metrics`. See `docs/reliability.md` for how these feed
//! the service-level objectives.
//!
//! Job outcome counts are read from the database at scrape time (the database is the
//! record of truth); process-local counters cover things the database does not record.

use crate::Shared;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Counter(AtomicU64);

impl Counter {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

pub static CONNECTS: Counter = Counter::new();
pub static SWEEPS_OK: Counter = Counter::new();
pub static SWEEPS_FAILED: Counter = Counter::new();

pub async fn render(state: &Shared) -> anyhow::Result<String> {
    let mut out = String::new();
    let jobs: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT state, verification, count(*) FROM jobs GROUP BY state, verification ORDER BY 1, 2",
    )
    .fetch_all(&state.db)
    .await?;
    writeln!(
        out,
        "# HELP flyw8t_jobs Jobs by execution state and verification (all time)."
    )?;
    writeln!(out, "# TYPE flyw8t_jobs gauge")?;
    for (s, v, n) in jobs {
        writeln!(out, "flyw8t_jobs{{state=\"{s}\",verification=\"{v}\"}} {n}")?;
    }
    let (devices,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM devices WHERE retired_at IS NULL")
            .fetch_one(&state.db)
            .await?;
    let gauges = [
        (
            "flyw8t_devices_enrolled",
            "Enrolled, non-retired devices.",
            devices as u64,
        ),
        (
            "flyw8t_agents_connected",
            "Devices with a live authenticated connection to this instance.",
            state.registry.connected_devices().len() as u64,
        ),
        (
            "flyw8t_process_start_time_seconds",
            "Unix time this server process started.",
            state.started_unix,
        ),
    ];
    for (name, help, v) in gauges {
        writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}")?;
    }
    let counters = [
        (
            "flyw8t_agent_connects_total",
            "Authenticated agent connections accepted.",
            &CONNECTS,
        ),
        (
            "flyw8t_sweeps_total",
            "Deadline sweeps that completed.",
            &SWEEPS_OK,
        ),
        (
            "flyw8t_sweep_failures_total",
            "Deadline sweeps that failed.",
            &SWEEPS_FAILED,
        ),
    ];
    for (name, help, c) in counters {
        writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}",
            c.get()
        )?;
    }
    Ok(out)
}
