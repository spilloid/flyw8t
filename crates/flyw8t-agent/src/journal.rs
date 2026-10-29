//! The durable job journal: the agent's at-most-once guarantee.
//!
//! Rules, in order of importance:
//!
//! 1. A job is written to disk (`Accepted`) **before** the agent acknowledges it and before it
//!    can start. A job id present in the journal is never executed again, however many times
//!    it is offered.
//! 2. `Started` is written **before** execution begins. On restart, an entry that is
//!    `Accepted` but not `Started` provably never ran (`NotStarted`); one that is `Started`
//!    but not `Finished` may have done anything (`Interrupted`, outcome unknown). Neither is
//!    re-run.
//! 3. A final report is kept and re-sent until the server acknowledges storing it.
//! 4. Retention is bounded: only server-acknowledged entries are ever pruned.
//!
//! Each entry is its own small file, replaced atomically, so a crash mid-write leaves the
//! previous version intact.

use crate::config::write_atomic;
use anyhow::{Context, Result};
use flyw8t_protocol::messages::{ExecOutcome, Finished, JobPhase, JobReport};
use flyw8t_protocol::Action;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Acknowledged entries older than this are pruned.
const RETAIN_ACKED: Duration = Duration::days(30);
/// At most this many acknowledged entries are kept regardless of age.
const MAX_ACKED: usize = 5000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub job_id: Uuid,
    /// `None` for a cancel tombstone: a job cancelled before this agent ever saw its offer.
    pub action: Option<Action>,
    pub timeout_secs: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    pub state: EntryState,
    pub server_acked: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EntryState {
    Accepted,
    Started {
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    Finished {
        report: Box<Finished>,
    },
}

impl Entry {
    pub fn report(&self) -> JobReport {
        let phase = match &self.state {
            EntryState::Accepted => JobPhase::Accepted,
            EntryState::Started { at } => JobPhase::Started { at: *at },
            EntryState::Finished { report } => JobPhase::Finished(report.clone()),
        };
        JobReport {
            job_id: self.job_id,
            phase,
        }
    }

    fn finished_at(&self) -> Option<OffsetDateTime> {
        match &self.state {
            EntryState::Finished { report } => Some(report.finished_at),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Accept {
    /// First time this job id has been seen. It is now journaled and must be run.
    New,
    /// Already journaled. Do not run; re-send this entry's report instead.
    Known(Box<Entry>),
}

pub struct Journal {
    dir: PathBuf,
    entries: Mutex<HashMap<Uuid, Entry>>,
}

impl Journal {
    /// Open the journal, resolving anything a previous process left unfinished.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut entries = HashMap::new();
        for item in std::fs::read_dir(dir)? {
            let path = item?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match std::fs::read(&path)
                .map_err(anyhow::Error::from)
                .and_then(|b| serde_json::from_slice::<Entry>(&b).map_err(Into::into))
            {
                Ok(entry) => {
                    entries.insert(entry.job_id, entry);
                }
                Err(e) => {
                    // Atomic replacement makes this unexpected. Keep the file for inspection.
                    tracing::error!(path = %path.display(), error = %e, "unreadable journal entry; quarantining");
                    let _ = std::fs::rename(&path, path.with_extension("corrupt"));
                }
            }
        }
        let journal = Self {
            dir: dir.to_path_buf(),
            entries: Mutex::new(entries),
        };
        journal.recover()?;
        journal.prune()?;
        Ok(journal)
    }

    /// Entries left mid-flight by a previous process become final, without re-running.
    fn recover(&self) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let mut entries = self.entries.lock().unwrap();
        for entry in entries.values_mut() {
            let outcome = match &entry.state {
                EntryState::Accepted => ExecOutcome::NotStarted {
                    reason: "the agent restarted before execution began; it was not run".into(),
                },
                EntryState::Started { .. } => ExecOutcome::Interrupted {
                    reason:
                        "the agent stopped while this was running; it may or may not have completed"
                            .into(),
                },
                EntryState::Finished { .. } => continue,
            };
            let started_at = match entry.state {
                EntryState::Started { at } => Some(at),
                _ => None,
            };
            entry.state = EntryState::Finished {
                report: Box::new(Finished {
                    outcome,
                    started_at,
                    finished_at: now,
                    stdout: None,
                    stderr: None,
                    structured: None,
                }),
            };
            tracing::warn!(job_id = %entry.job_id, "recovered unfinished job from a previous run");
            self.persist(entry)?;
        }
        Ok(())
    }

    fn path(&self, job_id: Uuid) -> PathBuf {
        self.dir.join(format!("{job_id}.json"))
    }

    fn persist(&self, entry: &Entry) -> Result<()> {
        write_atomic(&self.path(entry.job_id), &serde_json::to_vec(entry)?)
    }

    /// Record a job offer. Returns `New` exactly once per job id, ever (within retention).
    pub fn accept(&self, job_id: Uuid, action: &Action, timeout_secs: u32) -> Result<Accept> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(existing) = entries.get(&job_id) {
            return Ok(Accept::Known(Box::new(existing.clone())));
        }
        let entry = Entry {
            job_id,
            action: Some(action.clone()),
            timeout_secs,
            received_at: OffsetDateTime::now_utc(),
            state: EntryState::Accepted,
            server_acked: false,
        };
        self.persist(&entry)?;
        entries.insert(job_id, entry);
        Ok(Accept::New)
    }

    /// Record that execution is about to begin. Must succeed before the work starts.
    pub fn mark_started(&self, job_id: Uuid, at: OffsetDateTime) -> Result<()> {
        self.update(job_id, |e| {
            if matches!(e.state, EntryState::Accepted) {
                e.state = EntryState::Started { at };
            }
        })
    }

    pub fn finish(&self, job_id: Uuid, report: Finished) -> Result<()> {
        self.update(job_id, |e| {
            if !matches!(e.state, EntryState::Finished { .. }) {
                e.state = EntryState::Finished {
                    report: Box::new(report),
                };
            }
        })
    }

    /// Record a cancel for a job this agent has never seen, so a later offer is not run.
    /// Returns the entry to report. If the job is already known, nothing changes.
    pub fn cancel_unknown(&self, job_id: Uuid) -> Result<Entry> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(existing) = entries.get(&job_id) {
            return Ok(existing.clone());
        }
        let now = OffsetDateTime::now_utc();
        let entry = Entry {
            job_id,
            action: None,
            timeout_secs: 0,
            received_at: now,
            state: EntryState::Finished {
                report: Box::new(Finished {
                    outcome: ExecOutcome::Cancelled { started: false },
                    started_at: None,
                    finished_at: now,
                    stdout: None,
                    stderr: None,
                    structured: None,
                }),
            },
            server_acked: false,
        };
        self.persist(&entry)?;
        entries.insert(job_id, entry.clone());
        Ok(entry)
    }

    /// The server has durably stored this job's final report.
    pub fn mark_acked(&self, job_id: Uuid) -> Result<()> {
        self.update(job_id, |e| {
            if matches!(e.state, EntryState::Finished { .. }) {
                e.server_acked = true;
            }
        })
    }

    pub fn get(&self, job_id: Uuid) -> Option<Entry> {
        self.entries.lock().unwrap().get(&job_id).cloned()
    }

    /// Latest report for every entry the server has not acknowledged, oldest first.
    pub fn unreported(&self) -> Vec<JobReport> {
        let entries = self.entries.lock().unwrap();
        let mut pending: Vec<&Entry> = entries.values().filter(|e| !e.server_acked).collect();
        pending.sort_by_key(|e| e.received_at);
        pending.into_iter().map(Entry::report).collect()
    }

    fn update(&self, job_id: Uuid, f: impl FnOnce(&mut Entry)) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .get_mut(&job_id)
            .with_context(|| format!("job {job_id} is not in the journal"))?;
        let before = entry.clone();
        f(entry);
        if *entry != before {
            self.persist(entry)?;
        }
        Ok(())
    }

    /// Drop old acknowledged entries. Unacknowledged entries are never pruned.
    pub fn prune(&self) -> Result<usize> {
        let now = OffsetDateTime::now_utc();
        let mut entries = self.entries.lock().unwrap();
        let mut acked: Vec<(OffsetDateTime, Uuid)> = entries
            .values()
            .filter(|e| e.server_acked)
            .map(|e| (e.finished_at().unwrap_or(e.received_at), e.job_id))
            .collect();
        acked.sort();
        let excess = acked.len().saturating_sub(MAX_ACKED);
        let doomed: Vec<Uuid> = acked
            .iter()
            .enumerate()
            .filter(|(i, (at, _))| *i < excess || now - *at > RETAIN_ACKED)
            .map(|(_, (_, id))| *id)
            .collect();
        for id in &doomed {
            entries.remove(id);
            let _ = std::fs::remove_file(self.path(*id));
        }
        Ok(doomed.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(outcome: ExecOutcome) -> Finished {
        Finished {
            outcome,
            started_at: None,
            finished_at: OffsetDateTime::now_utc(),
            stdout: None,
            stderr: None,
            structured: None,
        }
    }

    #[test]
    fn a_job_id_is_new_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path()).unwrap();
        let id = Uuid::new_v4();
        assert_eq!(j.accept(id, &Action::NetIpconfig, 30).unwrap(), Accept::New);
        assert!(matches!(
            j.accept(id, &Action::NetIpconfig, 30).unwrap(),
            Accept::Known(_)
        ));
    }

    #[test]
    fn duplicates_are_detected_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        {
            let j = Journal::open(dir.path()).unwrap();
            j.accept(id, &Action::NetIpconfig, 30).unwrap();
            j.mark_started(id, OffsetDateTime::now_utc()).unwrap();
            j.finish(id, done(ExecOutcome::Exited { code: 0 })).unwrap();
            j.mark_acked(id).unwrap();
        }
        let j = Journal::open(dir.path()).unwrap();
        assert!(matches!(
            j.accept(id, &Action::NetIpconfig, 30).unwrap(),
            Accept::Known(_)
        ));
    }

    #[test]
    fn restart_before_start_reports_not_started() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        Journal::open(dir.path())
            .unwrap()
            .accept(id, &Action::SystemInfo, 30)
            .unwrap();
        let j = Journal::open(dir.path()).unwrap();
        let EntryState::Finished { report } = j.get(id).unwrap().state else {
            panic!("recovered entry should be finished");
        };
        assert!(matches!(report.outcome, ExecOutcome::NotStarted { .. }));
    }

    #[test]
    fn restart_mid_execution_reports_interrupted_and_never_reruns() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        {
            let j = Journal::open(dir.path()).unwrap();
            j.accept(id, &Action::SystemInfo, 30).unwrap();
            j.mark_started(id, OffsetDateTime::now_utc()).unwrap();
        }
        let j = Journal::open(dir.path()).unwrap();
        let EntryState::Finished { report } = j.get(id).unwrap().state else {
            panic!("recovered entry should be finished");
        };
        assert!(matches!(report.outcome, ExecOutcome::Interrupted { .. }));
        assert!(report.started_at.is_some());
        assert!(matches!(
            j.accept(id, &Action::SystemInfo, 30).unwrap(),
            Accept::Known(_)
        ));
        assert_eq!(
            j.unreported().len(),
            1,
            "the interrupted result must still be reported"
        );
    }

    #[test]
    fn cancel_before_offer_blocks_a_late_offer() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path()).unwrap();
        let id = Uuid::new_v4();
        j.cancel_unknown(id).unwrap();
        assert!(matches!(
            j.accept(id, &Action::NetIpconfig, 30).unwrap(),
            Accept::Known(_)
        ));
    }

    #[test]
    fn finish_is_write_once() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path()).unwrap();
        let id = Uuid::new_v4();
        j.accept(id, &Action::NetIpconfig, 30).unwrap();
        j.finish(id, done(ExecOutcome::Exited { code: 0 })).unwrap();
        j.finish(id, done(ExecOutcome::TimedOut)).unwrap();
        let EntryState::Finished { report } = j.get(id).unwrap().state else {
            panic!()
        };
        assert_eq!(report.outcome, ExecOutcome::Exited { code: 0 });
    }

    #[test]
    fn only_acked_entries_are_reported_done_and_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path()).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        for id in [a, b] {
            j.accept(id, &Action::NetIpconfig, 30).unwrap();
            j.finish(id, done(ExecOutcome::Exited { code: 0 })).unwrap();
        }
        j.mark_acked(a).unwrap();
        assert_eq!(
            j.unreported().iter().map(|r| r.job_id).collect::<Vec<_>>(),
            vec![b]
        );
        // Ack before finish is ignored: a non-final report can't be acknowledged away.
        let c = Uuid::new_v4();
        j.accept(c, &Action::NetIpconfig, 30).unwrap();
        j.mark_acked(c).unwrap();
        assert!(!j.get(c).unwrap().server_acked);
        assert_eq!(j.prune().unwrap(), 0, "recent acked entries are retained");
    }

    #[test]
    fn corrupt_entries_are_quarantined_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(format!("{}.json", Uuid::new_v4())),
            b"{not json",
        )
        .unwrap();
        let j = Journal::open(dir.path()).unwrap();
        assert!(j.unreported().is_empty());
        assert!(std::fs::read_dir(dir.path()).unwrap().any(|e| e
            .unwrap()
            .path()
            .extension()
            .is_some_and(|x| x == "corrupt")));
    }
}
