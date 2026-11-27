//! Spent run authorizations and the time high-water mark (ADR-0015 section 5).
//!
//! A C2 or C3 run authorization is spent before anything of its job runs, and the record is kept forever: about 50
//! bytes per run. The store is an append-only file of fixed-size records, flushed before `spend` returns; it is not
//! the job journal, which forgets old jobs. If the store cannot be read or written, nothing that needs an
//! authorization runs.
//!
//! The high-water mark is the latest time this agent has seen. A clock wound back past it refuses every run that
//! needs an authorization until the clock catches up, so an old, unused authorization cannot become current again.

use anyhow::{bail, Context, Result};
use flyw8t_protocol::trust::statement::CLOCK_TOLERANCE_SECS;
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

pub const SPENT_FILE: &str = "spent-runs.bin";
pub const HIGH_WATER_FILE: &str = "time-high-water";
/// "flyw8t spent v1": a header so a different file is never read as this one.
const MAGIC: &[u8; 16] = b"flyw8t spent v1\n";
/// deployment (16) + job (16).
const RECORD: usize = 32;

pub struct Spent {
    path: PathBuf,
    high_water_path: PathBuf,
    inner: Mutex<Inner>,
}

struct Inner {
    file: std::fs::File,
    seen: HashSet<(Uuid, Uuid)>,
    high_water: u64,
    append_disabled: bool,
}

impl Spent {
    pub fn open(state_dir: &Path) -> Result<Spent> {
        let path = state_dir.join(SPENT_FILE);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let mut raw = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut raw)?;
        if raw.is_empty() {
            file.seek(SeekFrom::Start(0))?;
            file.write_all(MAGIC)?;
            file.sync_all()?;
        } else if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
            bail!("{} is not a spent-run store", path.display());
        }
        let body = raw.get(MAGIC.len()..).unwrap_or(&[]);
        // A torn last record (power cut mid-append) was never acknowledged as spent; it is ignored, and the run
        // it belonged to did not start (spending happens before anything runs).
        let mut seen = HashSet::new();
        for rec in body.as_chunks::<RECORD>().0 {
            let d = Uuid::from_slice(&rec[..16]).expect("16 bytes");
            let j = Uuid::from_slice(&rec[16..]).expect("16 bytes");
            seen.insert((d, j));
        }
        if body.len() % RECORD != 0 {
            let keep = (MAGIC.len() + body.len() / RECORD * RECORD) as u64;
            file.set_len(keep)?;
            file.sync_all()?;
        }
        let high_water_path = state_dir.join(HIGH_WATER_FILE);
        let high_water = match std::fs::read_to_string(&high_water_path) {
            Ok(s) => s
                .trim()
                .parse()
                .context("the time high-water mark is damaged")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e).context("reading the time high-water mark"),
        };
        Ok(Spent {
            path,
            high_water_path,
            inner: Mutex::new(Inner {
                file,
                seen,
                high_water,
                append_disabled: false,
            }),
        })
    }

    pub fn is_spent(&self, deployment: Uuid, job: Uuid) -> bool {
        self.inner.lock().unwrap().seen.contains(&(deployment, job))
    }

    /// Whether the clock reading `now` is acceptable: not behind the mark by more than the tolerance.
    pub fn clock_ok(&self, now: u64) -> bool {
        now.saturating_add(CLOCK_TOLERANCE_SECS) >= self.inner.lock().unwrap().high_water
    }

    pub fn high_water(&self) -> u64 {
        self.inner.lock().unwrap().high_water
    }

    /// Record `job` as spent, durably, or fail. A job already spent is refused.
    pub fn spend(&self, deployment: Uuid, job: Uuid) -> Result<()> {
        self.spend_with(deployment, job, std::fs::File::write_all)
    }

    fn spend_with(
        &self,
        deployment: Uuid,
        job: Uuid,
        append: impl FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
    ) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.append_disabled {
            bail!("the spent-run store is closed until restart");
        }
        if g.seen.contains(&(deployment, job)) {
            bail!("this run authorization was already used");
        }
        let end = g
            .file
            .seek(SeekFrom::End(0))
            .with_context(|| format!("seeking to the end of {}", self.path.display()))?;
        if end < MAGIC.len() as u64 || !(end - MAGIC.len() as u64).is_multiple_of(RECORD as u64) {
            g.append_disabled = true;
            bail!("the spent-run store has an unaligned length");
        }
        let mut rec = [0u8; RECORD];
        rec[..16].copy_from_slice(deployment.as_bytes());
        rec[16..].copy_from_slice(job.as_bytes());
        if let Err(error) = append(&mut g.file, &rec).and_then(|_| g.file.sync_all()) {
            // A failed write can leave part of a record behind. Do not allow another
            // append unless the previous length has been restored durably.
            if let Err(rollback) = g.file.set_len(end).and_then(|_| g.file.sync_all()) {
                g.append_disabled = true;
                return Err(error).with_context(|| {
                    format!(
                        "recording the spent run in {} (rollback failed: {rollback})",
                        self.path.display()
                    )
                });
            }
            return Err(error)
                .with_context(|| format!("recording the spent run in {}", self.path.display()));
        }
        g.seen.insert((deployment, job));
        Ok(())
    }

    /// Advance the high-water mark to `now`, durably, if it is later.
    pub fn advance(&self, now: u64) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if now <= g.high_water {
            return Ok(());
        }
        crate::config::write_atomic(&self.high_water_path, now.to_string().as_bytes())?;
        g.high_water = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spent_runs_are_remembered_across_restarts_and_never_spent_twice() {
        let dir = tempfile::tempdir().unwrap();
        let (d, j) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let s = Spent::open(dir.path()).unwrap();
        assert!(!s.is_spent(d, j));
        s.spend(d, j).unwrap();
        assert!(s.spend(d, j).is_err());
        drop(s);
        let s = Spent::open(dir.path()).unwrap();
        assert!(s.is_spent(d, j) && s.spend(d, j).is_err());
        assert!(
            !s.is_spent(Uuid::from_u128(9), j),
            "keyed by deployment too"
        );
        drop(s);
        // A torn record is dropped; the whole ones are kept.
        let p = dir.path().join(SPENT_FILE);
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(&[7; 10]).unwrap();
        drop(f);
        let s = Spent::open(dir.path()).unwrap();
        assert!(s.is_spent(d, j));
        drop(s);
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            (MAGIC.len() + RECORD) as u64
        );
        // Anything else in its place refuses to open.
        std::fs::write(&p, b"not a store").unwrap();
        assert!(Spent::open(dir.path()).is_err());
    }

    #[test]
    fn a_short_failed_append_does_not_corrupt_the_next_spend() {
        let dir = tempfile::tempdir().unwrap();
        let deployment = Uuid::from_u128(1);
        let first = Uuid::from_u128(2);
        let failed = Uuid::from_u128(3);
        let next = Uuid::from_u128(4);
        let store = Spent::open(dir.path()).unwrap();
        store.spend(deployment, first).unwrap();
        let error = store.spend_with(deployment, failed, |file, record| {
            file.write_all(&record[..10])?;
            Err(std::io::Error::other(
                "injected error after a partial write",
            ))
        });
        assert!(error.is_err());
        assert!(!store.is_spent(deployment, failed));
        assert_eq!(
            std::fs::metadata(dir.path().join(SPENT_FILE))
                .unwrap()
                .len(),
            (MAGIC.len() + RECORD) as u64,
        );
        store.spend(deployment, next).unwrap();
        drop(store);

        let store = Spent::open(dir.path()).unwrap();
        assert!(store.is_spent(deployment, first));
        assert!(!store.is_spent(deployment, failed));
        assert!(store.is_spent(deployment, next));
        assert!(store.spend(deployment, next).is_err());
    }

    #[test]
    fn a_clock_wound_back_is_refused_until_it_catches_up() {
        let dir = tempfile::tempdir().unwrap();
        let s = Spent::open(dir.path()).unwrap();
        s.advance(10_000).unwrap();
        s.advance(5_000).unwrap();
        assert_eq!(s.high_water(), 10_000);
        assert!(s.clock_ok(10_000) && s.clock_ok(10_000 - CLOCK_TOLERANCE_SECS));
        assert!(!s.clock_ok(10_000 - CLOCK_TOLERANCE_SECS - 1));
        drop(s);
        assert_eq!(Spent::open(dir.path()).unwrap().high_water(), 10_000);
    }
}
