//! A log file that keeps itself small: when it would pass `max_bytes` it is renamed to `<name>.1` (replacing the
//! previous one) and a new file is started. Used when the agent runs as a Windows service, where stdout goes nowhere.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    file: File,
    size: u64,
    /// The handle is writing `<name>.1`: a rotation renamed the log but could not start a new one.
    on_backup: bool,
}

impl RotatingFile {
    pub fn open(path: &Path, max_bytes: u64) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            max_bytes,
            file,
            size,
            on_backup: false,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        // While the handle is writing `<name>.1`, only retry starting the new file: never remove or rename the file
        // being written, whatever has appeared at the log's own name meanwhile.
        if !self.on_backup {
            let old = self.path.with_extension("log.1");
            let _ = std::fs::remove_file(&old);
            // Rust opens files with delete sharing on Windows, so the open log can be renamed.
            std::fs::rename(&self.path, &old)?;
            self.on_backup = true;
        }
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.on_backup = false;
        self.size = 0;
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.size > 0 && self.size + buf.len() as u64 > self.max_bytes && self.rotate().is_err()
        {
            // Keep logging to the handle we have, and try again after another `max_bytes`.
            self.size = 0;
        }
        let n = self.file.write(buf)?;
        self.size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_at_the_limit_and_keeps_one_old_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs").join("agent.log");
        let mut f = RotatingFile::open(&path, 100).unwrap();
        for i in 0..3 {
            f.write_all(format!("{i}:{}\n", "x".repeat(58)).as_bytes())
                .unwrap();
        }
        drop(f);
        let current = std::fs::read_to_string(&path).unwrap();
        let old = std::fs::read_to_string(path.with_extension("log.1")).unwrap();
        assert!(current.starts_with("2:"), "{current}");
        assert!(old.starts_with("1:"), "{old}");

        // Reopening appends, counting what is already there.
        let mut f = RotatingFile::open(&path, 100).unwrap();
        f.write_all(format!("3:{}\n", "y".repeat(58)).as_bytes())
            .unwrap();
        drop(f);
        assert!(std::fs::read_to_string(&path).unwrap().starts_with("3:"));
        assert!(std::fs::read_to_string(path.with_extension("log.1"))
            .unwrap()
            .starts_with("2:"));
    }
}
