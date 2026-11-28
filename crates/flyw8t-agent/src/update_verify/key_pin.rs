//! A Windows administrator's independent release verification key.

use crate::config::{default_state_dir, is_default_state_dir};
use crate::winsec::{check_private_dir, check_private_file, publish_private_file_once};
use anyhow::{ensure, Context, Result};
use flyw8t_protocol::trust::sig::ed25519_key_is_canonical;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

const FILE: &str = "release-public-key.bin";

pub fn parse(hex: &str) -> Result<[u8; 32]> {
    let mut key = [0; 32];
    hex::decode_to_slice(hex, &mut key).context("the update public key must be 64 hex digits")?;
    ensure!(ed25519_key_is_canonical(&key), "invalid Ed25519 public key");
    Ok(key)
}

fn protected_path(state_dir: &Path) -> Result<PathBuf> {
    ensure!(
        is_default_state_dir(state_dir)?,
        "the release key pin requires the default Windows agent state folder"
    );
    let state = default_state_dir()?;
    check_private_dir(state.parent().context("missing state folder parent")?)?;
    check_private_dir(&state)?;
    Ok(state.join(FILE))
}

pub fn load(state_dir: &Path) -> Result<Option<[u8; 32]>> {
    read_at(&protected_path(state_dir)?)
}

/// Pin the first key. `false` means this key was already pinned.
pub fn pin(state_dir: &Path, key: &[u8; 32]) -> Result<bool> {
    ensure!(ed25519_key_is_canonical(key), "invalid Ed25519 public key");
    pin_at(&protected_path(state_dir)?, key)
}

fn read_at(path: &Path) -> Result<Option<[u8; 32]>> {
    match fs::symlink_metadata(path) {
        Ok(_) => check_private_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .context("opening the pinned release public key")?;
    let mut key = [0; 32];
    file.read_exact(&mut key)
        .context("reading the pinned release public key")?;
    ensure!(
        file.read(&mut [0; 1])? == 0 && ed25519_key_is_canonical(&key),
        "invalid pinned release public key"
    );
    Ok(Some(key))
}

fn pin_at(path: &Path, key: &[u8; 32]) -> Result<bool> {
    let (held, created) = match read_at(path)? {
        Some(held) => (held, false),
        None => {
            let created = publish_private_file_once(path, key)?;
            let held = read_at(path)?.context("the pinned release public key disappeared")?;
            (held, created)
        }
    };
    ensure!(
        held == *key,
        "a different release public key is already pinned"
    );
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::winsec::{create_dir, Created, PRIVATE};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn parse_requires_a_canonical_ed25519_public_key() {
        let expected = key(1);
        assert_eq!(parse(&hex::encode(expected)).unwrap(), expected);
        assert!(parse(&"00".repeat(32)).is_err());
        assert!(parse("ff").is_err());
    }

    #[test]
    fn custom_state_cannot_hold_a_pin() {
        let temporary = tempfile::tempdir().unwrap();
        for result in [
            load(temporary.path()).map(|_| ()),
            pin(temporary.path(), &key(1)).map(|_| ()),
        ] {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("default Windows agent state folder"));
        }
        assert!(!temporary.path().join(FILE).exists());
    }

    #[test]
    #[ignore = "run on an elevated Windows x64 test account to check real NTFS permissions"]
    fn first_pin_wins_and_insecure_or_damaged_files_fail_closed() {
        use std::sync::Barrier;

        let temporary = tempfile::tempdir().unwrap();
        let protected = temporary.path().join("protected");
        assert_eq!(create_dir(&protected, PRIVATE).unwrap(), Created::New);
        check_private_dir(&protected).unwrap();
        let path = protected.join(FILE);
        let keys = [key(1), key(2)];
        assert_eq!(read_at(&path).unwrap(), None);
        let gate = Barrier::new(2);
        let (left, right) = std::thread::scope(|scope| {
            let attempt = |key: [u8; 32]| {
                gate.wait();
                pin_at(&path, &key)
            };
            let left = scope.spawn(move || attempt(keys[0]));
            let right = scope.spawn(move || attempt(keys[1]));
            (left.join().unwrap(), right.join().unwrap())
        });
        let (winner, loser, refused) = match (left, right) {
            (Ok(true), Err(error)) => (keys[0], keys[1], error),
            (Err(error), Ok(true)) => (keys[1], keys[0], error),
            other => panic!("one writer must win, got {other:?}"),
        };
        assert!(refused.to_string().contains("different release public key"));
        assert!(!publish_private_file_once(&path, &loser).unwrap());
        assert_eq!(read_at(&path).unwrap(), Some(winner));
        assert!(!pin_at(&path, &winner).unwrap());
        assert!(pin_at(&path, &loser).is_err());
        let link = protected.join("other-name");
        fs::hard_link(&path, &link).unwrap();
        assert!(read_at(&path)
            .unwrap_err()
            .to_string()
            .contains("hard link"));
        fs::remove_file(link).unwrap();
        fs::write(&path, b"bad key").unwrap();
        assert!(pin_at(&path, &winner).is_err());
        assert_eq!(fs::read(path).unwrap(), b"bad key");
    }
}
