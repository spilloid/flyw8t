use crate::{confirm, keyfile, passphrase};
use anyhow::{ensure, Context, Result};
use clap::Subcommand;
use ed25519_dalek::Signer;
use flyw8t_protocol::agent_update::{
    Release, SignedRelease, MANIFEST_NAME, MAX_MANIFEST_BYTES, MAX_WINDOWS_AGENT_BYTES,
};
use flyw8t_protocol::trust::Bytes;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub(super) enum Cmd {
    /// Create a dedicated offline update key and print its public half in hex.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a Windows agent artifact from the verified release build.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long, default_value = MANIFEST_NAME)]
        out: PathBuf,
    },
    /// Check manifest signature, version and artifact bytes using an independently trusted key.
    Verify {
        #[arg(long)]
        public_key: String,
        /// Require an update newer than this installed version.
        #[arg(
            long,
            required_unless_present = "release_version",
            conflicts_with = "release_version"
        )]
        current_version: Option<String>,
        /// Require this exact version and its release filename before publication.
        #[arg(long)]
        release_version: Option<String>,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long, default_value = MANIFEST_NAME)]
        manifest: PathBuf,
    },
}

pub(super) fn run(cmd: Cmd, yes: bool) -> Result<()> {
    use keyfile::Purpose::AgentRelease;

    match cmd {
        Cmd::Keygen { out } => {
            let (key, bytes) = keyfile::generate(&passphrase(true)?, AgentRelease)?;
            keyfile::write_private(&out, &bytes)?;
            println!("Made {}", out.display());
            println!("Update public key {}", hex::encode(key.public()));
        }
        Cmd::Sign {
            key,
            version,
            artifact,
            out,
        } => {
            let bytes = read_bounded(&artifact, MAX_WINDOWS_AGENT_BYTES)?;
            let release = Release::from_artifact(version, &bytes)?;
            let name = check_release_filename(&release, &artifact)?;
            release.check_update_image(&bytes)?;
            let key = keyfile::open(&key, &passphrase(false)?, AgentRelease)?;
            println!("Windows x64 agent {}", release.version);
            println!("{name} ({} bytes)\n{}", release.size_bytes, release.sha256);
            println!("Update public key {}", hex::encode(key.public()));
            confirm(yes, "the Windows agent release")?;
            let signature = key.signing.sign(&release.signing_bytes());
            let signed = SignedRelease {
                release,
                signature: Bytes(signature.to_bytes().to_vec()),
            };
            write_manifest(&out, &signed)?;
            println!("Signed {}", out.display());
        }
        Cmd::Verify {
            public_key,
            current_version,
            release_version,
            artifact,
            manifest,
        } => {
            let mut trusted_key = [0u8; 32];
            hex::decode_to_slice(public_key, &mut trusted_key)
                .context("the update public key must be 64 hex digits")?;
            let signed = SignedRelease::parse(&read_bounded(&manifest, MAX_MANIFEST_BYTES)?)?;
            let bytes = read_bounded(&artifact, MAX_WINDOWS_AGENT_BYTES)?;
            if let Some(expected) = release_version {
                signed.verify_release(&trusted_key, &expected, &bytes)?;
                let name = check_release_filename(&signed.release, &artifact)?;
                println!(
                    "Verified staged Windows x64 release {name} ({} bytes)\n{}",
                    signed.release.size_bytes, signed.release.sha256
                );
            } else {
                let current_version = current_version.context("expected an installed version")?;
                signed.verify(&trusted_key, &current_version, &bytes)?;
                println!(
                    "Verified manifest and artifact for Windows x64 agent {}",
                    signed.release.version
                );
            }
        }
    }
    Ok(())
}

fn check_release_filename(release: &Release, path: &Path) -> Result<String> {
    let name = release.artifact_name()?;
    ensure!(
        path.file_name().and_then(|name| name.to_str()) == Some(name.as_str()),
        "expected the release artifact {name}"
    );
    Ok(name)
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "{} exceeds the size limit",
        path.display()
    );
    Ok(bytes)
}

fn write_manifest(path: &Path, signed: &SignedRelease) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(signed)?;
    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("staging {}", path.display()))?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .with_context(|| format!("creating {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::Barrier;

    #[test]
    fn concurrent_signatures_publish_one_complete_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_NAME);
        let key = SigningKey::from_bytes(&[31; 32]);
        let signed = |version: &str| {
            let release = Release::from_artifact(version.into(), b"synthetic fixture").unwrap();
            let signature = Bytes(key.sign(&release.signing_bytes()).to_bytes().to_vec());
            SignedRelease { release, signature }
        };
        let first = signed("0.3.1");
        let second = signed("0.3.2");
        let ready = Barrier::new(2);
        let publish = |manifest: &SignedRelease| {
            ready.wait();
            write_manifest(&path, manifest)
        };
        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(|| publish(&first));
            let right = scope.spawn(|| publish(&second));
            (left.join().unwrap(), right.join().unwrap())
        });
        let winner = match (left, right) {
            (Ok(()), Err(_)) => first,
            (Err(_), Ok(())) => second,
            other => panic!("one writer must publish a manifest, got {other:?}"),
        };
        assert_eq!(
            SignedRelease::parse(&std::fs::read(path).unwrap()).unwrap(),
            winner
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
