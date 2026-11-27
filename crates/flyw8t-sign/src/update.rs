use crate::{confirm, keyfile, passphrase};
use anyhow::{ensure, Context, Result};
use clap::Subcommand;
use ed25519_dalek::Signer;
use flyw8t_protocol::agent_update::{
    Release, SignedRelease, MANIFEST_NAME, MAX_MANIFEST_BYTES, MAX_WINDOWS_AGENT_BYTES,
};
use flyw8t_protocol::enrollment_package::is_template;
use flyw8t_protocol::trust::Bytes;
use std::fs::{File, OpenOptions};
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
            let name = check_release_artifact(&release, &artifact, &bytes)?;
            release.check_build_version(&bytes)?;
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
                let name = check_release_artifact(&signed.release, &artifact, &bytes)?;
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

fn check_release_artifact(release: &Release, path: &Path, bytes: &[u8]) -> Result<String> {
    let name = release.artifact_name()?;
    ensure!(
        path.file_name().and_then(|name| name.to_str()) == Some(name.as_str()),
        "expected the release artifact {name}"
    );
    ensure!(
        is_template(bytes),
        "expected a plain Windows agent release executable without an enrollment token"
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
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
