//! Signed release metadata for the Windows x64 Flyw8t agent (ADR-0008).

use crate::trust::{encode::Enc, sig::verify_ed25519, Bytes, Hash};
use ring::digest;
use semver::Version;
use serde::{Deserialize, Serialize};

pub const MAX_WINDOWS_AGENT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024;
pub const MANIFEST_NAME: &str = "flyw8t-agent-windows-x64-update.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub version: String,
    pub size_bytes: u64,
    pub sha256: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelease {
    pub release: Release,
    pub signature: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("expected a release version such as 0.3.0")]
    Version,
    #[error("agent executable size is outside the supported range")]
    Size,
    #[error("release manifest signature does not match the trusted update key")]
    Signature,
    #[error("release version must be newer than the installed version")]
    NotNewer,
    #[error("signed release version {actual} does not match expected release version {expected}")]
    UnexpectedReleaseVersion { actual: Version, expected: Version },
    #[error("agent executable size or SHA-256 does not match the manifest")]
    Artifact,
    #[error("Windows x64 agent has no valid embedded build version")]
    MissingBuildVersion,
    #[error("Windows agent build version {actual} does not match release version {expected}")]
    BuildVersion { actual: String, expected: String },
    #[error("invalid release manifest")]
    Manifest,
}

fn release_version(input: &str) -> Result<Version, Error> {
    let version = Version::parse(input).map_err(|_| Error::Version)?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        return Err(Error::Version);
    }
    Ok(version)
}

impl Release {
    pub fn from_artifact(version: String, bytes: &[u8]) -> Result<Self, Error> {
        release_version(&version)?;
        if !(1..=MAX_WINDOWS_AGENT_BYTES).contains(&bytes.len()) {
            return Err(Error::Size);
        }
        Ok(Self {
            version,
            size_bytes: bytes.len() as u64,
            sha256: artifact_digest(bytes),
        })
    }

    /// Check the release fields before consuming them as metadata.
    pub fn validate_metadata(&self) -> Result<Version, Error> {
        let version = release_version(&self.version)?;
        if !(1..=MAX_WINDOWS_AGENT_BYTES as u64).contains(&self.size_bytes) {
            return Err(Error::Size);
        }
        Ok(version)
    }

    pub fn artifact_name(&self) -> Result<String, Error> {
        let version = release_version(&self.version)?;
        Ok(format!(
            "flyw8t-agent-v{version}-x86_64-pc-windows-msvc.exe"
        ))
    }

    /// Read the version built into the Windows agent without running the executable.
    pub fn check_build_version(&self, bytes: &[u8]) -> Result<(), Error> {
        let actual = windows_build_version(bytes).ok_or(Error::MissingBuildVersion)?;
        if actual != self.version {
            return Err(Error::BuildVersion {
                actual: actual.into(),
                expected: self.version.clone(),
            });
        }
        Ok(())
    }

    /// The signing target is fixed by the domain. There is no caller-supplied URL or filename.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut enc = Enc::statement("flyw8t Windows x64 agent release v1");
        enc.text(&self.version)
            .uint(self.size_bytes)
            .hash(&self.sha256.0);
        enc.into_bytes()
    }
}

impl SignedRelease {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Manifest);
        }
        serde_json::from_slice(bytes).map_err(|_| Error::Manifest)
    }

    /// Check a candidate against a trusted key and the locally installed version before accepting its bytes.
    pub fn verify(
        &self,
        trusted_key: &[u8],
        installed_version: &str,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let version = self.verify_metadata(trusted_key)?;
        if version <= release_version(installed_version)? {
            return Err(Error::NotNewer);
        }
        self.verify_artifact(bytes)
    }

    /// Check that the staged bytes belong to the exact release selected for publication.
    pub fn verify_release(
        &self,
        trusted_key: &[u8],
        expected_version: &str,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let actual = self.verify_metadata(trusted_key)?;
        let expected = release_version(expected_version)?;
        if actual != expected {
            return Err(Error::UnexpectedReleaseVersion { actual, expected });
        }
        self.verify_artifact(bytes)
    }

    fn verify_metadata(&self, trusted_key: &[u8]) -> Result<Version, Error> {
        let version = self.release.validate_metadata()?;
        if !verify_ed25519(
            trusted_key,
            &self.release.signing_bytes(),
            &self.signature.0,
        ) {
            return Err(Error::Signature);
        }
        Ok(version)
    }

    fn verify_artifact(&self, bytes: &[u8]) -> Result<(), Error> {
        if self.release.size_bytes != bytes.len() as u64
            || self.release.sha256 != artifact_digest(bytes)
        {
            return Err(Error::Artifact);
        }
        self.release.check_build_version(bytes)
    }
}

fn windows_build_version(image: &[u8]) -> Option<&str> {
    const COFF_HEADER_END: usize = 24;
    const SECTION_HEADER_BYTES: usize = 40;
    const READ_ONLY_DATA: u32 = 0x4000_0040;
    const ACCESS_AND_INITIALIZED_DATA: u32 = 0xe000_0040;
    let u16_at = |bytes: &[u8], at| {
        Some(usize::from(u16::from_le_bytes(
            bytes.get(at..at + 2)?.try_into().ok()?,
        )))
    };
    let u32_at =
        |bytes: &[u8], at| Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?));
    if !image.starts_with(b"MZ") {
        return None;
    }
    let pe_start = usize::try_from(u32_at(image, 0x3c)?).ok()?;
    let pe = image.get(pe_start..)?;
    if pe_start < 64 || !pe.starts_with(b"PE\0\0\x64\x86") {
        return None;
    }
    let section_count = u16_at(pe, 6)?;
    let optional_end = COFF_HEADER_END + u16_at(pe, 20)?;
    let optional = pe.get(COFF_HEADER_END..optional_end)?;
    if !optional.starts_with(b"\x0b\x02") {
        return None;
    }
    let table_end = optional_end + section_count * SECTION_HEADER_BYTES;
    let mut receipts = pe
        .get(optional_end..table_end)?
        .as_chunks::<SECTION_HEADER_BYTES>()
        .0
        .iter()
        .filter(|section| section.starts_with(b".fw8tver"));
    let receipt = receipts.next()?;
    if receipts.next().is_some()
        || u32_at(receipt, 36)? & ACCESS_AND_INITIALIZED_DATA != READ_ONLY_DATA
    {
        return None;
    }
    let version_len = usize::try_from(u32_at(receipt, 8)?).ok()?;
    let raw_size = usize::try_from(u32_at(receipt, 16)?).ok()?;
    let raw_start = usize::try_from(u32_at(receipt, 20)?).ok()?;
    let raw_end = raw_start.checked_add(raw_size)?;
    let headers_size = usize::try_from(u32_at(optional, 60)?).ok()?;
    if headers_size < pe_start.checked_add(table_end)? || raw_start < headers_size {
        return None;
    }
    // The PE32+ certificate directory points to a file offset outside image sections.
    // Never accept a receipt from that Authenticode-excluded part of a signed file.
    if u32_at(optional, 108)? > 4 {
        let certificate_start = usize::try_from(u32_at(optional, 144)?).ok()?;
        let certificate_size = usize::try_from(u32_at(optional, 148)?).ok()?;
        if certificate_size != 0 && raw_end > certificate_start {
            return None;
        }
    }
    let version_bytes = image.get(raw_start..raw_end)?.get(..version_len)?;
    let version = std::str::from_utf8(version_bytes.strip_suffix(&[0])?).ok()?;
    release_version(version).ok()?;
    Some(version)
}

fn artifact_digest(bytes: &[u8]) -> Hash {
    Hash(
        digest::digest(&digest::SHA256, bytes)
            .as_ref()
            .try_into()
            .expect("SHA-256 is 32 bytes"),
    )
}
