//! Verify the bytes and publisher of a Windows x64 update candidate.

#[cfg(any(test, all(windows, target_arch = "x86_64")))]
use flyw8t_protocol::agent_update::{Error, SignedRelease};

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;
#[cfg(all(windows, target_arch = "x86_64"))]
pub use windows::{check, check_rollback};
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod key_pin;

#[cfg(any(test, all(windows, target_arch = "x86_64")))]
enum VersionCheck<'a> {
    NewerThan(&'a str),
    Exact(&'a str),
}

#[cfg(any(test, all(windows, target_arch = "x86_64")))]
impl VersionCheck<'_> {
    fn verify(self, signed: &SignedRelease, key: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
        match self {
            Self::NewerThan(current) => signed.verify(key, current, bytes),
            Self::Exact(expected) => signed.verify_release(key, expected, bytes),
        }
    }
}

#[cfg(test)]
#[path = "../../flyw8t-protocol/tests/support/agent_update.rs"]
mod release_fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use flyw8t_protocol::{agent_update::Release, trust::Bytes};

    fn sign(key: &SigningKey, image: &[u8]) -> SignedRelease {
        let release = Release::from_artifact("0.3.0".into(), image).unwrap();
        let signature = Bytes(key.sign(&release.signing_bytes()).to_bytes().to_vec());
        SignedRelease { release, signature }
    }

    #[test]
    fn rollback_requires_the_exact_running_version_and_trusted_bytes() {
        let key = SigningKey::from_bytes(&[18; 32]);
        let public = key.verifying_key().to_bytes();
        let image = release_fixture::versioned_image("0.3.0");
        let signed = sign(&key, &image);
        assert_eq!(
            VersionCheck::Exact("0.3.0").verify(&signed, &public, &image),
            Ok(())
        );
        assert!(matches!(
            VersionCheck::NewerThan("0.3.0").verify(&signed, &public, &image),
            Err(Error::NotNewer)
        ));
        for version in ["0.2.0", "0.3.1"] {
            assert!(matches!(
                VersionCheck::Exact(version).verify(&signed, &public, &image),
                Err(Error::UnexpectedReleaseVersion { .. })
            ));
        }
        assert!(matches!(
            VersionCheck::Exact("0.3.0").verify(&signed, &[0; 32], &image),
            Err(Error::Signature)
        ));
        assert!(matches!(
            VersionCheck::Exact("0.3.0").verify(&signed, &public, b"changed"),
            Err(Error::Artifact)
        ));
    }

    #[test]
    fn a_signed_candidate_must_be_an_x64_release_without_enrollment_data() {
        let key = SigningKey::from_bytes(&[18; 32]);
        let public = key.verifying_key().to_bytes();
        let image = release_fixture::versioned_image("0.3.0");
        sign(&key, &image).verify(&public, "0.2.0", &image).unwrap();

        let mut wrong_machine = image.clone();
        wrong_machine[68..70].copy_from_slice(b"\x4c\x01");
        let mut invalid_offset = image.clone();
        invalid_offset[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut enrollment = image;
        flyw8t_protocol::enrollment_package::EnrollmentPackage {
            server_url: "https://example.test".into(),
            organization: "Fixture".into(),
            site: None,
            token: "fixture-token".into(),
        }
        .append(&mut enrollment)
        .unwrap();
        for (malformed, expected) in [
            (wrong_machine, "no valid embedded build version"),
            (invalid_offset, "no valid embedded build version"),
            (b"MZ".to_vec(), "no valid embedded build version"),
            (enrollment, "expected a plain Windows x64"),
            (
                release_fixture::versioned_image("0.2.0"),
                "Windows agent build version 0.2.0 does not match release version 0.3.0",
            ),
        ] {
            assert!(sign(&key, &malformed)
                .verify(&public, "0.2.0", &malformed)
                .unwrap_err()
                .to_string()
                .contains(expected));
        }
    }
}
