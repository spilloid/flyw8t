//! Verify the bytes and publisher of a Windows x64 update candidate.

use anyhow::{ensure, Result};
use flyw8t_protocol::{agent_update::SignedRelease, enrollment_package::is_template};

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;
#[cfg(all(windows, target_arch = "x86_64"))]
pub use windows::check;
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod key_pin;

#[cfg(test)]
#[path = "../../flyw8t-protocol/tests/support/agent_update.rs"]
mod release_fixture;

fn verify_release(
    signed: &SignedRelease,
    bytes: &[u8],
    key: &[u8; 32],
    installed_version: &str,
) -> Result<()> {
    signed.verify(key, installed_version, bytes)?;
    let is_x64 = bytes.get(0x3c..0x40).is_some_and(|offset| {
        let offset = u32::from_le_bytes(offset.try_into().expect("four-byte PE header offset"));
        bytes
            .get(offset as usize..)
            .is_some_and(|header| header.starts_with(b"PE\0\0\x64\x86"))
    });
    ensure!(
        is_x64 && is_template(bytes),
        "expected a plain Windows x64 agent executable without enrollment data"
    );
    Ok(())
}

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
    fn a_signed_candidate_must_be_an_x64_release_without_enrollment_data() {
        let key = SigningKey::from_bytes(&[18; 32]);
        let public = key.verifying_key().to_bytes();
        let image = release_fixture::versioned_image("0.3.0");
        verify_release(&sign(&key, &image), &image, &public, "0.2.0").unwrap();

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
            assert!(
                verify_release(&sign(&key, &malformed), &malformed, &public, "0.2.0")
                    .unwrap_err()
                    .to_string()
                    .contains(expected)
            );
        }
    }
}
