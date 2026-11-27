use anyhow::{anyhow, ensure, Context, Result};
use flyw8t_protocol::agent_update::{
    Release, SignedRelease, MAX_MANIFEST_BYTES, MAX_WINDOWS_AGENT_BYTES,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek};
use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::{
    szOID_COMMON_NAME, CertGetNameStringW, CERT_NAME_ATTR_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, SGNR_TYPE_TIMESTAMP, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
    WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_SHARE_READ};

const RELEASE_PUBLISHER: &str = "Joseph Spillers";

/// Check a candidate against the running build's version. The operator supplies the trusted key separately.
pub fn check(manifest: &Path, candidate: &Path, key: &[u8; 32]) -> Result<Release> {
    check_with_version(manifest, candidate, key, env!("CARGO_PKG_VERSION"))
}

fn check_with_version(
    manifest: &Path,
    candidate: &Path,
    key: &[u8; 32],
    installed_version: &str,
) -> Result<Release> {
    let manifest_file = File::open(manifest).context("opening the Windows update manifest")?;
    let signed = SignedRelease::parse(&read_bounded(&manifest_file, MAX_MANIFEST_BYTES)?)?;
    // Retain the same handle from digest computation through Windows trust verification. Share mode
    // refuses a candidate opened for writing or deletion and prevents either while we hold the handle.
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(candidate)
        .context("opening the Windows update candidate for verification")?;
    let bytes = read_bounded(&file, MAX_WINDOWS_AGENT_BYTES)?;
    signed.verify(key, installed_version, &bytes)?;
    file.rewind()?;
    verify_publisher(&file)?;
    Ok(signed.release)
}

fn read_bounded(file: &File, limit: usize) -> Result<Vec<u8>> {
    ensure!(file.metadata()?.is_file(), "expected a regular file");
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "update file exceeds its size limit");
    Ok(bytes)
}

fn verify_publisher(file: &File) -> Result<()> {
    let handle = file.as_raw_handle();
    let mut path = vec![0u16; 32_768];
    // SAFETY: a live file handle and a writable UTF-16 buffer of the declared length.
    let size =
        unsafe { GetFinalPathNameByHandleW(handle, path.as_mut_ptr(), path.len() as u32, 0) };
    if size == 0 {
        return Err(std::io::Error::last_os_error()).context("resolving the signed file path");
    }
    ensure!((size as usize) < path.len(), "signed file path is too long");

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: handle,
        ..Default::default()
    };
    let mut request = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: all fields of the request and its file union refer to live values. INVALID_HANDLE_VALUE
    // and WTD_UI_NONE suppress interaction. The request's state is closed below on both paths.
    let status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut request as *mut WINTRUST_DATA).cast(),
        )
    };
    let result = if status == 0 {
        check_signer(request.hWVTStateData)
    } else {
        Err(anyhow!(
            "Windows Authenticode verification failed (0x{:08x})",
            status as u32
        ))
    };
    request.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: the same structures and backing path and file remain live through cleanup.
    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut request as *mut WINTRUST_DATA).cast(),
        );
    }
    result
}

fn check_signer(state: HANDLE) -> Result<()> {
    ensure!(
        !state.is_null(),
        "Windows returned no Authenticode verification state"
    );
    // SAFETY: all returned pointers refer to WinTrust's state until WTD_STATEACTION_CLOSE.
    // Null pointers, failed signers and missing chains are refused before reading them.
    unsafe {
        let provider = WTHelperProvDataFromStateData(state);
        ensure!(
            !provider.is_null(),
            "Windows returned no Authenticode provider"
        );
        let signer_ptr = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
        let signer = signer_ptr
            .as_ref()
            .context("missing Authenticode publisher")?;
        ensure!(
            signer.dwError == 0 && signer.csCertChain > 0,
            "invalid Authenticode publisher"
        );
        let cert = WTHelperGetProvCertFromChain(signer_ptr, 0)
            .as_ref()
            .context("missing Authenticode publisher certificate")?;
        ensure!(
            !cert.pCert.is_null(),
            "missing Authenticode publisher certificate"
        );
        let mut name = [0u16; 256];
        let len = CertGetNameStringW(
            cert.pCert,
            CERT_NAME_ATTR_TYPE,
            0,
            szOID_COMMON_NAME.cast(),
            name.as_mut_ptr(),
            name.len() as u32,
        );
        let expected: Vec<u16> = RELEASE_PUBLISHER.encode_utf16().chain([0]).collect();
        ensure!(
            name.get(..len as usize) == Some(expected.as_slice()),
            "the Authenticode publisher is not {RELEASE_PUBLISHER}"
        );
        let timestamped = (0..signer.csCounterSigners).any(|index| {
            WTHelperGetProvSignerFromChain(provider, 0, 1, index)
                .as_ref()
                .is_some_and(|timestamp| {
                    timestamp.dwError == 0
                        && timestamp.dwSignerType & SGNR_TYPE_TIMESTAMP != 0
                        && timestamp.csCertChain > 0
                })
        });
        ensure!(
            timestamped,
            "the Authenticode signature has no trusted timestamp"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use flyw8t_protocol::trust::Bytes;

    #[test]
    #[ignore = "requires a timestamped release artifact from the Windows signing rehearsal"]
    fn authenticode_is_required_for_a_manifest_valid_candidate() {
        let candidate = std::env::var_os("FLYW8T_TEST_SIGNED_AGENT")
            .map(std::path::PathBuf::from)
            .expect("signed Windows agent fixture path");
        let signed_bytes = std::fs::read(&candidate).unwrap();
        let key = SigningKey::from_bytes(&[24; 32]);
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("update.json");
        let write_manifest = |bytes: &[u8]| {
            let release = Release::from_artifact(env!("CARGO_PKG_VERSION").into(), bytes).unwrap();
            let signature = Bytes(key.sign(&release.signing_bytes()).to_bytes().to_vec());
            let signed = SignedRelease { release, signature };
            std::fs::write(&manifest, serde_json::to_vec(&signed).unwrap()).unwrap();
            signed.release
        };
        let public_key = key.verifying_key().to_bytes();
        let release = write_manifest(&signed_bytes);
        let staged = dir.path().join("staged agent.exe");
        std::fs::write(&staged, &signed_bytes).unwrap();
        assert_eq!(
            check_with_version(&manifest, &staged, &public_key, "0.0.0")
                .expect("released agent must pass Windows update verification"),
            release,
        );
        assert!(check(&manifest, &staged, &public_key)
            .unwrap_err()
            .to_string()
            .contains("must be newer"));

        // The COFF timestamp is covered by Authenticode. A fresh fixture manifest still
        // describes the modified bytes exactly, so only the publisher check can refuse them.
        let mut modified = signed_bytes;
        let pe_offset = u32::from_le_bytes(modified[0x3c..0x40].try_into().unwrap()) as usize;
        modified[pe_offset + 8] ^= 1;
        std::fs::write(&staged, &modified).unwrap();
        write_manifest(&modified);
        assert!(check_with_version(&manifest, &staged, &public_key, "0.0.0")
            .unwrap_err()
            .to_string()
            .contains("Windows Authenticode verification failed"));
    }
}
