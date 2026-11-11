//! The offline key file (ADR-0015 section 1): versioned and authenticated. Argon2id stretches the passphrase,
//! XChaCha20-Poly1305 seals the 32-byte Ed25519 seed, and everything outside the sealed part (format, public key,
//! KDF settings, salt) is bound as associated data, so none of it can be changed without the file refusing to open.

use anyhow::{bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use flyw8t_protocol::trust::encode::Enc;
use flyw8t_protocol::trust::{key_id, Bytes, Hash, KeyKind};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

pub const FORMAT: &str = "flyw8t-sign key v1";
/// Argon2id: 64 MiB, 3 passes, one lane. Opening takes a fraction of a second; guessing takes that per guess.
const M_KIB: u32 = 64 * 1024;
const T: u32 = 3;
const P: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kdf {
    alg: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: Bytes,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    format: String,
    public_key: Bytes,
    kdf: Kdf,
    nonce: Bytes,
    sealed: Bytes,
}

fn associated(f: &File) -> Vec<u8> {
    let mut e = Enc::statement(FORMAT);
    e.bytes(&f.public_key.0)
        .text(&f.kdf.alg)
        .uint(f.kdf.m_kib.into())
        .uint(f.kdf.t.into())
        .uint(f.kdf.p.into())
        .bytes(&f.kdf.salt.0);
    e.into_bytes()
}

fn stretch(pass: &str, kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>> {
    // Bounded both ways before anything is spent: the settings are checked only after the work is done.
    if kdf.alg != "argon2id"
        || !(19 * 1024..=1024 * 1024).contains(&kdf.m_kib)
        || !(2..=16).contains(&kdf.t)
        || !(1..=8).contains(&kdf.p)
    {
        bail!("the key file asks for a key derivation this tool will not use");
    }
    let params = argon2::Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32))
        .map_err(|e| anyhow::anyhow!("key derivation settings: {e}"))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass.as_bytes(), &kdf.salt.0, out.as_mut())
        .map_err(|e| anyhow::anyhow!("key derivation: {e}"))?;
    Ok(out)
}

pub struct OfflineKey {
    pub signing: ed25519_dalek::SigningKey,
}

impl OfflineKey {
    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
    pub fn id(&self) -> Hash {
        key_id(KeyKind::Offline, &self.public())
    }
}

/// Make a new key and the bytes of its file.
pub fn generate(pass: &str) -> Result<(OfflineKey, Vec<u8>)> {
    let rng = SystemRandom::new();
    let mut seed = Zeroizing::new([0u8; 32]);
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    for b in [seed.as_mut_slice(), &mut salt, &mut nonce] {
        rng.fill(b)
            .map_err(|_| anyhow::anyhow!("no system randomness"))?;
    }
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut f = File {
        format: FORMAT.into(),
        public_key: Bytes(signing.verifying_key().to_bytes().to_vec()),
        kdf: Kdf {
            alg: "argon2id".into(),
            m_kib: M_KIB,
            t: T,
            p: P,
            salt: Bytes(salt.to_vec()),
        },
        nonce: Bytes(nonce.to_vec()),
        sealed: Bytes::default(),
    };
    let k = stretch(pass, &f.kdf)?;
    let aad = associated(&f);
    f.sealed = Bytes(
        XChaCha20Poly1305::new(k.as_ref().into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: seed.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("sealing the key failed"))?,
    );
    Ok((OfflineKey { signing }, serde_json::to_vec_pretty(&f)?))
}

/// Open a key file with its passphrase.
pub fn open(path: &Path, pass: &str) -> Result<OfflineKey> {
    if std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) > 64 * 1024 {
        bail!("{} is not a key file", path.display());
    }
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let f: File = serde_json::from_slice(&raw).context("not a flyw8t-sign key file")?;
    if f.format != FORMAT {
        bail!(
            "this key file is {:?}; this tool reads {FORMAT:?}",
            f.format
        );
    }
    if f.nonce.0.len() != 24 {
        bail!("the key file is damaged");
    }
    let k = stretch(pass, &f.kdf)?;
    let seed = Zeroizing::new(
        XChaCha20Poly1305::new(k.as_ref().into())
            .decrypt(
                XNonce::from_slice(&f.nonce.0),
                Payload {
                    msg: &f.sealed.0,
                    aad: &associated(&f),
                },
            )
            .map_err(|_| anyhow::anyhow!("wrong passphrase, or the key file was changed"))?,
    );
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .context("the key file is damaged")?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    if signing.verifying_key().to_bytes().as_slice() != f.public_key.0 {
        bail!("the key file's public key does not match its private key");
    }
    Ok(OfflineKey { signing })
}

/// Write `bytes` to a new file only its owner can read. Refuses to replace an existing file.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = create_private(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(windows)]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{LocalFree, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL};
    // Protected: nothing inherited. Full control for the file's owner only.
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)".encode_utf16().chain([0]).collect();
    let wpath: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: NUL-terminated SDDL; on success `sd` is LocalAlloc'd and freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    const GENERIC_WRITE: u32 = 0x4000_0000;
    // SAFETY: NUL-terminated path, valid attributes; the handle is owned by the returned File.
    let h = unsafe {
        CreateFileW(
            wpath.as_ptr(),
            GENERIC_WRITE,
            0,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    let err = std::io::Error::last_os_error();
    // SAFETY: `sd` came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe { LocalFree(sd as _) };
    if h == INVALID_HANDLE_VALUE {
        return Err(err);
    }
    // SAFETY: a fresh, valid file handle that nothing else owns.
    Ok(unsafe { std::fs::File::from_raw_handle(h as _) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_opens_with_its_passphrase_only_and_refuses_tampering() {
        let dir = std::env::temp_dir().join(format!("flyw8t-sign-key-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("root.key");
        let (k, bytes) = generate("correct horse").unwrap();
        write_private(&path, &bytes).unwrap();
        assert!(
            write_private(&path, &bytes).is_err(),
            "never replaces a file"
        );
        assert_eq!(open(&path, "correct horse").unwrap().public(), k.public());
        assert!(open(&path, "wrong").is_err());
        // Weakening the KDF or swapping the public key breaks the seal.
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["kdf"]["t"] = 4.into();
        let p2 = dir.join("t.key");
        std::fs::write(&p2, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(open(&p2, "correct horse").is_err());
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["kdf"]["m_kib"] = 8.into();
        let p3 = dir.join("m.key");
        std::fs::write(&p3, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(open(&p3, "correct horse").is_err());
        // Extreme settings are refused before any work: this would ask for 4 TiB.
        for (field, value) in [
            ("m_kib", 4_294_967_295u64),
            ("t", 4_294_967_295),
            ("p", 1000),
        ] {
            let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            v["kdf"][field] = value.into();
            let p4 = dir.join(format!("{field}.key"));
            std::fs::write(&p4, serde_json::to_vec(&v).unwrap()).unwrap();
            let started = std::time::Instant::now();
            let err = open(&p4, "correct horse").err().unwrap().to_string();
            assert!(err.contains("will not use"), "{field}: {err}");
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
