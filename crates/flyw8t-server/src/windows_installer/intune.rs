//! Intune Win32 application packaging for the fixed Flyw8t x64 installer.

use crate::error::AppError;
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{digest, hmac, rand, rand::SecureRandom};
use std::io::{Cursor, Write};
use tokio::sync::Semaphore;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

const SETUP: &str = "Flyw8t-Setup-x64.exe";
const PAYLOAD: &str = "IntunePackage.intunewin";
const BUNDLE_PACKAGE: &str = "Flyw8t-Setup-x64.intunewin";
const MAC_LEN: usize = 32;
const BLOCK_LEN: usize = 16;
static BUILDS: Semaphore = Semaphore::const_new(1);

pub(crate) async fn deployment_bundle(
    installer: Vec<u8>,
    detection_script: String,
) -> Result<Vec<u8>, AppError> {
    let permit = BUILDS.try_acquire().map_err(|_| AppError::RateLimited)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let package = package(&installer)?;
        drop(installer);
        archive(
            CompressionMethod::Stored,
            &[
                (BUNDLE_PACKAGE, &package),
                ("Detect-Flyw8t.ps1", detection_script.as_bytes()),
                ("README.txt", include_bytes!("intune-readme.txt")),
            ],
        )
    })
    .await
    .map_err(|error| AppError::Internal(error.into()))?
    .map_err(AppError::Internal)
}

fn package(installer: &[u8]) -> Result<Vec<u8>> {
    let uninstall = include_str!("intune-uninstall.cmd").replace('\n', "\r\n");
    let mut compressed = archive(
        CompressionMethod::Deflated,
        &[
            (SETUP, installer),
            ("Uninstall-Flyw8t.cmd", uninstall.as_bytes()),
        ],
    )?;
    let size = compressed.len();
    let file_digest = digest::digest(&digest::SHA256, &compressed);
    let rng = rand::SystemRandom::new();
    let mut encryption_key = [0u8; 32];
    let mut mac_key = [0u8; MAC_LEN];
    let mut iv = [0u8; BLOCK_LEN];
    for bytes in [&mut encryption_key[..], &mut mac_key, &mut iv] {
        rng.fill(bytes)
            .map_err(|_| anyhow!("generating Win32 package encryption material"))?;
    }

    // ProfileVersion1 uses AES-256-CBC/PKCS#7 with a SHA-256 HMAC over IV and ciphertext.
    compressed.resize(size + BLOCK_LEN, 0);
    let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&encryption_key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut compressed, size)
        .map_err(|_| anyhow!("encrypting Win32 package content"))?;
    let mut content = Vec::with_capacity(MAC_LEN + iv.len() + ciphertext.len());
    content.resize(MAC_LEN, 0);
    content.extend_from_slice(&iv);
    content.extend_from_slice(ciphertext);
    let mac = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, &mac_key),
        &content[MAC_LEN..],
    );
    content[..MAC_LEN].copy_from_slice(mac.as_ref());

    // ToolVersion describes the Content Prep metadata format this file targets.
    // Only fixed filenames, numbers and Base64 values appear in this XML.
    let metadata = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="1.8.7.0">
  <Name>Flyw8t Agent</Name>
  <UnencryptedContentSize>{size}</UnencryptedContentSize>
  <FileName>{PAYLOAD}</FileName>
  <SetupFile>{SETUP}</SetupFile>
  <EncryptionInfo>
    <EncryptionKey>{}</EncryptionKey>
    <MacKey>{}</MacKey>
    <InitializationVector>{}</InitializationVector>
    <Mac>{}</Mac>
    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>
    <FileDigest>{}</FileDigest>
    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>
  </EncryptionInfo>
</ApplicationInfo>"#,
        STANDARD.encode(encryption_key),
        STANDARD.encode(mac_key),
        STANDARD.encode(iv),
        STANDARD.encode(mac),
        STANDARD.encode(file_digest),
    );
    archive(
        CompressionMethod::Stored,
        &[
            (
                "IntuneWinPackage/Metadata/Detection.xml",
                metadata.as_bytes(),
            ),
            (
                "IntuneWinPackage/Contents/IntunePackage.intunewin",
                &content,
            ),
        ],
    )
}

fn archive(compression: CompressionMethod, files: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(compression);
    for (filename, bytes) in files {
        zip.start_file(*filename, options)?;
        zip.write_all(bytes)?;
    }
    Ok(zip.finish()?.into_inner())
}
