//! Validate and unpack the downloaded Win32 app in enrollment acceptance tests.

pub struct InstallationFiles {
    pub installer: Vec<u8>,
    pub detector: Vec<u8>,
    pub uninstall: Vec<u8>,
}

pub fn unpack(bundle: &[u8], expected_detector: &str) -> InstallationFiles {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ring::{digest, hmac};
    use std::io::{Cursor, Read};
    use zip::ZipArchive;

    fn file(zip: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        zip.by_name(name).unwrap().read_to_end(&mut bytes).unwrap();
        bytes
    }

    let mut bundle = ZipArchive::new(Cursor::new(bundle)).unwrap();
    assert_eq!(bundle.len(), 3);
    let detector = file(&mut bundle, "Detect-Flyw8t.ps1");
    assert_eq!(detector, expected_detector.as_bytes());
    let instructions = String::from_utf8(file(&mut bundle, "README.txt")).unwrap();
    assert!(instructions.contains("Flyw8t-Setup-x64.exe --quiet"));
    assert!(instructions.contains("cmd.exe /d /c Uninstall-Flyw8t.cmd"));

    let app = file(&mut bundle, "Flyw8t-Setup-x64.intunewin");
    let mut app = ZipArchive::new(Cursor::new(app.as_slice())).unwrap();
    assert_eq!(app.len(), 2);
    let metadata =
        String::from_utf8(file(&mut app, "IntuneWinPackage/Metadata/Detection.xml")).unwrap();
    let field = |name: &str| {
        metadata
            .split_once(&format!("<{name}>"))
            .unwrap()
            .1
            .split_once(&format!("</{name}>"))
            .unwrap()
            .0
    };
    assert_eq!(field("SetupFile"), "Flyw8t-Setup-x64.exe");
    assert_eq!(field("FileName"), "IntunePackage.intunewin");
    assert_eq!(field("ProfileIdentifier"), "ProfileVersion1");
    assert_eq!(field("FileDigestAlgorithm"), "SHA256");
    let mut encrypted = file(
        &mut app,
        "IntuneWinPackage/Contents/IntunePackage.intunewin",
    );
    assert_eq!(encrypted[..32], STANDARD.decode(field("Mac")).unwrap());
    assert_eq!(
        encrypted[32..48],
        STANDARD.decode(field("InitializationVector")).unwrap()
    );
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        &STANDARD.decode(field("MacKey")).unwrap(),
    );
    hmac::verify(&key, &encrypted[32..], &encrypted[..32]).unwrap();
    encrypted[48] ^= 1;
    assert!(hmac::verify(&key, &encrypted[32..], &encrypted[..32]).is_err());
    encrypted[48] ^= 1;
    let decrypted = cbc::Decryptor::<aes::Aes256>::new_from_slices(
        &STANDARD.decode(field("EncryptionKey")).unwrap(),
        &encrypted[32..48],
    )
    .unwrap()
    .decrypt_padded_mut::<Pkcs7>(&mut encrypted[48..])
    .unwrap();
    assert_eq!(
        decrypted.len(),
        field("UnencryptedContentSize").parse::<usize>().unwrap()
    );
    assert_eq!(
        digest::digest(&digest::SHA256, decrypted).as_ref(),
        STANDARD.decode(field("FileDigest")).unwrap()
    );
    let mut payload = ZipArchive::new(Cursor::new(decrypted)).unwrap();
    assert_eq!(payload.len(), 2);
    InstallationFiles {
        installer: file(&mut payload, "Flyw8t-Setup-x64.exe"),
        detector,
        uninstall: file(&mut payload, "Uninstall-Flyw8t.cmd"),
    }
}
