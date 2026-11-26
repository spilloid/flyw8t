//! Enrollment data appended to a Windows installer. The original agent bytes are preserved.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Seek, SeekFrom};

const MAGIC: &[u8] = b"FLYW8T_WINDOWS_ENROLLMENT_PACKAGE_V1";
const MAX_DATA: usize = 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentPackage {
    pub server_url: String,
    pub organization: String,
    pub site: Option<String>,
    pub token: String,
}

/// Check that the published artifact is a plain installer-capable agent.
pub fn is_template(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
        && !bytes.ends_with(MAGIC)
        && bytes.windows(MAGIC.len()).any(|part| part == MAGIC)
}

impl EnrollmentPackage {
    pub fn append(&self, exe: &mut Vec<u8>) -> io::Result<()> {
        let data = serde_json::to_vec(self)?;
        if data.len() > MAX_DATA {
            return Err(invalid());
        }
        exe.extend_from_slice(&data);
        exe.extend_from_slice(&(data.len() as u32).to_le_bytes());
        exe.extend_from_slice(MAGIC);
        Ok(())
    }

    /// Return the original executable length and the package, leaving the file at its start.
    pub fn read(source: &mut (impl Read + Seek)) -> io::Result<Option<(u64, Self)>> {
        // Keep this marker in the executable so the server can recognize capable release assets.
        let magic = std::hint::black_box(MAGIC);
        let footer_len = (magic.len() + 4) as u64;
        let file_len = source.seek(SeekFrom::End(0))?;
        if file_len < footer_len {
            source.rewind()?;
            return Ok(None);
        }
        source.seek(SeekFrom::Start(file_len - footer_len))?;
        let mut length = [0; 4];
        let mut marker = [0; MAGIC.len()];
        source.read_exact(&mut length)?;
        source.read_exact(&mut marker)?;
        if marker != magic {
            source.rewind()?;
            return Ok(None);
        }
        let length = u32::from_le_bytes(length) as usize;
        let base_len = file_len
            .checked_sub(footer_len + length as u64)
            .filter(|base| *base > 0 && (1..=MAX_DATA).contains(&length))
            .ok_or_else(invalid)?;
        source.seek(SeekFrom::Start(base_len))?;
        let mut data = vec![0; length];
        source.read_exact(&mut data)?;
        source.rewind()?;
        let package = serde_json::from_slice(&data).map_err(|_| invalid())?;
        Ok(Some((base_len, package)))
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Windows enrollment package",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn package_round_trip_recovers_original_agent_bytes() {
        let base = [b"MZ payload ".as_slice(), MAGIC, b" original suffix"].concat();
        assert!(is_template(&base));
        let mut exe = base.clone();
        let package = EnrollmentPackage {
            server_url: "https://example.test".into(),
            organization: "Client A".into(),
            site: Some("Main Office".into()),
            token: "fixture-token".into(),
        };
        package.append(&mut exe).unwrap();
        assert!(!is_template(&exe));
        let mut source = Cursor::new(exe);
        let (base_len, decoded) = EnrollmentPackage::read(&mut source).unwrap().unwrap();
        assert_eq!(decoded.site, package.site);
        assert_eq!(decoded.token, package.token);
        let mut agent = Vec::new();
        source.take(base_len).read_to_end(&mut agent).unwrap();
        assert_eq!(agent, base);
        assert!(EnrollmentPackage::read(&mut Cursor::new(base))
            .unwrap()
            .is_none());
    }

    #[test]
    fn malformed_footer_cannot_allocate_unbounded_data() {
        let exe = [b"MZ".as_slice(), &u32::MAX.to_le_bytes(), MAGIC].concat();
        assert!(EnrollmentPackage::read(&mut Cursor::new(exe)).is_err());
    }
}
