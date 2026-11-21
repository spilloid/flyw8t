//! Evidence accepted on the fixture's private pipe. The console commits to its certificate
//! before receiving the native offer. Verify that commitment against the live DTLS transport.
use super::Result;
use ring::digest::{digest, SHA256};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Commitment {
    session: String,
    commit: String,
}

pub enum ExpectedPeer {
    Fingerprint([u8; 32]),
    Session { id: Uuid, commitment: [u8; 32] },
}

fn fingerprint(value: &str) -> Option<[u8; 32]> {
    if value.len() != 95 {
        return None;
    }
    let mut bytes = [0; 32];
    let mut fields = value.split(':');
    for byte in &mut bytes {
        let field = fields.next()?;
        if field.len() != 2 {
            return None;
        }
        hex::decode_to_slice(field, std::slice::from_mut(byte)).ok()?;
    }
    fields.next().is_none().then_some(bytes)
}

fn hash(value: String) -> [u8; 32] {
    digest(&SHA256, value.as_bytes())
        .as_ref()
        .try_into()
        .expect("SHA-256 length")
}

impl ExpectedPeer {
    pub fn session_code(id: &Uuid, technician: &str, participant: &str) -> Option<String> {
        let technician = hex::encode(fingerprint(technician)?);
        let participant = hex::encode(fingerprint(participant)?);
        let bytes = hash(format!("flyw8t-sas-v1|{id}|{technician}|{participant}"));
        let n = u32::from_be_bytes(bytes[..4].try_into().ok()?) % 1_000_000;
        Some(format!("{n:06}"))
    }

    pub fn parse(line: &str) -> Result<Self> {
        if line.starts_with('{') {
            let claim: Commitment = serde_json::from_str(line)?;
            let id: Uuid = claim.session.parse()?;
            if id.to_string() != claim.session {
                return Err("invalid fixture session".into());
            }
            let mut commitment = [0; 32];
            hex::decode_to_slice(claim.commit, &mut commitment)?;
            return Ok(Self::Session { id, commitment });
        }
        fingerprint(line)
            .map(Self::Fingerprint)
            .ok_or_else(|| "invalid fixture peer fingerprint".into())
    }

    pub fn matches(&self, actual: &str) -> bool {
        let Some(bytes) = fingerprint(actual) else {
            return false;
        };
        match self {
            Self::Fingerprint(expected) => bytes == *expected,
            Self::Session { id, commitment } => {
                let fp = hex::encode(bytes);
                hash(format!("flyw8t-sas-commit-v1|{id}|{fp}")) == *commitment
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SESSION: &str = "12345678-1234-4567-89ab-1234567890ab";
    const FP: &str = "00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F";

    #[test]
    fn verifies_console_vector_and_rejects_substitutions() {
        // Produced independently with the same Web Crypto inputs as support.js.
        let commit = "22ece0fb127b7171f120ea98e5885ed35807870f019356318152601f35e3c05c";
        let make =
            |session: &str| serde_json::json!({"session":session,"commit":commit}).to_string();
        let pin = ExpectedPeer::parse(&make(SESSION)).unwrap();
        assert!(pin.matches(FP));
        assert!(pin.matches(&FP.to_ascii_lowercase()));
        assert!(!pin.matches(&FP.replacen("00", "A0", 1)));
        assert!(
            !ExpectedPeer::parse(&make("12345678-1234-4567-89ab-1234567890ac"))
                .unwrap()
                .matches(FP)
        );
        assert!(ExpectedPeer::parse(&make("not-an-id")).is_err());
        assert!(ExpectedPeer::parse(&make(SESSION).replace(commit, FP)).is_err());
        assert!(!pin.matches(&FP.replace(':', "")));
        assert!(ExpectedPeer::parse(FP).unwrap().matches(FP));
    }
}
