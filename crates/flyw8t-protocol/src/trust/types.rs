//! Values shared by the trust statements, and how each one is written in JSON.
//!
//! JSON is only the transport: what is signed is always the encoding of `encode`, recomputed from the parsed values.
//! Parsing is strict: unknown fields, duplicate fields, padded or non-canonical base64, and upper-case or
//! unprefixed hashes are refused, never repaired.

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A SHA-256 hash: a key id, a list version, a content hash, a commitment. Written `sha256:` and 64 lower-case hex
/// digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn parse(s: &str) -> Option<Hash> {
        let h = s.strip_prefix("sha256:")?;
        if h.len() != 64
            || !h
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(h, &mut out).ok()?;
        Some(Hash(out))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Hash::parse(&s).ok_or_else(|| {
            serde::de::Error::custom("expected sha256: and 64 lower-case hex digits")
        })
    }
}

/// Bytes, written as unpadded base64url. Only the canonical encoding is accepted.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Bytes(pub Vec<u8>);

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({})", B64.encode(&self.0))
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        // The default engine refuses padding (this one has none) and non-zero trailing bits, so each byte string
        // has exactly one accepted spelling.
        B64.decode(&s)
            .map(Bytes)
            .map_err(|_| serde::de::Error::custom("expected unpadded base64url"))
    }
}

/// A script's risk class (ADR-0014). The agent cannot check it; it is the approver's promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskClass {
    C0,
    C1,
    C2,
    C3,
}

impl RiskClass {
    pub fn code(self) -> u8 {
        match self {
            RiskClass::C0 => 1,
            RiskClass::C1 => 2,
            RiskClass::C2 => 3,
            RiskClass::C3 => 4,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            RiskClass::C0 => "C0",
            RiskClass::C1 => "C1",
            RiskClass::C2 => "C2",
            RiskClass::C3 => "C3",
        }
    }
    pub fn parse(s: &str) -> Option<RiskClass> {
        Some(match s {
            "C0" => RiskClass::C0,
            "C1" => RiskClass::C1,
            "C2" => RiskClass::C2,
            "C3" => RiskClass::C3,
            _ => return None,
        })
    }
    /// Whether a run needs its own signature.
    pub fn needs_run_signature(self) -> bool {
        self >= RiskClass::C2
    }
}

/// The highest class a signer may approve and sign runs for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MayApprove {
    None,
    #[serde(rename = "C0")]
    C0,
    #[serde(rename = "C1")]
    C1,
    #[serde(rename = "C2")]
    C2,
    #[serde(rename = "C3")]
    C3,
}

impl MayApprove {
    pub fn code(self) -> u8 {
        match self {
            MayApprove::None => 0,
            MayApprove::C0 => 1,
            MayApprove::C1 => 2,
            MayApprove::C2 => 3,
            MayApprove::C3 => 4,
        }
    }
    pub fn allows(self, class: RiskClass) -> bool {
        self.code() >= class.code()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKind {
    Passkey,
    Offline,
}

/// The kind number in a key id. A device key is not a signer, but its id is made the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Passkey,
    Offline,
    Device,
}

impl KeyKind {
    pub fn code(self) -> u8 {
        match self {
            KeyKind::Passkey => 1,
            KeyKind::Offline => 2,
            KeyKind::Device => 3,
        }
    }
}

impl From<SignerKind> for KeyKind {
    fn from(k: SignerKind) -> Self {
        match k {
            SignerKind::Passkey => KeyKind::Passkey,
            SignerKind::Offline => KeyKind::Offline,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Signer,
    ListAdmin,
    /// Also a list admin. Only offline keys may be roots.
    Root,
}

impl Role {
    pub fn code(self) -> u8 {
        match self {
            Role::Signer => 1,
            Role::ListAdmin => 2,
            Role::Root => 3,
        }
    }
    pub fn is_list_admin(self) -> bool {
        self >= Role::ListAdmin
    }
}

/// Which organizations a signer's approvals and run signatures apply to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    All,
    Organizations(Vec<uuid::Uuid>),
}

impl Scope {
    pub fn code(&self) -> u8 {
        match self {
            Scope::All => 1,
            Scope::Organizations(_) => 2,
        }
    }
    pub fn includes(&self, org: &uuid::Uuid) -> bool {
        match self {
            Scope::All => true,
            Scope::Organizations(o) => o.contains(org),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_have_one_spelling() {
        let h = Hash([0xab; 32]);
        let s = h.to_string();
        assert_eq!(Hash::parse(&s), Some(h));
        assert_eq!(
            Hash::parse(&s.to_uppercase().replace("SHA256", "sha256")),
            None
        );
        assert_eq!(Hash::parse(&s["sha256:".len()..]), None);
        assert_eq!(Hash::parse(&s[..s.len() - 1]), None);
    }

    #[test]
    fn bytes_have_one_spelling() {
        let ok: Bytes = serde_json::from_str("\"AQI\"").unwrap();
        assert_eq!(ok.0, vec![1, 2]);
        for bad in ["\"AQI=\"", "\"AQJ\"", "\"AQ+\"", "\"A\""] {
            assert!(serde_json::from_str::<Bytes>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn classes_order_and_limit() {
        assert!(MayApprove::C2.allows(RiskClass::C1));
        assert!(MayApprove::C2.allows(RiskClass::C2));
        assert!(!MayApprove::C2.allows(RiskClass::C3));
        assert!(!MayApprove::None.allows(RiskClass::C0));
        assert!(!RiskClass::C1.needs_run_signature());
        assert!(RiskClass::C2.needs_run_signature());
        assert_eq!(serde_json::to_string(&MayApprove::C3).unwrap(), "\"C3\"");
        assert_eq!(
            serde_json::to_string(&MayApprove::None).unwrap(),
            "\"none\""
        );
    }
}
