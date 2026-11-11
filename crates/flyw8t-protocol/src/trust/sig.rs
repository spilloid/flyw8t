//! Signatures over statement hashes, by an offline key or a passkey (ADR-0015 section 4).

use super::list::{Signer, TrustList};
use super::types::{Bytes, Hash, SignerKind};
use crate::webauthn;
use serde::{Deserialize, Serialize};

/// What an offline key signs: this prefix, then the 32-byte statement hash.
pub const OFFLINE_PREFIX: &[u8] = b"flyw8t offline signature v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Signature {
    /// Ed25519 over [`OFFLINE_PREFIX`] and the statement hash.
    Offline { key_id: Hash, signature: Bytes },
    /// A WebAuthn assertion whose challenge is the statement hash.
    Passkey {
        key_id: Hash,
        authenticator_data: Bytes,
        client_data_json: Bytes,
        signature: Bytes,
    },
}

impl Signature {
    pub fn key_id(&self) -> &Hash {
        match self {
            Signature::Offline { key_id, .. } | Signature::Passkey { key_id, .. } => key_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    #[error("signed by {0}, which is not in the trust list")]
    UnknownSigner(Hash),
    #[error("signed by {0}, which has been removed")]
    Removed(Hash),
    #[error("a {0:?} signature from a key that is not one")]
    WrongKind(Hash),
    #[error("the signature by {0} does not verify")]
    BadSignature(Hash),
    #[error("the passkey signature by {0} does not verify: {1}")]
    Passkey(Hash, webauthn::Error),
}

/// The message an offline key signs for `statement`.
pub fn offline_message(statement: &Hash) -> Vec<u8> {
    let mut m = OFFLINE_PREFIX.to_vec();
    m.extend_from_slice(&statement.0);
    m
}

/// Verify `sig` over `statement` under the version `ctx` (the verifying version, ADR-0015 section 4): the signer
/// must be in it and not removed, and a passkey must have signed on one of its origins for its relying party.
pub fn verify<'a>(
    sig: &Signature,
    statement: &Hash,
    ctx: &'a TrustList,
) -> Result<&'a Signer, SigError> {
    let id = *sig.key_id();
    if ctx.removed_keys.contains(&id) {
        return Err(SigError::Removed(id));
    }
    let signer = ctx
        .signers
        .iter()
        .find(|s| s.key_id() == id)
        .ok_or(SigError::UnknownSigner(id))?;
    match (sig, signer.kind) {
        (Signature::Offline { signature, .. }, SignerKind::Offline) => verify_ed25519(
            &signer.public_key.0,
            &offline_message(statement),
            &signature.0,
        )
        .then_some(signer)
        .ok_or(SigError::BadSignature(id)),
        (
            Signature::Passkey {
                authenticator_data,
                client_data_json,
                signature,
                ..
            },
            SignerKind::Passkey,
        ) => webauthn::verify_assertion_any_origin(
            &signer.public_key.0,
            &statement.0,
            &ctx.origins,
            &ctx.rp_id,
            &authenticator_data.0,
            &client_data_json.0,
            &signature.0,
        )
        .map(|_| signer)
        .map_err(|e| SigError::Passkey(id, e)),
        _ => Err(SigError::WrongKind(id)),
    }
}

/// Strict Ed25519: a canonical, non-small-order key and a canonical signature, or false.
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (
        <[u8; 32]>::try_from(public_key),
        <[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    if !ed25519_key_is_canonical(&pk) {
        return false;
    }
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig))
        .is_ok()
}

/// A key that decodes to a point of large order, and whose encoding is that point's only one.
pub fn ed25519_key_is_canonical(pk: &[u8; 32]) -> bool {
    match ed25519_dalek::VerifyingKey::from_bytes(pk) {
        Ok(vk) => !vk.is_weak() && vk.to_edwards().compress().to_bytes() == *pk,
        Err(_) => false,
    }
}

/// A valid uncompressed SEC1 P-256 point, the only form a passkey key is accepted in.
pub fn p256_key_is_canonical(pk: &[u8]) -> bool {
    pk.len() == webauthn::P256_KEY_LEN
        && pk[0] == 0x04
        && p256::PublicKey::from_sec1_bytes(pk).is_ok()
}

/// Sign `statement` with an offline key (`flyw8t-sign`, and tests).
pub fn sign_offline(key: &ed25519_dalek::SigningKey, statement: &Hash) -> Signature {
    use ed25519_dalek::Signer as _;
    let public = key.verifying_key().to_bytes();
    Signature::Offline {
        key_id: super::key_id(super::KeyKind::Offline, &public),
        signature: Bytes(key.sign(&offline_message(statement)).to_bytes().to_vec()),
    }
}
