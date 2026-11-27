//! The exact byte strings a device signs.
//!
//! Each connection starts with a fresh server nonce. The device signs a domain-separated
//! message binding that nonce to what it is claiming, so a captured signature cannot be
//! replayed on another connection or reused for a different purpose.

use crate::agent_update::Release;
use uuid::Uuid;

/// Length of the server's per-connection challenge nonce, in bytes.
pub const NONCE_LEN: usize = 32;

const UPDATE_POLICY_DOMAIN: &[u8] = b"flyw8t/agent-update-policy/v1\0";
const AUTH_DOMAIN: &[u8] = b"flyw8t/agent-auth/v1\0";
const ENROLL_DOMAIN: &[u8] = b"flyw8t/agent-enroll/v1\0";

/// Message an enrolled device signs to authenticate a connection.
pub fn auth_message(nonce: &[u8], device_id: Uuid) -> Vec<u8> {
    let mut m = Vec::with_capacity(AUTH_DOMAIN.len() + nonce.len() + 16);
    m.extend_from_slice(AUTH_DOMAIN);
    m.extend_from_slice(nonce);
    m.extend_from_slice(device_id.as_bytes());
    m
}

/// Message an enrolled device signs to check fleet policy for a candidate it has verified locally.
pub fn agent_update_policy_message(nonce: &[u8], device_id: Uuid, candidate: &Release) -> Vec<u8> {
    let release = candidate.signing_bytes();
    let mut m = Vec::with_capacity(UPDATE_POLICY_DOMAIN.len() + nonce.len() + 16 + release.len());
    m.extend_from_slice(UPDATE_POLICY_DOMAIN);
    m.extend_from_slice(nonce);
    m.extend_from_slice(device_id.as_bytes());
    m.extend_from_slice(&release);
    m
}

/// Message a device signs during enrollment, proving it holds the private half of the public
/// key it is registering. `token_digest` is SHA-256 of the enrollment token, so the signature
/// is bound to one token without the signed bytes containing the secret.
pub fn enroll_message(nonce: &[u8], public_key: &[u8], token_digest: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(ENROLL_DOMAIN.len() + nonce.len() + public_key.len() + 32);
    m.extend_from_slice(ENROLL_DOMAIN);
    m.extend_from_slice(nonce);
    m.extend_from_slice(public_key);
    m.extend_from_slice(token_digest);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_and_enroll_messages_are_domain_separated() {
        let nonce = [7u8; NONCE_LEN];
        let id = Uuid::nil();
        let a = auth_message(&nonce, id);
        let e = enroll_message(&nonce, id.as_bytes(), &[]);
        assert_ne!(a, e, "same inputs must not produce the same signed bytes");
        assert!(a.starts_with(AUTH_DOMAIN));
        assert!(e.starts_with(ENROLL_DOMAIN));
    }

    #[test]
    fn agent_update_policy_signature_uses_its_own_domain() {
        let nonce = [7; NONCE_LEN];
        let device = Uuid::from_u128(1);
        let candidate = Release::from_artifact("0.3.1".into(), b"synthetic payload").unwrap();
        let probe = agent_update_policy_message(&nonce, device, &candidate);
        assert!(probe.starts_with(UPDATE_POLICY_DOMAIN));
        assert_ne!(probe, auth_message(&nonce, device));
        let changed = Release::from_artifact("0.3.1".into(), b"synthetic content").unwrap();
        assert_ne!(probe, agent_update_policy_message(&nonce, device, &changed));
    }

    #[test]
    fn auth_message_binds_nonce_and_device() {
        let id = Uuid::from_u128(1);
        assert_ne!(auth_message(&[1; 32], id), auth_message(&[2; 32], id));
        assert_ne!(
            auth_message(&[1; 32], id),
            auth_message(&[1; 32], Uuid::from_u128(2))
        );
    }
}
