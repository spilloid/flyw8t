//! Revision approvals and run authorizations (ADR-0015 section 4).

use super::encode::{record, Enc, EncodeError};
use super::list::{Signer, TrustList};
use super::sig::{self, SigError, Signature};
use super::types::{Hash, RiskClass};
use crate::script::Revision;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DOMAIN_APPROVAL: &str = "flyw8t revision approval v1";
pub const DOMAIN_RUN: &str = "flyw8t run authorization v1";
pub const DOMAIN_VALUES: &str = "flyw8t run values v1";

/// The longest a C3 run authorization may be valid, counted from when it was signed.
pub const C3_WINDOW_SECS: u64 = 15 * 60;
/// The same for C2.
pub const C2_WINDOW_SECS: u64 = 24 * 60 * 60;

pub fn window_cap(class: RiskClass) -> Option<u64> {
    match class {
        RiskClass::C2 => Some(C2_WINDOW_SECS),
        RiskClass::C3 => Some(C3_WINDOW_SECS),
        _ => None,
    }
}

/// One person's approval of one revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionApproval {
    pub deployment_id: Uuid,
    pub script_id: Uuid,
    pub revision: u64,
    pub content_hash: Hash,
    pub risk: RiskClass,
    pub language: String,
    /// The script's organization, or absent for a global script.
    pub script_scope: Option<Uuid>,
    pub approved_at: u64,
    pub signer: Hash,
}

impl RevisionApproval {
    pub fn hash(&self) -> Hash {
        let mut e = Enc::statement(DOMAIN_APPROVAL);
        e.uuid(&self.deployment_id)
            .uuid(&self.script_id)
            .uint(self.revision)
            .hash(&self.content_hash.0)
            .enumeration(self.risk.code())
            .text(&self.language)
            .option(self.script_scope.as_ref(), |e, o| {
                e.uuid(o);
            })
            .time(self.approved_at)
            .hash(&self.signer.0);
        Hash(e.hash32())
    }

    /// The approval a signer gives for `rev` in `deployment`.
    pub fn of(deployment_id: Uuid, rev: &Revision, approved_at: u64, signer: Hash) -> Self {
        RevisionApproval {
            deployment_id,
            script_id: rev.script_id,
            revision: rev.revision,
            content_hash: rev.content_hash(),
            risk: rev.risk,
            language: rev.language.clone(),
            script_scope: rev.scope,
            approved_at,
            signer,
        }
    }

    /// Whether every field names `rev` in `deployment`.
    pub fn matches(&self, deployment_id: &Uuid, rev: &Revision) -> bool {
        self.deployment_id == *deployment_id
            && self.script_id == rev.script_id
            && self.revision == rev.revision
            && self.content_hash == rev.content_hash()
            && self.risk == rev.risk
            && self.language == rev.language
            && self.script_scope == rev.scope
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApproval {
    pub approval: RevisionApproval,
    pub signature: Signature,
}

/// One signature for one run of one revision, with these values, on the devices named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAuthorization {
    pub deployment_id: Uuid,
    pub job_id: Uuid,
    /// Device key ids (`key_id(Device, public key)`), never server-assigned device ids.
    pub devices: Vec<Hash>,
    pub content_hash: Hash,
    pub parameters: Hash,
    pub timeout_secs: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signer: Hash,
}

impl RunAuthorization {
    pub fn hash(&self) -> Result<Hash, EncodeError> {
        let mut e = Enc::statement(DOMAIN_RUN);
        e.uuid(&self.deployment_id).uuid(&self.job_id);
        e.list(&self.devices, |e, d| {
            e.hash(&d.0);
        })?;
        e.hash(&self.content_hash.0)
            .hash(&self.parameters.0)
            .duration(self.timeout_secs)
            .time(self.issued_at)
            .time(self.expires_at)
            .hash(&self.signer.0);
        Ok(Hash(e.hash32()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorization {
    pub authorization: RunAuthorization,
    pub signature: Signature,
}

/// The commitment to a run's values: the salt, then every declared parameter's (name, value), the names as
/// declared. The caller has already checked that the supplied names are exactly the declared ones.
pub fn commitment<'a>(
    salt: &[u8; 32],
    values: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Hash, EncodeError> {
    let mut e = Enc::statement(DOMAIN_VALUES);
    e.bytes(salt);
    e.list(values, |e, (name, value)| {
        e.record(record::PARAMETER, 2, |e| {
            e.text(name).text(value);
        });
    })?;
    Ok(Hash(e.hash32()))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatementError {
    #[error("signed by a key other than the one the statement names")]
    SignerMismatch,
    #[error(transparent)]
    Signature(#[from] SigError),
    #[error("a list in the statement holds the same item twice")]
    Encoding,
}

/// Verify a signed approval under the head version, and return its signer.
pub fn verify_approval<'a>(
    a: &SignedApproval,
    head: &'a TrustList,
) -> Result<&'a Signer, StatementError> {
    if a.signature.key_id() != &a.approval.signer {
        return Err(StatementError::SignerMismatch);
    }
    Ok(sig::verify(&a.signature, &a.approval.hash(), head)?)
}

/// Verify a signed run authorization under the head version, and return its signer.
pub fn verify_authorization<'a>(
    a: &SignedAuthorization,
    head: &'a TrustList,
) -> Result<&'a Signer, StatementError> {
    if a.signature.key_id() != &a.authorization.signer {
        return Err(StatementError::SignerMismatch);
    }
    let h = a
        .authorization
        .hash()
        .map_err(|_| StatementError::Encoding)?;
    Ok(sig::verify(&a.signature, &h, head)?)
}
