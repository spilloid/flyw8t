//! Script trust (ADR-0015): the signed trust list and its chain, the statements people sign, and how their
//! signatures are verified. The server, the agent and `flyw8t-sign` all use this one implementation.
//!
//! The byte-level grammar is `docs/spec/trust-encoding.md`; `tests/vectors/` holds its literal test vectors.

pub mod encode;
pub mod list;
pub mod run;
pub mod sig;
pub mod statement;
#[cfg(test)]
mod tests;
pub mod types;

pub use list::{
    extend, verify_chain, verify_genesis, verify_next, SignedList, Signer, TrustError, TrustList,
    Verified,
};
pub use sig::Signature;
pub use statement::{
    commitment, verify_approval, verify_authorization, RevisionApproval, RunAuthorization,
    SignedApproval, SignedAuthorization,
};
pub use types::{Bytes, Hash, KeyKind, MayApprove, RiskClass, Role, Scope, SignerKind};

pub const DOMAIN_KEY_ID: &str = "flyw8t key id v1";

/// A key's id: SHA-256 over the kind and the key in its one canonical form.
pub fn key_id(kind: KeyKind, public_key: &[u8]) -> Hash {
    let mut e = encode::Enc::statement(DOMAIN_KEY_ID);
    e.enumeration(kind.code()).bytes(public_key);
    Hash(e.hash32())
}
