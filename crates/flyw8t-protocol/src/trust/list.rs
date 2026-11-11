//! The trust list and its chain (ADR-0015 sections 1 and 2).

use super::encode::{record, Enc};
use super::sig::{self, SigError, Signature};
use super::types::{Bytes, Hash, MayApprove, Role, Scope, SignerKind};
use super::{key_id, KeyKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const DOMAIN_LIST: &str = "flyw8t trust list v1";
/// The genesis version's number.
pub const GENESIS_VERSION: u64 = 1;

/// Limits that keep one list small enough to verify and show. Not security boundaries.
pub const MAX_SIGNERS: usize = 256;
pub const MAX_ORIGINS: usize = 8;
pub const MAX_NAME: usize = 200;
pub const MAX_CREDENTIAL_ID: usize = 1023;

/// One key belonging to one person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    pub kind: SignerKind,
    /// Ed25519: 32 raw bytes. P-256: the 65-byte uncompressed SEC1 point.
    pub public_key: Bytes,
    /// A passkey's credential id; absent for an offline key.
    pub credential_id: Option<Bytes>,
    pub person_id: Uuid,
    pub person_name: String,
    pub may_approve: MayApprove,
    pub scope: Scope,
    pub role: Role,
}

impl Signer {
    /// Recomputed from the key, never read from anywhere.
    pub fn key_id(&self) -> Hash {
        key_id(self.kind.into(), &self.public_key.0)
    }

    fn encode(&self, e: &mut Enc) {
        e.record(record::SIGNER, 9, |e| {
            e.enumeration(KeyKind::from(self.kind).code())
                .bytes(&self.public_key.0)
                .option(self.credential_id.as_ref(), |e, c| {
                    e.bytes(&c.0);
                })
                .uuid(&self.person_id)
                .text(&self.person_name)
                .enumeration(self.may_approve.code())
                .enumeration(self.scope.code());
            let orgs: &[Uuid] = match &self.scope {
                Scope::All => &[],
                Scope::Organizations(o) => o,
            };
            // Duplicates were refused by `check_alone` before anything is encoded.
            let _ = e.list(orgs, |e, o| {
                e.uuid(o);
            });
            e.enumeration(self.role.code());
        });
    }
}

/// One version of the trust list. Its hash covers these fields only, not its signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustList {
    pub deployment_id: Uuid,
    pub version: u64,
    pub previous: Option<Hash>,
    pub rp_id: String,
    pub origins: Vec<String>,
    /// How many different people among this version's list admins must sign the next version.
    pub threshold: u64,
    pub signers: Vec<Signer>,
    pub removed_keys: Vec<Hash>,
    pub revoked_revisions: Vec<Hash>,
    /// Seconds since the Unix epoch.
    pub made_at: u64,
}

/// A version and the signatures on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedList {
    pub list: TrustList,
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    #[error("version {0} is not valid on its own: {1}")]
    Invalid(u64, String),
    #[error("the first version does not hash to the pinned fingerprint (it hashes to {0})")]
    WrongFingerprint(Hash),
    #[error("a first version must be version 1, with no previous version and no removed keys")]
    NotGenesis,
    #[error("version {got} does not follow version {held}")]
    NotNext { held: u64, got: u64 },
    #[error("version {0} does not extend the version this holder has")]
    NotOurHead(u64),
    #[error("version {0} is for another deployment")]
    OtherDeployment(u64),
    #[error("version {version}: {error}")]
    Signature { version: u64, error: SigError },
    #[error("version {0} carries two signatures by one key")]
    DuplicateSignature(u64),
    #[error("version {version} is signed by {got} different list admins; {need} are needed")]
    Threshold { version: u64, got: u64, need: u64 },
    #[error("version {0} changes list admins, roots or the threshold, and no root of the version before signed it")]
    RootNeeded(u64),
    #[error("version 1 must be signed by every root in it")]
    GenesisRoots,
    #[error("version {0} forgets a removed key or a revoked revision")]
    Forgets(u64),
    #[error("version {0} drops key {1} without recording it as removed")]
    DroppedWithoutRemoval(u64, Hash),
    #[error("version {0} changes the person or kind of key {1}")]
    KeyChanged(u64, Hash),
}

impl TrustList {
    /// The statement hash of this version.
    pub fn hash(&self) -> Result<Hash, TrustError> {
        self.encoded().map(|e| Hash(e.hash32()))
    }

    /// The encoding the hash is taken over.
    pub fn encoded(&self) -> Result<Enc, TrustError> {
        let bad = |why: &str| TrustError::Invalid(self.version, why.into());
        let mut e = Enc::statement(DOMAIN_LIST);
        e.uuid(&self.deployment_id)
            .uint(self.version)
            .option(self.previous.as_ref(), |e, h| {
                e.hash(&h.0);
            })
            .text(&self.rp_id);
        e.list(&self.origins, |e, o| {
            e.text(o);
        })
        .map_err(|_| bad("an origin appears twice"))?;
        e.uint(self.threshold);
        e.list(&self.signers, |e, s| s.encode(e))
            .map_err(|_| bad("a signer appears twice"))?;
        e.list(&self.removed_keys, |e, h| {
            e.hash(&h.0);
        })
        .map_err(|_| bad("a removed key appears twice"))?;
        e.list(&self.revoked_revisions, |e, h| {
            e.hash(&h.0);
        })
        .map_err(|_| bad("a revoked revision appears twice"))?;
        e.time(self.made_at);
        Ok(e)
    }

    /// Every rule a version must meet on its own (ADR-0015 section 2).
    pub fn check_alone(&self) -> Result<(), TrustError> {
        let bad = |why: String| Err(TrustError::Invalid(self.version, why));
        if self.rp_id.is_empty() || self.rp_id.len() > MAX_NAME {
            return bad("the relying-party id is empty or too long".into());
        }
        if self.origins.is_empty() || self.origins.len() > MAX_ORIGINS {
            return bad(format!("between 1 and {MAX_ORIGINS} origins are needed"));
        }
        if self.signers.is_empty() || self.signers.len() > MAX_SIGNERS {
            return bad(format!("between 1 and {MAX_SIGNERS} signers are needed"));
        }
        let mut ids = BTreeSet::new();
        let mut creds = BTreeSet::new();
        let mut person_names: BTreeMap<Uuid, &str> = BTreeMap::new();
        for s in &self.signers {
            let id = s.key_id();
            if !ids.insert(id) {
                return bad(format!("key {id} appears twice"));
            }
            if self.removed_keys.contains(&id) {
                return bad(format!("key {id} is listed and also removed"));
            }
            if s.person_name.trim().is_empty() || s.person_name.len() > MAX_NAME {
                return bad(format!("key {id} has an empty or too long person name"));
            }
            if let Some(n) = person_names.insert(s.person_id, &s.person_name) {
                if n != s.person_name {
                    return bad(format!("person {} has two names", s.person_id));
                }
            }
            match s.kind {
                SignerKind::Offline => {
                    let canonical = <[u8; 32]>::try_from(s.public_key.0.as_slice())
                        .is_ok_and(|pk| sig::ed25519_key_is_canonical(&pk));
                    if !canonical || s.credential_id.is_some() {
                        return bad(format!("offline key {id} is not a canonical Ed25519 key without a credential id"));
                    }
                }
                SignerKind::Passkey => {
                    if !sig::p256_key_is_canonical(&s.public_key.0) {
                        return bad(format!("passkey {id} is not an uncompressed P-256 point"));
                    }
                    match &s.credential_id {
                        Some(c) if !c.0.is_empty() && c.0.len() <= MAX_CREDENTIAL_ID => {
                            if !creds.insert(c.0.clone()) {
                                return bad(format!("passkey {id} shares its credential id"));
                            }
                        }
                        _ => return bad(format!("passkey {id} has no valid credential id")),
                    }
                    if s.role == Role::Root {
                        return bad(format!("passkey {id} cannot be a root"));
                    }
                }
            }
            if let Scope::Organizations(o) = &s.scope {
                let set: BTreeSet<_> = o.iter().collect();
                if o.is_empty() || set.len() != o.len() {
                    return bad(format!(
                        "key {id} has an empty or repeating organization scope"
                    ));
                }
            }
        }
        if !self.signers.iter().any(|s| s.role == Role::Root) {
            return bad("there is no root".into());
        }
        let admins = self.admin_people().len() as u64;
        if self.threshold < 1 || self.threshold > admins {
            return bad(format!(
                "the threshold is {}, but there are {admins} different list admins",
                self.threshold
            ));
        }
        // Encoding refuses repeated origins, removed keys and revoked revisions.
        self.encoded().map(|_| ())
    }

    /// The different people who are list admins (roots included).
    pub fn admin_people(&self) -> BTreeSet<Uuid> {
        self.signers
            .iter()
            .filter(|s| s.role.is_list_admin())
            .map(|s| s.person_id)
            .collect()
    }

    pub fn signer(&self, id: &Hash) -> Option<&Signer> {
        self.signers.iter().find(|s| s.key_id() == *id)
    }

    /// Who may change the list, and how many must agree: changing these needs a root (section 2).
    fn governance(&self) -> (BTreeSet<(Hash, Role)>, u64) {
        let admins = self
            .signers
            .iter()
            .filter(|s| s.role.is_list_admin())
            .map(|s| (s.key_id(), s.role))
            .collect();
        (admins, self.threshold)
    }
}

/// A version that verified, with its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub list: TrustList,
    pub hash: Hash,
}

/// Verify the signatures on `signed` under `ctx`, and return who signed: key ids and their entries in `ctx`. Any
/// signature that fails refuses the version; a key signing twice does too.
fn signers_of<'a>(
    signed: &SignedList,
    hash: &Hash,
    ctx: &'a TrustList,
) -> Result<Vec<&'a super::list::Signer>, TrustError> {
    let version = signed.list.version;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for s in &signed.signatures {
        if !seen.insert(*s.key_id()) {
            return Err(TrustError::DuplicateSignature(version));
        }
        out.push(
            sig::verify(s, hash, ctx).map_err(|error| TrustError::Signature { version, error })?,
        );
    }
    Ok(out)
}

fn count_admins(version: u64, who: &[&Signer], need: u64) -> Result<(), TrustError> {
    let got = who
        .iter()
        .filter(|s| s.role.is_list_admin())
        .map(|s| s.person_id)
        .collect::<BTreeSet<_>>()
        .len() as u64;
    if got < need {
        return Err(TrustError::Threshold { version, got, need });
    }
    Ok(())
}

/// Verify the first version against the pinned fingerprint.
/// Every rule a first version must meet that does not depend on its signatures. `flyw8t-sign` checks this before
/// it records or signs anything.
pub fn check_genesis(l: &TrustList) -> Result<Hash, TrustError> {
    l.check_alone()?;
    if l.version != GENESIS_VERSION || l.previous.is_some() || !l.removed_keys.is_empty() {
        return Err(TrustError::NotGenesis);
    }
    l.hash()
}

/// Whether a version is refused only for want of signatures, which more signers can supply.
pub fn needs_more_signatures(e: &TrustError) -> bool {
    matches!(
        e,
        TrustError::Threshold { .. } | TrustError::GenesisRoots | TrustError::RootNeeded(_)
    )
}

pub fn verify_genesis(signed: &SignedList, fingerprint: &Hash) -> Result<Verified, TrustError> {
    let l = &signed.list;
    let hash = check_genesis(l)?;
    if hash != *fingerprint {
        return Err(TrustError::WrongFingerprint(hash));
    }
    let who = signers_of(signed, &hash, l)?;
    count_admins(l.version, &who, l.threshold)?;
    let signed_roots: BTreeSet<Hash> = who
        .iter()
        .filter(|s| s.role == Role::Root)
        .map(|s| s.key_id())
        .collect();
    if l.signers
        .iter()
        .any(|s| s.role == Role::Root && !signed_roots.contains(&s.key_id()))
    {
        return Err(TrustError::GenesisRoots);
    }
    Ok(Verified {
        list: l.clone(),
        hash,
    })
}

/// Every rule a later version must meet that does not depend on its signatures: valid on its own, follows the
/// held head, keeps the deployment, forgets no removal or revocation, drops keys only by removing them, and keeps
/// each retained key's person and kind. `flyw8t-sign` checks this before it signs anything.
pub fn check_transition(held: &Verified, next: &TrustList) -> Result<Hash, TrustError> {
    let prev = &held.list;
    let v = next.version;
    next.check_alone()?;
    if Some(v) != prev.version.checked_add(1) {
        return Err(TrustError::NotNext {
            held: prev.version,
            got: v,
        });
    }
    if next.previous != Some(held.hash) {
        return Err(TrustError::NotOurHead(v));
    }
    if next.deployment_id != prev.deployment_id {
        return Err(TrustError::OtherDeployment(v));
    }
    let superset = |a: &[Hash], b: &[Hash]| a.iter().all(|h| b.contains(h));
    if !superset(&prev.removed_keys, &next.removed_keys)
        || !superset(&prev.revoked_revisions, &next.revoked_revisions)
    {
        return Err(TrustError::Forgets(v));
    }
    for old in &prev.signers {
        let id = old.key_id();
        match next.signer(&id) {
            None if !next.removed_keys.contains(&id) => {
                return Err(TrustError::DroppedWithoutRemoval(v, id))
            }
            Some(new) if new.person_id != old.person_id || new.kind != old.kind => {
                return Err(TrustError::KeyChanged(v, id))
            }
            _ => {}
        }
    }
    next.hash()
}

/// Whether `next` changes who governs the list (list admins, roots or the threshold), which needs a root.
pub fn changes_governance(prev: &TrustList, next: &TrustList) -> bool {
    prev.governance() != next.governance()
}

/// Verify one later version against the version held now. `held` is the holder's own head: the chain only ever
/// grows from there.
pub fn verify_next(held: &Verified, signed: &SignedList) -> Result<Verified, TrustError> {
    let (prev, next) = (&held.list, &signed.list);
    let hash = check_transition(held, next)?;
    // Verified under the previous version: its signers, people, threshold, relying party and origins.
    let who = signers_of(signed, &hash, prev)?;
    count_admins(next.version, &who, prev.threshold)?;
    if changes_governance(prev, next) && !who.iter().any(|s| s.role == Role::Root) {
        return Err(TrustError::RootNeeded(next.version));
    }
    Ok(Verified {
        list: next.clone(),
        hash,
    })
}

/// Verify a whole chain from its first version.
pub fn verify_chain(fingerprint: &Hash, chain: &[SignedList]) -> Result<Verified, TrustError> {
    let (first, rest) = chain.split_first().ok_or(TrustError::NotGenesis)?;
    extend(verify_genesis(first, fingerprint)?, rest)
}

/// Extend a held head by `versions`, in order.
pub fn extend(mut head: Verified, versions: &[SignedList]) -> Result<Verified, TrustError> {
    for v in versions {
        head = verify_next(&head, v)?;
    }
    Ok(head)
}
