//! Literal vectors (from `docs/spec/trust_vectors.py`, an independent encoder) and the chain rules of ADR-0015
//! section 2, each shown to refuse.

use super::list::*;
use super::sig::{self, Signature};
use super::statement::*;
use super::types::*;
use super::{key_id, KeyKind};
use crate::script::Revision;
use crate::webauthn::{b64url, FLAG_UP, FLAG_UV};
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use uuid::Uuid;

const VECTORS: &str = include_str!("../../tests/vectors/trust.json");
const RP: &str = "rmm.example.com";
const ORIGIN: &str = "https://rmm.example.com";
const DEP: Uuid = Uuid::from_u128(0x0d);

fn vector(name: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    v[name].as_str().unwrap().to_string()
}

fn h(name: &str) -> Hash {
    Hash::parse(&format!("sha256:{}", vector(name))).unwrap()
}

/// The P-256 base point: a valid key nobody signs with.
const G: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

struct Offline(ed25519_dalek::SigningKey);

impl Offline {
    fn seed(b: u8) -> Self {
        Offline(ed25519_dalek::SigningKey::from_bytes(&[b; 32]))
    }
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn id(&self) -> Hash {
        key_id(KeyKind::Offline, &self.public())
    }
    fn signer(&self, person: u128, name: &str, role: Role) -> Signer {
        Signer {
            kind: SignerKind::Offline,
            public_key: Bytes(self.public()),
            credential_id: None,
            person_id: Uuid::from_u128(person),
            person_name: name.into(),
            may_approve: MayApprove::C3,
            scope: Scope::All,
            role,
        }
    }
    fn sign(&self, statement: &Hash) -> Signature {
        sig::sign_offline(&self.0, statement)
    }
}

struct Passkey(EcdsaKeyPair, Vec<u8>);

impl Passkey {
    fn new(cred: &[u8]) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        Passkey(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
            cred.to_vec(),
        )
    }
    fn public(&self) -> Vec<u8> {
        self.0.public_key().as_ref().to_vec()
    }
    fn id(&self) -> Hash {
        key_id(KeyKind::Passkey, &self.public())
    }
    fn signer(&self, person: u128, name: &str, role: Role) -> Signer {
        Signer {
            kind: SignerKind::Passkey,
            public_key: Bytes(self.public()),
            credential_id: Some(Bytes(self.1.clone())),
            person_id: Uuid::from_u128(person),
            person_name: name.into(),
            may_approve: MayApprove::C3,
            scope: Scope::All,
            role,
        }
    }
    fn sign_at(&self, statement: &Hash, origin: &str) -> Signature {
        let mut a = digest(&SHA256, RP.as_bytes()).as_ref().to_vec();
        a.push(FLAG_UP | FLAG_UV);
        a.extend_from_slice(&0u32.to_be_bytes());
        let c = serde_json::json!({"type": "webauthn.get", "challenge": b64url(&statement.0), "origin": origin})
            .to_string()
            .into_bytes();
        let mut m = a.clone();
        m.extend_from_slice(digest(&SHA256, &c).as_ref());
        let s = self.0.sign(&SystemRandom::new(), &m).unwrap();
        Signature::Passkey {
            key_id: self.id(),
            authenticator_data: Bytes(a),
            client_data_json: Bytes(c),
            signature: Bytes(s.as_ref().to_vec()),
        }
    }
    fn sign(&self, statement: &Hash) -> Signature {
        self.sign_at(statement, ORIGIN)
    }
}

fn list(version: u64, previous: Option<Hash>, signers: Vec<Signer>) -> TrustList {
    TrustList {
        deployment_id: DEP,
        version,
        previous,
        rp_id: RP.into(),
        origins: vec![ORIGIN.into()],
        threshold: 1,
        signers,
        removed_keys: vec![],
        revoked_revisions: vec![],
        made_at: 1_800_000_000,
    }
}

fn signed(l: TrustList, by: &[&dyn Fn(&Hash) -> Signature]) -> SignedList {
    let h = l.hash().unwrap();
    SignedList {
        signatures: by.iter().map(|f| f(&h)).collect(),
        list: l,
    }
}

/// The literal genesis of the vectors file.
fn vector_genesis() -> TrustList {
    let mut l = list(
        1,
        None,
        vec![
            Offline::seed(1).signer(0x0a, "Root", Role::Root),
            Signer {
                kind: SignerKind::Passkey,
                public_key: Bytes(hex::decode(G).unwrap()),
                credential_id: Some(Bytes(b"cred-1".to_vec())),
                person_id: Uuid::from_u128(0x0b),
                person_name: "Operator".into(),
                may_approve: MayApprove::C3,
                scope: Scope::Organizations(vec![Uuid::from_u128(0x0f), Uuid::from_u128(0x0e)]),
                role: Role::Signer,
            },
        ],
    );
    l.made_at = 1_800_000_000;
    l
}

// ---------------------------------------------------------------------------------------
// Literal vectors

#[test]
fn key_ids_match_the_reference_encoder() {
    assert_eq!(Offline::seed(1).id(), h("key_id_offline"));
    assert_eq!(
        key_id(KeyKind::Passkey, &hex::decode(G).unwrap()),
        h("key_id_passkey")
    );
    assert_eq!(
        key_id(KeyKind::Device, &Offline::seed(1).public()),
        h("key_id_device")
    );
}

#[test]
fn the_genesis_encoding_matches_the_reference_byte_for_byte() {
    let l = vector_genesis();
    l.check_alone().unwrap();
    assert_eq!(
        hex::encode(l.encoded().unwrap().as_bytes()),
        vector("genesis_encoding")
    );
    assert_eq!(l.hash().unwrap(), h("genesis_hash"));
    // Signers given in another order are the same list.
    let mut r = l.clone();
    r.signers.reverse();
    assert_eq!(r.hash().unwrap(), l.hash().unwrap());
}

fn vector_revision() -> Revision {
    Revision {
        script_id: Uuid::from_u128(1),
        revision: 1,
        language: "powershell".into(),
        risk: RiskClass::C3,
        scope: None,
        parameters: String::new(),
        source: "Restart-Computer\n".into(),
    }
}

#[test]
fn statements_match_the_reference() {
    let rev = vector_revision();
    let root = Offline::seed(1);
    let a = RevisionApproval::of(DEP, &rev, 1_800_000_100, root.id());
    assert_eq!(
        hex::encode(a.encoded().as_bytes()),
        vector("approval_encoding")
    );
    assert_eq!(a.hash(), h("approval_hash"));
    let salt = [0x22; 32];
    let c = commitment(&salt, [("Reason", "ok"), ("Delay", "30")]).unwrap();
    assert_eq!(c, h("commitment"));
    let run = RunAuthorization {
        deployment_id: DEP,
        job_id: Uuid::from_u128(0x77),
        devices: vec![h("key_id_device")],
        content_hash: rev.content_hash(),
        parameters: c,
        timeout_secs: 600,
        issued_at: 1_800_000_200,
        expires_at: 1_800_001_100,
        signer: root.id(),
    };
    assert_eq!(
        hex::encode(run.encoded().unwrap().as_bytes()),
        vector("run_encoding")
    );
    assert_eq!(run.hash().unwrap(), h("run_hash"));
    // Ed25519 is deterministic: this signature is a literal vector too.
    let Signature::Offline { signature, .. } = root.sign(&a.hash()) else {
        unreachable!()
    };
    assert_eq!(hex::encode(&signature.0), OFFLINE_SIGNATURE_VECTOR.trim());
}

const OFFLINE_SIGNATURE_VECTOR: &str = include_str!("../../tests/vectors/offline_signature.txt");

/// A passkey assertion made once with a software P-256 key and kept: ECDSA is randomized, so this fixture is what
/// catches a change to how passkey signatures are verified.
const PASSKEY_FIXTURE: &str = include_str!("../../tests/vectors/passkey_signature.json");

#[test]
fn a_fixed_passkey_signature_verifies_and_nothing_near_it_does() {
    #[derive(serde::Deserialize)]
    struct F {
        public_key: Bytes,
        credential_id: Bytes,
        signature: Signature,
    }
    let f: F = serde_json::from_str(PASSKEY_FIXTURE).unwrap();
    let mut l = vector_genesis();
    l.signers[1].public_key = f.public_key.clone();
    l.signers[1].credential_id = Some(f.credential_id.clone());
    let statement = h("approval_hash");
    assert!(sig::verify(&f.signature, &statement, &l).is_ok());
    assert!(
        sig::verify(&f.signature, &h("run_hash"), &l).is_err(),
        "another statement"
    );
    let mut other = l.clone();
    other.origins = vec!["https://other.example".into()];
    assert!(
        sig::verify(&f.signature, &statement, &other).is_err(),
        "another origin"
    );
    let mut other = l.clone();
    other.rp_id = "other.example".into();
    assert!(
        sig::verify(&f.signature, &statement, &other).is_err(),
        "another relying party"
    );
}

#[test]
#[ignore = "run once to make tests/vectors/passkey_signature.json"]
fn make_passkey_fixture() {
    let pk = Passkey::new(b"fixture");
    let sig = pk.sign(&h("approval_hash"));
    println!(
        "{}",
        serde_json::json!({ "public_key": Bytes(pk.public()), "credential_id": Bytes(b"fixture".to_vec()), "signature": sig })
    );
}

#[test]
fn json_is_strict() {
    let s = serde_json::to_string(&vector_genesis()).unwrap();
    assert_eq!(
        serde_json::from_str::<TrustList>(&s).unwrap(),
        vector_genesis()
    );
    let extra = s.replacen("{", "{\"extra\":1,", 1);
    assert!(
        serde_json::from_str::<TrustList>(&extra).is_err(),
        "unknown field"
    );
    let twice = s.replacen("{", "{\"version\":2,", 1);
    assert!(
        serde_json::from_str::<TrustList>(&twice).is_err(),
        "duplicate field"
    );
    let sig = r#"{"kind":"offline","key_id":"sha256:0000000000000000000000000000000000000000000000000000000000000000","signature":"AA","more":1}"#;
    assert!(
        serde_json::from_str::<Signature>(sig).is_err(),
        "unknown signature field"
    );
}

// ---------------------------------------------------------------------------------------
// Each version on its own

#[test]
fn a_version_must_be_valid_on_its_own() {
    let root = Offline::seed(1);
    let pk = Passkey::new(b"c1");
    let good = list(
        1,
        None,
        vec![
            root.signer(1, "Root", Role::Root),
            pk.signer(2, "Op", Role::Signer),
        ],
    );
    good.check_alone().unwrap();
    let mut cases: Vec<(&str, TrustList)> = vec![];
    let mut l = good.clone();
    l.signers[0].role = Role::ListAdmin;
    cases.push(("no root", l));
    let mut l = good.clone();
    l.signers[1].role = Role::Root;
    cases.push(("passkey root", l));
    let mut l = good.clone();
    l.threshold = 0;
    cases.push(("threshold 0", l));
    let mut l = good.clone();
    l.threshold = 2;
    cases.push(("threshold above admins", l));
    let mut l = good.clone();
    l.signers.push(root.signer(3, "Again", Role::Signer));
    cases.push(("same key twice", l));
    let mut l = good.clone();
    l.signers
        .push(Passkey::new(b"c1").signer(3, "Twin", Role::Signer));
    cases.push(("same credential id", l));
    let mut l = good.clone();
    l.removed_keys.push(pk.id());
    cases.push(("listed and removed", l));
    let mut l = good.clone();
    l.signers[1].public_key.0[0] = 0x02;
    cases.push(("compressed P-256", l));
    let mut l = good.clone();
    l.signers[1].public_key.0[64] ^= 1;
    cases.push(("off the curve", l));
    let mut l = good.clone();
    l.signers[0].public_key = Bytes(vec![0; 32]);
    cases.push(("small-order Ed25519", l));
    let mut l = good.clone();
    l.signers[1].credential_id = None;
    cases.push(("passkey without credential", l));
    let mut l = good.clone();
    l.signers[1].person_id = Uuid::from_u128(1);
    cases.push(("one person, two names", l));
    let mut l = good.clone();
    l.origins.push(ORIGIN.into());
    cases.push(("origin twice", l));
    let mut l = good.clone();
    l.signers[1].scope = Scope::Organizations(vec![]);
    cases.push(("empty scope", l));
    for (why, l) in cases {
        assert!(
            matches!(l.check_alone(), Err(TrustError::Invalid(..))),
            "{why}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// The chain

fn genesis() -> (Offline, Passkey, Verified, Hash) {
    let root = Offline::seed(1);
    let pk = Passkey::new(b"c1");
    let g = signed(
        list(
            1,
            None,
            vec![
                root.signer(1, "Root", Role::Root),
                pk.signer(2, "Op", Role::Signer),
            ],
        ),
        &[&|h| root.sign(h)],
    );
    let fp = g.list.hash().unwrap();
    let v = verify_genesis(&g, &fp).unwrap();
    (root, pk, v, fp)
}

fn next_of(held: &Verified) -> TrustList {
    let mut l = held.list.clone();
    l.version += 1;
    l.previous = Some(held.hash);
    l
}

#[test]
fn genesis_needs_the_fingerprint_its_threshold_and_every_root() {
    let (root, pk, v, fp) = genesis();
    let g = signed(v.list.clone(), &[&|h| root.sign(h)]);
    assert!(verify_chain(&fp, std::slice::from_ref(&g)).is_ok());
    assert!(matches!(
        verify_genesis(&g, &Hash([0; 32])),
        Err(TrustError::WrongFingerprint(_))
    ));
    let unsigned = signed(v.list.clone(), &[]);
    assert!(matches!(
        verify_genesis(&unsigned, &fp),
        Err(TrustError::Threshold { .. })
    ));
    // A second root that did not sign.
    let root2 = Offline::seed(2);
    let mut l = v.list.clone();
    l.signers.push(root2.signer(3, "Root2", Role::Root));
    let two = signed(l.clone(), &[&|h| root.sign(h)]);
    assert_eq!(
        verify_genesis(&two, &l.hash().unwrap()),
        Err(TrustError::GenesisRoots)
    );
    // A passkey signature alone does not meet a list admin threshold.
    let by_pk = signed(v.list.clone(), &[&|h| pk.sign(h)]);
    assert!(matches!(
        verify_genesis(&by_pk, &fp),
        Err(TrustError::Threshold { .. })
    ));
    let mut l = v.list.clone();
    l.version = 2;
    let wrong = signed(l.clone(), &[&|h| root.sign(h)]);
    assert_eq!(
        verify_genesis(&wrong, &l.hash().unwrap()),
        Err(TrustError::NotGenesis)
    );
}

#[test]
fn a_later_version_extends_only_the_head_and_needs_the_previous_threshold() {
    let (root, pk, v1, _) = genesis();
    let mut l2 = next_of(&v1);
    l2.revoked_revisions.push(Hash([7; 32]));
    let s2 = signed(l2.clone(), &[&|h| root.sign(h)]);
    let v2 = verify_next(&v1, &s2).unwrap();
    // Not again, not skipping, not from somewhere else.
    assert!(matches!(
        verify_next(&v2, &s2),
        Err(TrustError::NotNext { .. })
    ));
    let mut fork = next_of(&v1);
    fork.previous = Some(Hash([1; 32]));
    let fork = signed(fork, &[&|h| root.sign(h)]);
    assert_eq!(verify_next(&v1, &fork), Err(TrustError::NotOurHead(2)));
    let mut other = next_of(&v1);
    other.deployment_id = Uuid::from_u128(99);
    let other = signed(other, &[&|h| root.sign(h)]);
    assert_eq!(
        verify_next(&v1, &other),
        Err(TrustError::OtherDeployment(2))
    );
    // A plain signer cannot sign a version.
    let by_pk = signed(l2.clone(), &[&|h| pk.sign(h)]);
    assert!(matches!(
        verify_next(&v1, &by_pk),
        Err(TrustError::Threshold { .. })
    ));
    // A signature that fails refuses the version, even when the threshold is met without it.
    let bad = signed(
        l2.clone(),
        &[&|h| root.sign(h), &|_| pk.sign(&Hash([0; 32]))],
    );
    assert!(matches!(
        verify_next(&v1, &bad),
        Err(TrustError::Signature { .. })
    ));
    let dup = signed(l2, &[&|h| root.sign(h), &|h| root.sign(h)]);
    assert_eq!(
        verify_next(&v1, &dup),
        Err(TrustError::DuplicateSignature(2))
    );
}

#[test]
fn removal_and_revocation_are_permanent_and_recorded() {
    let (root, pk, v1, _) = genesis();
    // Dropping the passkey without recording it.
    let mut l = next_of(&v1);
    l.signers.retain(|s| s.kind == SignerKind::Offline);
    let quiet = signed(l.clone(), &[&|h| root.sign(h)]);
    assert_eq!(
        verify_next(&v1, &quiet),
        Err(TrustError::DroppedWithoutRemoval(2, pk.id()))
    );
    // Recorded: accepted; then listing it again is refused, and so is forgetting the record.
    l.removed_keys.push(pk.id());
    l.revoked_revisions.push(Hash([9; 32]));
    let v2 = verify_next(&v1, &signed(l.clone(), &[&|h| root.sign(h)])).unwrap();
    let mut back = next_of(&v2);
    back.signers.push(pk.signer(2, "Op", Role::Signer));
    assert!(matches!(
        verify_next(&v2, &signed(back, &[&|h| root.sign(h)])),
        Err(TrustError::Invalid(..))
    ));
    let mut forget = next_of(&v2);
    forget.removed_keys.clear();
    assert_eq!(
        verify_next(&v2, &signed(forget, &[&|h| root.sign(h)])),
        Err(TrustError::Forgets(3))
    );
    let mut unrevoke = next_of(&v2);
    unrevoke.revoked_revisions.clear();
    assert_eq!(
        verify_next(&v2, &signed(unrevoke, &[&|h| root.sign(h)])),
        Err(TrustError::Forgets(3))
    );
    // A key keeps its person.
    let mut moved = next_of(&v1);
    moved.signers[1].person_id = Uuid::from_u128(5);
    assert_eq!(
        verify_next(&v1, &signed(moved, &[&|h| root.sign(h)])),
        Err(TrustError::KeyChanged(2, pk.id()))
    );
}

#[test]
fn changing_who_governs_needs_a_root_and_thresholds_count_people() {
    let root = Offline::seed(1);
    let admin_a = Passkey::new(b"a");
    let admin_a2 = Passkey::new(b"a2");
    let admin_b = Passkey::new(b"b");
    let mut l1 = list(
        1,
        None,
        vec![
            root.signer(1, "Root", Role::Root),
            admin_a.signer(2, "A", Role::ListAdmin),
            admin_a2.signer(2, "A", Role::ListAdmin),
            admin_b.signer(3, "B", Role::ListAdmin),
        ],
    );
    l1.threshold = 2;
    let g = signed(l1.clone(), &[&|h| root.sign(h), &|h| admin_a.sign(h)]);
    let v1 = verify_genesis(&g, &l1.hash().unwrap()).unwrap();
    // Two keys of one person are one person.
    let mut l2 = next_of(&v1);
    l2.revoked_revisions.push(Hash([3; 32]));
    let same_person = signed(l2.clone(), &[&|h| admin_a.sign(h), &|h| admin_a2.sign(h)]);
    assert!(matches!(
        verify_next(&v1, &same_person),
        Err(TrustError::Threshold {
            got: 1,
            need: 2,
            ..
        })
    ));
    assert!(verify_next(
        &v1,
        &signed(l2, &[&|h| admin_a.sign(h), &|h| admin_b.sign(h)])
    )
    .is_ok());
    // Two list admins removing a third, or lowering the threshold, still need the root.
    let mut l2 = next_of(&v1);
    l2.signers.retain(|s| s.person_id != Uuid::from_u128(3));
    l2.removed_keys.push(admin_b.id());
    let coup = signed(l2.clone(), &[&|h| admin_a.sign(h), &|h| admin_a2.sign(h)]);
    assert!(matches!(
        verify_next(&v1, &coup),
        Err(TrustError::Threshold { .. })
    ));
    l2.threshold = 1;
    let coup = signed(l2.clone(), &[&|h| admin_a.sign(h), &|h| admin_b.sign(h)]);
    assert_eq!(verify_next(&v1, &coup), Err(TrustError::RootNeeded(2)));
    assert!(verify_next(&v1, &signed(l2, &[&|h| admin_a.sign(h), &|h| root.sign(h)])).is_ok());
    // Promoting a signer is a change of who governs.
    let mut l2 = next_of(&v1);
    l2.signers
        .push(Passkey::new(b"c").signer(4, "C", Role::ListAdmin));
    let promote = signed(l2, &[&|h| admin_a.sign(h), &|h| admin_b.sign(h)]);
    assert_eq!(verify_next(&v1, &promote), Err(TrustError::RootNeeded(2)));
}

#[test]
fn later_versions_verify_under_the_previous_settings() {
    let root = Offline::seed(1);
    let admin = Passkey::new(b"a");
    let l1 = list(
        1,
        None,
        vec![
            root.signer(1, "Root", Role::Root),
            admin.signer(2, "A", Role::ListAdmin),
        ],
    );
    let v1 = verify_genesis(
        &signed(l1.clone(), &[&|h| root.sign(h)]),
        &l1.hash().unwrap(),
    )
    .unwrap();
    // A new origin applies from the next step: a signature made on it does not count for the version adding it.
    let mut l2 = next_of(&v1);
    l2.origins = vec!["https://new.example".into()];
    let on_new = signed(l2.clone(), &[&|h| admin.sign_at(h, "https://new.example")]);
    assert!(matches!(
        verify_next(&v1, &on_new),
        Err(TrustError::Signature { .. })
    ));
    let v2 = verify_next(&v1, &signed(l2, &[&|h| admin.sign(h)])).unwrap();
    let mut l3 = next_of(&v2);
    l3.revoked_revisions.push(Hash([1; 32]));
    assert!(verify_next(&v2, &signed(l3.clone(), &[&|h| admin.sign(h)])).is_err());
    assert!(verify_next(
        &v2,
        &signed(l3, &[&|h| admin.sign_at(h, "https://new.example")])
    )
    .is_ok());
}

// ---------------------------------------------------------------------------------------
// Statements

#[test]
fn approvals_and_authorizations_verify_under_the_head_and_name_their_signer() {
    let (root, pk, v1, _) = genesis();
    let rev = vector_revision();
    let a = RevisionApproval::of(DEP, &rev, 1, pk.id());
    let sa = SignedApproval {
        signature: pk.sign(&a.hash()),
        approval: a.clone(),
    };
    assert_eq!(verify_approval(&sa, &v1.list).unwrap().key_id(), pk.id());
    assert!(a.matches(&DEP, &rev));
    let mut other = rev.clone();
    other.risk = RiskClass::C0;
    assert!(!a.matches(&DEP, &other), "a C3 approval is not a C0 one");
    // Signed by someone other than the key it names.
    let wrong = SignedApproval {
        signature: root.sign(&a.hash()),
        approval: a.clone(),
    };
    assert_eq!(
        verify_approval(&wrong, &v1.list),
        Err(StatementError::SignerMismatch)
    );
    // Removed from the head: no longer counts.
    let mut l2 = next_of(&v1);
    l2.signers.retain(|s| s.kind == SignerKind::Offline);
    l2.removed_keys.push(pk.id());
    let v2 = verify_next(&v1, &signed(l2, &[&|h| root.sign(h)])).unwrap();
    assert!(matches!(
        verify_approval(&sa, &v2.list),
        Err(StatementError::Signature(sig::SigError::Removed(_)))
    ));
    let run = RunAuthorization {
        deployment_id: DEP,
        job_id: Uuid::from_u128(1),
        devices: vec![Hash([1; 32])],
        content_hash: rev.content_hash(),
        parameters: commitment(&[0; 32], []).unwrap(),
        timeout_secs: 60,
        issued_at: 10,
        expires_at: 20,
        signer: root.id(),
    };
    let sr = SignedAuthorization {
        signature: root.sign(&run.hash().unwrap()),
        authorization: run.clone(),
    };
    assert!(verify_authorization(&sr, &v2.list).is_ok());
    let mut changed = sr.clone();
    changed.authorization.timeout_secs = 61;
    assert!(verify_authorization(&changed, &v2.list).is_err());
}

#[test]
fn commitments_bind_names_values_and_salt() {
    let c = |salt: u8, v: &[(&str, &str)]| commitment(&[salt; 32], v.iter().copied()).unwrap();
    let base = c(1, &[("A", "1"), ("B", "2")]);
    assert_eq!(
        base,
        c(1, &[("B", "2"), ("A", "1")]),
        "order does not matter"
    );
    assert_ne!(base, c(2, &[("A", "1"), ("B", "2")]));
    assert_ne!(base, c(1, &[("A", "1"), ("B", "3")]));
    assert_ne!(base, c(1, &[("A", "1")]));
    assert_ne!(base, c(1, &[("A", "1"), ("B", "2"), ("C", "")]));
    assert_ne!(
        c(1, &[("A", "1B"), ("", "2")]),
        c(1, &[("A", "1"), ("B", "2")])
    );
    assert!(commitment(&[0; 32], [("A", "1"), ("A", "1")]).is_err());
}
