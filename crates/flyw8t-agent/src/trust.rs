//! What this agent trusts (ADR-0015 section 3): the deployment's trust fingerprint, its organization, and the head
//! of the trust list it has verified, kept in `trust.json` in the protected state folder. Nothing here is ever taken
//! from the server unverified: the server only carries versions, and each one is checked before it is stored.

use anyhow::{bail, Context, Result};
use flyw8t_protocol::trust::{self, Hash, SignedList, TrustList, Verified};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

pub const FILE: &str = "trust.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    fingerprint: Hash,
    organization_id: Uuid,
    head: TrustList,
}

/// The pinned trust: fixed fingerprint and organization, and the newest verified version.
#[derive(Debug, Clone)]
pub struct Pinned {
    pub fingerprint: Hash,
    pub organization_id: Uuid,
    pub head: Verified,
}

/// A pin given on the command line: `--trust sha256:… --org <uuid>`.
#[derive(Debug, Clone, Copy)]
pub struct Pin {
    pub fingerprint: Hash,
    pub organization_id: Uuid,
}

impl Pin {
    pub fn parse(fingerprint: &str, org: Uuid) -> Result<Pin> {
        Ok(Pin {
            fingerprint: Hash::parse(fingerprint.trim())
                .context("a trust fingerprint is sha256: followed by 64 lower-case hex digits")?,
            organization_id: org,
        })
    }

    /// Verify a whole chain against this pin.
    pub fn verify(&self, chain: &[SignedList]) -> Result<Pinned> {
        let head = trust::verify_chain(&self.fingerprint, chain)
            .context("the server's trust chain does not verify against the fingerprint given")?;
        Ok(Pinned {
            fingerprint: self.fingerprint,
            organization_id: self.organization_id,
            head,
        })
    }
}

/// The agent's trust state. One lock covers reading, extending and storing the head, and (in build step 4) the
/// final checks before a script starts, so a removal that arrives while a job waits stops it.
pub struct Trust {
    path: PathBuf,
    pinned: Mutex<Option<Pinned>>,
}

impl Trust {
    pub fn load(state_dir: &Path) -> Result<Trust> {
        let path = state_dir.join(FILE);
        let pinned = match std::fs::read(&path) {
            Ok(raw) => Some(decode(&raw).with_context(|| format!("reading {}", path.display()))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Trust {
            path,
            pinned: Mutex::new(pinned),
        })
    }

    pub fn get(&self) -> Option<Pinned> {
        self.pinned.lock().unwrap().clone()
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Option<Pinned>> {
        self.pinned.lock().unwrap()
    }

    /// Extend the head with `versions` (any already held are skipped, but must be identical), and store the new
    /// head before returning. Returns the version now held.
    pub fn update(&self, versions: &[SignedList]) -> Result<Option<u64>> {
        let mut g = self.pinned.lock().unwrap();
        let Some(p) = g.as_mut() else {
            return Ok(None);
        };
        let held = p.head.list.version;
        let mut new: Vec<&SignedList> = versions.iter().filter(|v| v.list.version > held).collect();
        if let Some(same) = versions.iter().find(|v| v.list.version == held) {
            if same.list != p.head.list {
                bail!("the server offers a different version {held} from the one held");
            }
        }
        new.sort_by_key(|v| v.list.version);
        if new.is_empty() {
            return Ok(Some(held));
        }
        let mut head = p.head.clone();
        for v in new {
            head = trust::verify_next(&head, v).with_context(|| {
                format!("trust-list version {} does not verify", v.list.version)
            })?;
        }
        let next = Pinned { head, ..p.clone() };
        save(&self.path, &next)?;
        let version = next.head.list.version;
        *p = next;
        Ok(Some(version))
    }
}

/// Store a pin (enrollment, `trust pin`).
pub fn store(state_dir: &Path, p: &Pinned) -> Result<()> {
    save(&state_dir.join(FILE), p)
}

fn save(path: &Path, p: &Pinned) -> Result<()> {
    let s = Stored {
        fingerprint: p.fingerprint,
        organization_id: p.organization_id,
        head: p.head.list.clone(),
    };
    crate::config::write_atomic(path, &serde_json::to_vec_pretty(&s)?)
}

fn decode(raw: &[u8]) -> Result<Pinned> {
    let s: Stored = serde_json::from_slice(raw)?;
    // The file lives in the protected state folder and was verified before it was written; still, it must be a
    // well-formed version whose hash is recomputed here, never read.
    s.head.check_alone()?;
    let hash = s.head.hash()?;
    if s.head.version == trust::list::GENESIS_VERSION && hash != s.fingerprint {
        bail!("the stored first version does not match the stored fingerprint");
    }
    Ok(Pinned {
        fingerprint: s.fingerprint,
        organization_id: s.organization_id,
        head: Verified { list: s.head, hash },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flyw8t_protocol::trust::sig::sign_offline;
    use flyw8t_protocol::trust::{Bytes, MayApprove, Role, Scope, Signer, SignerKind};

    fn key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[5; 32])
    }

    fn genesis() -> SignedList {
        let k = key();
        let list = TrustList {
            deployment_id: Uuid::from_u128(1),
            version: 1,
            previous: None,
            rp_id: "rmm.example.com".into(),
            origins: vec!["https://rmm.example.com".into()],
            threshold: 1,
            signers: vec![Signer {
                kind: SignerKind::Offline,
                public_key: Bytes(k.verifying_key().to_bytes().to_vec()),
                credential_id: None,
                person_id: Uuid::from_u128(2),
                person_name: "Root".into(),
                may_approve: MayApprove::C3,
                scope: Scope::All,
                role: Role::Root,
            }],
            removed_keys: vec![],
            revoked_revisions: vec![],
            made_at: 1,
        };
        let h = list.hash().unwrap();
        SignedList {
            signatures: vec![sign_offline(&k, &h)],
            list,
        }
    }

    fn next(prev: &Verified, f: impl FnOnce(&mut TrustList)) -> SignedList {
        let mut l = prev.list.clone();
        l.version += 1;
        l.previous = Some(prev.hash);
        f(&mut l);
        let h = l.hash().unwrap();
        SignedList {
            signatures: vec![sign_offline(&key(), &h)],
            list: l,
        }
    }

    #[test]
    fn a_pin_survives_a_restart_and_only_grows() {
        let dir = std::env::temp_dir().join(format!("flyw8t-agent-trust-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let g = genesis();
        let pin = Pin {
            fingerprint: g.list.hash().unwrap(),
            organization_id: Uuid::from_u128(3),
        };
        assert!(Pin {
            fingerprint: Hash([0; 32]),
            ..pin
        }
        .verify(std::slice::from_ref(&g))
        .is_err());
        let p = pin.verify(std::slice::from_ref(&g)).unwrap();
        store(&dir, &p).unwrap();
        let t = Trust::load(&dir).unwrap();
        let v2 = next(&p.head, |l| l.revoked_revisions.push(Hash([1; 32])));
        assert_eq!(t.update(&[g.clone(), v2.clone()]).unwrap(), Some(2));
        let t = Trust::load(&dir).unwrap();
        assert_eq!(t.get().unwrap().head.list.version, 2, "stored before use");
        // A different version 2, or a forged version 3, changes nothing.
        let v1 = Verified {
            list: g.list.clone(),
            hash: g.list.hash().unwrap(),
        };
        let fork = next(&v1, |l| l.revoked_revisions.push(Hash([2; 32])));
        assert!(t.update(&[fork]).is_err());
        let mut v3 = next(&t.get().unwrap().head, |_| {});
        v3.signatures.clear();
        assert!(t.update(&[v3]).is_err());
        assert_eq!(
            Trust::load(&dir).unwrap().get().unwrap().head.list.version,
            2
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
