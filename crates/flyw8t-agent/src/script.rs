//! Deciding whether a script offer may run (ADR-0015 section 5). Everything is checked against what this agent
//! holds itself: its pinned trust list, its organization, its device key, its own limits and its clock. The server
//! supplies the offer and nothing else.

use crate::spent::{Spent, CLOCK_TOLERANCE_SECS};
use crate::trust::Pinned;
use flyw8t_protocol::messages::ScriptOffer;
use flyw8t_protocol::trust::run::{check_approvals, check_limits, check_values};
use flyw8t_protocol::trust::statement::window_cap;
use flyw8t_protocol::trust::{commitment, verify_authorization, Hash, RiskClass};
use std::collections::BTreeMap;

/// This device's own limits, set on the device (ADR-0015 section 5).
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub max_risk: RiskClass,
    pub timeout_ceiling_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_risk: RiskClass::C3,
            timeout_ceiling_secs: 3600,
        }
    }
}

/// The device's limits: `policy.json` in the state folder if present (written by an administrator on the device),
/// otherwise the defaults (up to C3, one hour).
pub fn load_policy(state_dir: &std::path::Path) -> anyhow::Result<Policy> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        max_risk: RiskClass,
        timeout_ceiling_secs: u64,
    }
    match std::fs::read(state_dir.join("policy.json")) {
        Ok(raw) => {
            let f: File = serde_json::from_slice(&raw)?;
            Ok(Policy {
                max_risk: f.max_risk,
                timeout_ceiling_secs: f.timeout_ceiling_secs.min(24 * 3600),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Policy::default()),
        Err(e) => Err(e.into()),
    }
}

/// What may run, once admitted.
#[derive(Debug)]
pub struct Admitted {
    pub class: RiskClass,
    pub values: Vec<(String, String)>,
    pub secrets: Vec<(String, String)>,
    pub timeout_secs: u64,
}

/// Every check, in the ADR's order. The first failure refuses the job with its reason.
pub fn check(
    pinned: Option<&Pinned>,
    device_key: &Hash,
    policy: &Policy,
    offer: &ScriptOffer,
    now: u64,
    spent: &Spent,
) -> Result<Admitted, String> {
    // 1. Pinned, and the offer is for this deployment.
    let p = pinned.ok_or("this agent is not pinned to a trust list (flyw8t-agent trust pin)")?;
    let head = &p.head.list;
    if offer.deployment_id != head.deployment_id {
        return Err("the offer is for another deployment".into());
    }
    let rev = &offer.revision;
    let approvals = offer.approvals.len();
    let devices = offer
        .authorization
        .as_ref()
        .map_or(0, |a| a.authorization.devices.len());
    check_limits(rev, approvals, devices).map_err(|e| e.to_string())?;
    if rev.language != "powershell" {
        return Err(format!(
            "this agent runs PowerShell scripts only, not {}",
            rev.language
        ));
    }
    // 2 and 3. Not revoked, and approved in every field by a signer allowed this class for this organization.
    let approvers = check_approvals(head, rev, &offer.approvals, Some(&p.organization_id))
        .map_err(|e| e.to_string())?;
    // 5. This device's own limit.
    if rev.risk > policy.max_risk {
        return Err(format!(
            "this device runs scripts up to {} only",
            policy.max_risk.as_str()
        ));
    }
    let timeout = u64::from(offer.timeout_secs);
    if timeout == 0 || timeout > policy.timeout_ceiling_secs {
        return Err(format!(
            "the timeout is outside this device's limit of {} seconds",
            policy.timeout_ceiling_secs
        ));
    }
    // 6. Values: exactly the declared names, secrets only among secrets, constants unchanged.
    let all = check_values(rev, &offer.values, &offer.secrets).map_err(|e| e.to_string())?;
    // 4. A fresh signature for this run on this device, for C2 and C3.
    if let Some(cap) = window_cap(rev.risk) {
        let a = offer
            .authorization
            .as_ref()
            .ok_or("a C2 or C3 script needs a run signature")?;
        let signer =
            verify_authorization(a, head).map_err(|e| format!("the run signature: {e}"))?;
        if !signer.may_approve.allows(rev.risk) || !signer.scope.includes(&p.organization_id) {
            return Err("the run was signed by someone not allowed to sign it here".into());
        }
        let auth = &a.authorization;
        if auth.deployment_id != head.deployment_id
            || auth.job_id != offer.job_id
            || !auth.devices.contains(device_key)
            || auth.content_hash != rev.content_hash()
        {
            return Err("the run signature is for another job, device or revision".into());
        }
        if auth.timeout_secs != timeout {
            return Err("the run signature names another timeout".into());
        }
        let salt: [u8; 32] = offer
            .salt
            .0
            .as_slice()
            .try_into()
            .map_err(|_| "the salt is not 32 bytes")?;
        let c = commitment(&salt, all.iter().map(|(n, v)| (n.as_str(), v.as_str())))
            .map_err(|e| e.to_string())?;
        if c != auth.parameters {
            return Err("the values are not the ones signed".into());
        }
        if !spent.clock_ok(now) {
            return Err(
                "this device's clock is behind the latest time it has seen: fix the clock".into(),
            );
        }
        let window = auth
            .expires_at
            .checked_sub(auth.issued_at)
            .ok_or("the run signature expires before it was issued")?;
        if window > cap
            || auth.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS)
            || now >= auth.expires_at
        {
            return Err("the run signature is not valid now".into());
        }
        if rev.risk == RiskClass::C2 && approvers.iter().any(|x| x.person_id == signer.person_id) {
            return Err("a C2 run must be signed by someone other than its approver".into());
        }
        if rev.risk == RiskClass::C3 && auth.devices.len() != 1 {
            return Err("a C3 run signature names exactly one device".into());
        }
        if spent.is_spent(head.deployment_id, offer.job_id) {
            return Err("this run signature was already used".into());
        }
    }
    let secret_names: BTreeMap<String, ()> = offer
        .secrets
        .keys()
        .map(|k| (k.to_ascii_lowercase(), ()))
        .collect();
    let (secrets, values) = all
        .into_iter()
        .partition(|(n, _)| secret_names.contains_key(&n.to_ascii_lowercase()));
    Ok(Admitted {
        class: rev.risk,
        values,
        secrets,
        timeout_secs: timeout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flyw8t_protocol::script::Revision;
    use flyw8t_protocol::trust::sig::sign_offline;
    use flyw8t_protocol::trust::{
        key_id, Bytes, KeyKind, MayApprove, RevisionApproval, Role, RunAuthorization, Scope,
        SignedApproval, SignedAuthorization, Signer, SignerKind, TrustList, Verified,
    };
    use uuid::Uuid;

    const NOW: u64 = 1_900_000_000;
    const ORG: Uuid = Uuid::from_u128(0x0a);
    const DEP: Uuid = Uuid::from_u128(0x0d);
    const JOB: Uuid = Uuid::from_u128(0x77);

    fn key(b: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[b; 32])
    }
    fn kid(k: &ed25519_dalek::SigningKey) -> Hash {
        key_id(KeyKind::Offline, &k.verifying_key().to_bytes())
    }
    fn signer(k: &ed25519_dalek::SigningKey, person: u128, role: Role, may: MayApprove) -> Signer {
        Signer {
            kind: SignerKind::Offline,
            public_key: Bytes(k.verifying_key().to_bytes().to_vec()),
            credential_id: None,
            person_id: Uuid::from_u128(person),
            person_name: format!("p{person}"),
            may_approve: may,
            scope: Scope::All,
            role,
        }
    }

    fn pinned(extra: impl FnOnce(&mut TrustList)) -> Pinned {
        let mut l = TrustList {
            deployment_id: DEP,
            version: 1,
            previous: None,
            rp_id: "r".into(),
            origins: vec!["https://r".into()],
            threshold: 1,
            signers: vec![
                signer(&key(1), 1, Role::Root, MayApprove::C3),
                signer(&key(2), 2, Role::Signer, MayApprove::C3),
                signer(&key(3), 3, Role::Signer, MayApprove::C1),
            ],
            removed_keys: vec![],
            revoked_revisions: vec![],
            made_at: 1,
        };
        extra(&mut l);
        let hash = l.hash().unwrap();
        Pinned {
            fingerprint: hash,
            organization_id: ORG,
            head: Verified { list: l, hash },
        }
    }

    fn device() -> Hash {
        key_id(KeyKind::Device, &[9; 32])
    }

    fn rev(risk: RiskClass) -> Revision {
        Revision {
            script_id: Uuid::from_u128(5),
            revision: 1,
            language: "powershell".into(),
            risk,
            scope: None,
            parameters: "Delay = \"30\"\nWhy = ask".into(),
            source: "param([string]$Delay, [string]$Why)\n".into(),
        }
    }

    fn approve(r: &Revision, by: &ed25519_dalek::SigningKey) -> SignedApproval {
        let a = RevisionApproval::of(DEP, r, 1, kid(by));
        SignedApproval {
            signature: sign_offline(by, &a.hash()),
            approval: a,
        }
    }

    fn offer(risk: RiskClass, f: impl FnOnce(&mut RunAuthorization)) -> ScriptOffer {
        let r = rev(risk);
        let salt = [4u8; 32];
        let values: BTreeMap<String, String> = [("Delay", "30"), ("Why", "test")]
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let mut auth = RunAuthorization {
            deployment_id: DEP,
            job_id: JOB,
            devices: vec![device()],
            content_hash: r.content_hash(),
            parameters: commitment(&salt, [("Delay", "30"), ("Why", "test")]).unwrap(),
            timeout_secs: 60,
            issued_at: NOW - 10,
            expires_at: NOW + 300,
            signer: kid(&key(1)),
        };
        f(&mut auth);
        let by = if auth.signer == kid(&key(2)) {
            key(2)
        } else {
            key(1)
        };
        let signed = SignedAuthorization {
            signature: sign_offline(&by, &auth.hash().unwrap()),
            authorization: auth,
        };
        ScriptOffer {
            job_id: JOB,
            deployment_id: DEP,
            timeout_secs: 60,
            approvals: vec![approve(&r, &key(2))],
            revision: r,
            authorization: risk.needs_run_signature().then_some(signed),
            salt: Bytes(salt.to_vec()),
            values,
            secrets: BTreeMap::new(),
        }
    }

    fn run(p: Option<&Pinned>, o: &ScriptOffer, spent: &Spent) -> Result<Admitted, String> {
        check(p, &device(), &Policy::default(), o, NOW, spent)
    }

    #[test]
    fn a_good_offer_is_admitted_and_every_rule_can_refuse_one() {
        let dir = tempfile::tempdir().unwrap();
        let spent = Spent::open(dir.path()).unwrap();
        let p = pinned(|_| {});
        let ok = run(Some(&p), &offer(RiskClass::C3, |_| {}), &spent).unwrap();
        assert_eq!(ok.values.len(), 2);
        assert!(
            run(Some(&p), &offer(RiskClass::C1, |_| {}), &spent).is_ok(),
            "C1 needs no run signature"
        );

        let refuse = |o: ScriptOffer, p: Option<&Pinned>, why: &str| {
            let e = run(p, &o, &spent).unwrap_err();
            assert!(e.contains(why), "expected {why:?}, got {e:?}");
        };
        refuse(offer(RiskClass::C3, |_| {}), None, "not pinned");
        refuse(
            offer(RiskClass::C3, |a| a.devices = vec![Hash([1; 32])]),
            Some(&p),
            "another job, device",
        );
        refuse(
            offer(RiskClass::C3, |a| a.job_id = Uuid::from_u128(1)),
            Some(&p),
            "another job",
        );
        refuse(
            offer(RiskClass::C3, |a| a.timeout_secs = 61),
            Some(&p),
            "another timeout",
        );
        refuse(
            offer(RiskClass::C3, |a| a.parameters = Hash([0; 32])),
            Some(&p),
            "not the ones signed",
        );
        refuse(
            offer(RiskClass::C3, |a| a.expires_at = NOW),
            Some(&p),
            "not valid now",
        );
        refuse(
            offer(RiskClass::C3, |a| a.issued_at = NOW - 3600),
            Some(&p),
            "not valid now",
        );
        refuse(
            offer(RiskClass::C3, |a| {
                a.issued_at = NOW + 3600;
                a.expires_at = NOW + 3700;
            }),
            Some(&p),
            "not valid now",
        );
        refuse(
            offer(RiskClass::C3, |a| a.devices.push(Hash([1; 32]))),
            Some(&p),
            "exactly one device",
        );
        // C2: the approver (person 2) may not also sign the run.
        refuse(
            offer(RiskClass::C2, |a| a.signer = kid(&key(2))),
            Some(&p),
            "someone other than its approver",
        );
        let mut o = offer(RiskClass::C3, |_| {});
        o.authorization = None;
        refuse(o, Some(&p), "needs a run signature");
        let mut o = offer(RiskClass::C3, |_| {});
        o.values.insert("Extra".into(), "x".into());
        refuse(o, Some(&p), "not declared");
        let mut o = offer(RiskClass::C3, |_| {});
        o.values.insert("Delay".into(), "0".into());
        refuse(o, Some(&p), "constant");
        let mut o = offer(RiskClass::C3, |_| {});
        o.approvals = vec![approve(&o.revision, &key(3))];
        refuse(o, Some(&p), "no approval");
        let mut o = offer(RiskClass::C3, |_| {});
        o.deployment_id = Uuid::from_u128(1);
        refuse(o, Some(&p), "another deployment");
        let revoked = pinned(|l| l.revoked_revisions.push(rev(RiskClass::C3).content_hash()));
        refuse(offer(RiskClass::C3, |_| {}), Some(&revoked), "revoked");
        let removed = pinned(|l| {
            l.signers.retain(|s| s.person_id != Uuid::from_u128(2));
            l.removed_keys.push(kid(&key(2)));
        });
        refuse(offer(RiskClass::C3, |_| {}), Some(&removed), "no approval");
        // A script of another organization.
        let mut o = offer(RiskClass::C3, |_| {});
        o.revision.scope = Some(Uuid::from_u128(0xb));
        o.approvals = vec![approve(&o.revision, &key(2))];
        refuse(o, Some(&p), "no approval");
        // The device's own limits.
        let low = Policy {
            max_risk: RiskClass::C1,
            timeout_ceiling_secs: 3600,
        };
        let e = check(
            Some(&p),
            &device(),
            &low,
            &offer(RiskClass::C3, |_| {}),
            NOW,
            &spent,
        )
        .unwrap_err();
        assert!(e.contains("up to C1"), "{e}");
        let short = Policy {
            max_risk: RiskClass::C3,
            timeout_ceiling_secs: 30,
        };
        let e = check(
            Some(&p),
            &device(),
            &short,
            &offer(RiskClass::C3, |_| {}),
            NOW,
            &spent,
        )
        .unwrap_err();
        assert!(e.contains("timeout"), "{e}");
        // Spent, and a clock wound back.
        spent.spend(DEP, JOB).unwrap();
        refuse(offer(RiskClass::C3, |_| {}), Some(&p), "already used");
        let dir2 = tempfile::tempdir().unwrap();
        let fresh = Spent::open(dir2.path()).unwrap();
        fresh.advance(NOW + 3600).unwrap();
        let e = run(Some(&p), &offer(RiskClass::C3, |_| {}), &fresh).unwrap_err();
        assert!(e.contains("clock"), "{e}");
    }
}
