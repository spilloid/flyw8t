//! The checks a run's revision, approvals and values must pass (ADR-0015 section 5, steps 2, 3 and 6), shared by
//! the agent and by `flyw8t-sign authorize` so both refuse the same things.

use super::list::{Signer, TrustList};
use super::statement::{verify_approval, SignedApproval};
use super::types::{Bytes, Hash, RiskClass};
use crate::script::{parse_parameters, ParamSource, Revision};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Largest single value, and all values together.
pub const MAX_VALUE: usize = 4 * 1024;
pub const MAX_VALUES: usize = 64 * 1024;

/// What a person is asked to sign for one C2 or C3 run: downloaded from the console for `flyw8t-sign authorize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    pub deployment_id: Uuid,
    pub job_id: Uuid,
    pub revision: Revision,
    pub approvals: Vec<SignedApproval>,
    /// Plain values by parameter name. Secret parameters are not supported offline yet.
    pub values: BTreeMap<String, String>,
    pub salt: Bytes,
    pub devices: Vec<Hash>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    #[error("the revision has been revoked")]
    Revoked,
    #[error("no approval of this exact revision by a signer allowed to approve {0:?} for this organization")]
    NotApproved(RiskClass),
    #[error("the parameter declarations have problems (line {0})")]
    Declarations(u32),
    #[error("parameter {0} is declared but has no value")]
    Missing(String),
    #[error("a value was sent for {0}, which is not declared")]
    Undeclared(String),
    #[error("parameter {0} has two values")]
    Twice(String),
    #[error("parameter {0} is a constant and its value differs")]
    ConstantChanged(String),
    #[error("parameter {0} is a secret and arrived as a plain value, or the other way round")]
    SecretMismatch(String),
    #[error("parameter {0}'s value is too long")]
    TooLong(String),
    #[error("the values are too long in all")]
    TooLongInAll,
}

/// Step 2 and 3: the revision is not revoked, and at least one approval matches it in every field by a signer in
/// `head` who may approve its class for `org` (or for any organization when `org` is `None`, as in `flyw8t-sign`,
/// which does not know the device's organization). Returns the approvers relied on.
pub fn check_approvals<'a>(
    head: &'a TrustList,
    rev: &Revision,
    approvals: &[SignedApproval],
    org: Option<&Uuid>,
) -> Result<Vec<&'a Signer>, RunError> {
    let hash = rev.content_hash();
    if head.revoked_revisions.contains(&hash) {
        return Err(RunError::Revoked);
    }
    let scope_ok = |rev_scope: &Option<Uuid>| match (rev_scope, org) {
        (None, _) | (_, None) => true,
        (Some(s), Some(o)) => s == o,
    };
    let mut out: Vec<&Signer> = Vec::new();
    for a in approvals {
        if !a.approval.matches(&head.deployment_id, rev) || !scope_ok(&a.approval.script_scope) {
            continue;
        }
        let Ok(s) = verify_approval(a, head) else {
            continue;
        };
        if s.may_approve.allows(rev.risk)
            && org.is_none_or(|o| s.scope.includes(o))
            && !out.contains(&s)
        {
            out.push(s);
        }
    }
    if out.is_empty() {
        return Err(RunError::NotApproved(rev.risk));
    }
    Ok(out)
}

/// Step 6: the supplied names are exactly the declared ones, secrets only among secrets, constants unchanged, sizes
/// within limits. Returns every declared parameter's (name as declared, value), for the commitment and the wrapper.
pub fn check_values(
    rev: &Revision,
    plain: &BTreeMap<String, String>,
    secrets: &BTreeMap<String, String>,
) -> Result<Vec<(String, String)>, RunError> {
    let (params, problems) = parse_parameters(&rev.parameters);
    if let Some(p) = problems.first() {
        return Err(RunError::Declarations(p.line));
    }
    let mut seen: Vec<String> = Vec::new();
    let mut total = 0usize;
    for (name, value) in plain.iter().chain(secrets) {
        let lower = name.to_ascii_lowercase();
        if seen.contains(&lower) {
            return Err(RunError::Twice(name.clone()));
        }
        seen.push(lower);
        if !params.iter().any(|p| p.name.eq_ignore_ascii_case(name)) {
            return Err(RunError::Undeclared(name.clone()));
        }
        if value.len() > MAX_VALUE {
            return Err(RunError::TooLong(name.clone()));
        }
        total += value.len();
    }
    if total > MAX_VALUES {
        return Err(RunError::TooLongInAll);
    }
    let find = |m: &BTreeMap<String, String>, n: &str| {
        m.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    let mut out = Vec::with_capacity(params.len());
    for p in &params {
        let (in_plain, in_secret) = (find(plain, &p.name), find(secrets, &p.name));
        let value = match (in_plain, in_secret, p.is_secret()) {
            (Some(v), None, false) | (None, Some(v), true) => v,
            (None, None, _) => return Err(RunError::Missing(p.name.clone())),
            _ => return Err(RunError::SecretMismatch(p.name.clone())),
        };
        if let ParamSource::Constant(c) = &p.source {
            if *c != value {
                return Err(RunError::ConstantChanged(p.name.clone()));
            }
        }
        out.push((p.name.clone(), value));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rev(params: &str) -> Revision {
        Revision {
            script_id: Uuid::from_u128(1),
            revision: 1,
            language: "powershell".into(),
            risk: RiskClass::C2,
            scope: None,
            parameters: params.into(),
            source: "param()\n".into(),
        }
    }

    fn m(v: &[(&str, &str)]) -> BTreeMap<String, String> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn values_must_be_exactly_the_declared_set() {
        let r = rev("Path = ask\nMode = \"fast\"\nKey = secret {{org.api_key}}\n");
        let ok = check_values(
            &r,
            &m(&[("path", "C:\\x"), ("Mode", "fast")]),
            &m(&[("Key", "s")]),
        )
        .unwrap();
        assert_eq!(
            ok,
            vec![
                ("Path".into(), "C:\\x".into()),
                ("Mode".into(), "fast".into()),
                ("Key".into(), "s".into())
            ],
            "names as declared, in declaration order"
        );
        type Case = (BTreeMap<String, String>, BTreeMap<String, String>, RunError);
        let cases: Vec<Case> = vec![
            (
                m(&[("Mode", "fast")]),
                m(&[("Key", "s")]),
                RunError::Missing("Path".into()),
            ),
            (
                m(&[("Path", "x"), ("Mode", "fast"), ("Extra", "-Force")]),
                m(&[("Key", "s")]),
                RunError::Undeclared("Extra".into()),
            ),
            (
                m(&[("Path", "x"), ("PATH", "y"), ("Mode", "fast")]),
                m(&[("Key", "s")]),
                RunError::Twice("Path".into()),
            ),
            (
                m(&[("Path", "x"), ("Mode", "slow")]),
                m(&[("Key", "s")]),
                RunError::ConstantChanged("Mode".into()),
            ),
            (
                m(&[("Path", "x"), ("Mode", "fast"), ("Key", "s")]),
                m(&[]),
                RunError::SecretMismatch("Key".into()),
            ),
            (
                m(&[("Mode", "fast")]),
                m(&[("Key", "s"), ("Path", "x")]),
                RunError::SecretMismatch("Path".into()),
            ),
            (
                m(&[("Path", &"x".repeat(MAX_VALUE + 1)), ("Mode", "fast")]),
                m(&[("Key", "s")]),
                RunError::TooLong("Path".into()),
            ),
        ];
        for (plain, secret, want) in cases {
            assert_eq!(
                check_values(&r, &plain, &secret),
                Err(want.clone()),
                "{want:?}"
            );
        }
        assert_eq!(
            check_values(&rev(""), &m(&[("A", "1")]), &m(&[])),
            Err(RunError::Undeclared("A".into()))
        );
        assert_eq!(check_values(&rev(""), &m(&[]), &m(&[])), Ok(vec![]));
        assert_eq!(
            check_values(&rev("bad line"), &m(&[]), &m(&[])),
            Err(RunError::Declarations(1))
        );
    }
}
