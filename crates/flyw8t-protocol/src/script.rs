//! Script revisions as both sides see them: the stored text, its content hash and its parameter declarations
//! (ADR-0014 step 2, ADR-0015 sections 4 and 5). Moved here from the server so the agent and `flyw8t-sign` parse and
//! hash exactly as the server does.

use crate::trust::types::{Hash, RiskClass};
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_SOURCE: usize = 256 * 1024;
pub const MAX_PARAMETERS: usize = 16 * 1024;
/// The languages a script may be written in.
pub const LANGUAGES: &[&str] = &["powershell", "bash", "python"];

/// One revision, as approved and as sent to an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub script_id: Uuid,
    pub revision: u64,
    pub language: String,
    pub risk: RiskClass,
    /// The script's organization, or absent for a global script.
    pub scope: Option<Uuid>,
    pub parameters: String,
    pub source: String,
}

impl Revision {
    pub fn content_hash(&self) -> Hash {
        Hash(content_hash(
            self.script_id,
            &self.language,
            self.risk.as_str(),
            &self.parameters,
            &self.source,
        ))
    }
}

/// One line ending (LF), no byte-order mark: what is stored and hashed.
pub fn normalize(raw: &str) -> String {
    raw.strip_prefix('\u{feff}')
        .unwrap_or(raw)
        .replace("\r\n", "\n")
        .replace('\r', "\n")
}

pub fn normalize_source(raw: &str) -> Result<String, String> {
    let s = normalize(raw);
    if s.trim().is_empty() {
        return Err("The script is empty.".into());
    }
    if s.contains('\0') {
        return Err("The script contains a NUL character; scripts are text.".into());
    }
    if s.len() > MAX_SOURCE {
        return Err(format!(
            "The script is {} KiB; at most {} KiB.",
            s.len().div_ceil(1024),
            MAX_SOURCE / 1024
        ));
    }
    Ok(s)
}

pub fn normalize_parameters(raw: &str) -> Result<String, String> {
    let s = normalize(raw).trim_end().to_string();
    if s.contains('\0') || s.len() > MAX_PARAMETERS {
        return Err(format!(
            "Parameters are at most {} KiB of text.",
            MAX_PARAMETERS / 1024
        ));
    }
    Ok(s)
}

/// What a revision would run, hashed: domain-separated, every part length-prefixed. Unchanged since ADR-0014
/// step 2; approvals sign it.
pub fn content_hash(
    script: Uuid,
    language: &str,
    risk: &str,
    parameters: &str,
    source: &str,
) -> [u8; 32] {
    let mut c = Context::new(&SHA256);
    c.update(b"flyw8t script revision v1\0");
    for part in [
        script.as_bytes().as_slice(),
        language.as_bytes(),
        risk.as_bytes(),
        parameters.as_bytes(),
        source.as_bytes(),
    ] {
        c.update(&(part.len() as u64).to_be_bytes());
        c.update(part);
    }
    c.finish().as_ref().try_into().expect("SHA-256 is 32 bytes")
}

// ---------------------------------------------------------------------------------------
// Parameters, one per line:
//   Name = {{level.key}}          a custom field's value
//   Name = secret {{level.key}}   the same, for a field that holds a secret
//   Name = "constant"             a JSON string
//   Name = ask | ask "prompt"     asked when the run is started
// A name is an ASCII letter, then letters, digits or _, at most 40; names are compared ignoring ASCII case.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamSource {
    /// `level` is `global`, `org`, `site` or `device`.
    Field {
        level: String,
        key: String,
        secret: bool,
    },
    Constant(String),
    Ask {
        prompt: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub source: ParamSource,
    pub line: u32,
}

impl Param {
    pub fn is_secret(&self) -> bool {
        matches!(self.source, ParamSource::Field { secret: true, .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamProblem {
    pub line: u32,
    pub message: String,
}

fn field_ref(v: &str) -> Option<(String, String)> {
    let inner = v.strip_prefix("{{")?.strip_suffix("}}")?.trim();
    let (level, key) = inner.split_once('.')?;
    let key_ok = key.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    (["global", "org", "site", "device"].contains(&level) && key_ok)
        .then(|| (level.to_string(), key.to_string()))
}

fn quoted(v: &str) -> Option<String> {
    v.starts_with('"')
        .then(|| serde_json::from_str::<String>(v).ok())
        .flatten()
}

pub fn valid_name(name: &str) -> bool {
    (1..=40).contains(&name.len())
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn parse_parameters(text: &str) -> (Vec<Param>, Vec<ParamProblem>) {
    let (mut params, mut problems) = (Vec::<Param>::new(), Vec::new());
    let mut problem = |line: u32, message: String| problems.push(ParamProblem { line, message });
    for (i, raw) in text.lines().enumerate() {
        let n = i as u32 + 1;
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let Some((name, value)) = l.split_once('=') else {
            problem(n, "Expected Name = value.".into());
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if !valid_name(name) {
            problem(
                n,
                "A parameter name starts with a letter and uses letters, digits and _ (at most 40).".into(),
            );
            continue;
        }
        let source = if let Some((level, key)) = field_ref(value) {
            ParamSource::Field {
                level,
                key,
                secret: false,
            }
        } else if let Some((level, key)) = value
            .strip_prefix("secret ")
            .and_then(|v| field_ref(v.trim()))
        {
            ParamSource::Field {
                level,
                key,
                secret: true,
            }
        } else if let Some(c) = quoted(value) {
            ParamSource::Constant(c)
        } else if value == "ask" {
            ParamSource::Ask { prompt: None }
        } else if let Some(p) = value.strip_prefix("ask ").and_then(|p| quoted(p.trim())) {
            ParamSource::Ask { prompt: Some(p) }
        } else {
            problem(
                n,
                "Expected {{global.key}}, {{org.key}}, {{site.key}} or {{device.key}}, secret and one of those, a \"quoted constant\", or ask.".into(),
            );
            continue;
        };
        // PowerShell parameter names ignore case, so two that differ only in case are the same parameter.
        if params.iter().any(|p| p.name.eq_ignore_ascii_case(name)) {
            problem(n, format!("{name} is declared twice."));
            continue;
        }
        params.push(Param {
            name: name.to_string(),
            source,
            line: n,
        });
    }
    (params, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_is_stored_with_one_line_ending_and_within_limits() {
        assert_eq!(
            normalize_source("\u{feff}a\r\nb\rc\n").unwrap(),
            "a\nb\nc\n"
        );
        assert!(normalize_source(" \n\t").is_err());
        assert!(normalize_source("a\0b").is_err());
        assert!(normalize_source(&"x".repeat(MAX_SOURCE)).is_ok());
        assert!(normalize_source(&"x".repeat(MAX_SOURCE + 1)).is_err());
    }

    #[test]
    fn the_hash_covers_every_part_and_cannot_be_shifted_between_them() {
        let id = Uuid::from_u128(1);
        let h = content_hash(id, "bash", "C0", "", "echo hi");
        assert_eq!(h, content_hash(id, "bash", "C0", "", "echo hi"));
        assert_ne!(
            h,
            content_hash(Uuid::from_u128(2), "bash", "C0", "", "echo hi")
        );
        assert_ne!(h, content_hash(id, "python", "C0", "", "echo hi"));
        assert_ne!(h, content_hash(id, "bash", "C1", "", "echo hi"));
        assert_ne!(h, content_hash(id, "bash", "C0", "A = ask", "echo hi"));
        assert_ne!(h, content_hash(id, "bash", "C0", "", "echo ho"));
        assert_ne!(
            content_hash(id, "bash", "C0", "x", "y"),
            content_hash(id, "bash", "C0", "", "xy")
        );
    }

    #[test]
    fn the_content_hash_is_unchanged_since_step_2() {
        // Literal: revisions stored before ADR-0015 keep their hashes.
        assert_eq!(
            hex::encode(content_hash(
                Uuid::from_u128(1),
                "powershell",
                "C3",
                "",
                "Restart-Computer\n"
            )),
            CONTENT_HASH_VECTOR
        );
    }
    pub(crate) const CONTENT_HASH_VECTOR: &str = include_str!("../tests/vectors/content_hash.txt");

    #[test]
    fn parameters_take_fields_secrets_constants_or_questions() {
        let (p, problems) = parse_parameters(
            "# comment\nShare = {{ org.backup_share }}\nTag={{device.asset_tag}}\nRetries = \"3\"\nWhy = ask \"Reason?\"\nOk = ask\nKey = secret {{org.api_key}}\n",
        );
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(p.len(), 6);
        assert_eq!(
            p[0].source,
            ParamSource::Field {
                level: "org".into(),
                key: "backup_share".into(),
                secret: false,
            }
        );
        assert_eq!(p[0].line, 2);
        assert_eq!(p[2].source, ParamSource::Constant("3".into()));
        assert_eq!(
            p[3].source,
            ParamSource::Ask {
                prompt: Some("Reason?".into())
            }
        );
        assert_eq!(p[4].source, ParamSource::Ask { prompt: None });
        assert!(p[5].is_secret() && !p[0].is_secret());
    }

    #[test]
    fn bad_parameters_are_named_by_line() {
        let (p, problems) = parse_parameters(
            "A = {{tenant.x}}\n9b = ask\nC = bare\nD\nE = ask\ne = ask\nF = \"unterminated\nG = secret \"x\"\nH = secret ask\n",
        );
        assert_eq!(p.len(), 1, "only E survives");
        let lines: Vec<u32> = problems.iter().map(|x| x.line).collect();
        assert_eq!(lines, vec![1, 2, 3, 4, 6, 7, 8, 9]);
        assert!(problems[4].message.contains("twice"));
    }
}
