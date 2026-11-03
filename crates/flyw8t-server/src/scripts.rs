//! Script library (ADR-0014 step 2): scripts that belong to one organization or are global, and their revisions. Every
//! save is a new, permanent revision with a hash of what it would run; the console shows each one, its diff from the
//! one before, and what the server's checks found. Nothing here runs anything, and nothing is approved yet (step 3).
//!
//! Who: `ViewScripts` reads global scripts and those of the user's organizations; `EditScripts` creates scripts and
//! saves revisions of any script it can read, global ones included (the operator's decision, 2026-11-02).

use crate::audit::Audit;
use crate::auth::{Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::script_check::{self, SyntaxCheck};
use crate::web::{check_csrf, ctx, flash, html, page, to, Form, MsgQuery};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use flyw8t_domain::Permission;
use flyw8t_web::model::{
    DiffRow, Flash, MissingRequired, OrgRef, RevisionChanges, RevisionSummary, RevisionView,
    ScriptDraft, ScriptListRow, ScriptProblem, ScriptView,
};
use ring::digest::{Context, SHA256};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

/// (value, label, file extension)
pub const LANGUAGES: &[(&str, &str, &str)] = &[
    ("powershell", "PowerShell", "ps1"),
    ("bash", "Bash", "sh"),
    ("python", "Python", "py"),
];
pub const RISK_CLASSES: &[&str] = &["C0", "C1", "C2", "C3"];
pub const MAX_SOURCE: usize = 256 * 1024;
const MAX_PARAMETERS: usize = 16 * 1024;
/// Lines compared at most (old x new, after the common start and end) before a diff is declined.
const DIFF_CELLS: usize = 2_000_000;
/// Unchanged lines kept around each change in a diff.
const CONTEXT: usize = 3;
/// CSP for the editor page: the console's policy plus same-origin script (Tab and file loading; ADR-0014).
const EDITOR_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; manifest-src 'self'; \
     form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

fn language(v: &str) -> Option<(&'static str, &'static str, &'static str)> {
    LANGUAGES.iter().copied().find(|(l, ..)| *l == v)
}

// ---------------------------------------------------------------------------------------
// Text as stored

/// One line ending (LF), no byte-order mark, no NUL; what is stored and hashed.
fn normalize(raw: &str) -> String {
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

fn normalize_parameters(raw: &str) -> Result<String, String> {
    let s = normalize(raw).trim_end().to_string();
    if s.contains('\0') || s.len() > MAX_PARAMETERS {
        return Err(format!(
            "Parameters are at most {} KiB of text.",
            MAX_PARAMETERS / 1024
        ));
    }
    Ok(s)
}

/// What a revision would run, hashed: domain-separated, every part length-prefixed. Approval (step 3) signs this.
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
// Parameters: `Name = {{org.backup_share}}`, `Name = "constant"`, `Name = ask` or `Name = ask "prompt"`, one per line.
// Values reach the script as data at run time (step 4), never as text in the source.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamSource {
    /// `level` is `global`, `org`, `site` or `device`.
    Field {
        level: String,
        key: String,
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

fn problem(section: &'static str, line: Option<u32>, message: impl Into<String>) -> ScriptProblem {
    ScriptProblem {
        section,
        line,
        message: message.into(),
    }
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

pub fn parse_parameters(text: &str) -> (Vec<Param>, Vec<ScriptProblem>) {
    let (mut params, mut problems) = (Vec::<Param>::new(), Vec::new());
    for (i, raw) in text.lines().enumerate() {
        let n = i as u32 + 1;
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let Some((name, value)) = l.split_once('=') else {
            problems.push(problem("parameters", Some(n), "Expected Name = value."));
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        let name_ok = (1..=40).contains(&name.len())
            && name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !name_ok {
            problems.push(problem(
                "parameters",
                Some(n),
                "A parameter name starts with a letter and uses letters, digits and _ (at most 40).",
            ));
            continue;
        }
        let source = if let Some((level, key)) = field_ref(value) {
            ParamSource::Field { level, key }
        } else if let Some(c) = quoted(value) {
            ParamSource::Constant(c)
        } else if value == "ask" {
            ParamSource::Ask { prompt: None }
        } else if let Some(p) = value.strip_prefix("ask ").and_then(|p| quoted(p.trim())) {
            ParamSource::Ask { prompt: Some(p) }
        } else {
            problems.push(problem(
                "parameters",
                Some(n),
                "Expected {{global.key}}, {{org.key}}, {{site.key}} or {{device.key}}, a \"quoted constant\", or ask.",
            ));
            continue;
        };
        // PowerShell parameter names ignore case, so two that differ only in case are the same parameter.
        if params.iter().any(|p| p.name.eq_ignore_ascii_case(name)) {
            problems.push(problem(
                "parameters",
                Some(n),
                format!("{name} is declared twice."),
            ));
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

/// A field a parameter refers to, as far as these checks need it.
pub struct FieldInfo<'a> {
    pub key: &'a str,
    pub scopes: &'a [String],
    pub has_default: bool,
    pub archived: bool,
}

/// Parameters that name fields which do not exist, are archived, or cannot have a value at the level named.
pub fn check_references(params: &[Param], fields: &[FieldInfo]) -> Vec<ScriptProblem> {
    let mut out = Vec::new();
    for p in params {
        let ParamSource::Field { level, key } = &p.source else {
            continue;
        };
        let line = Some(p.line);
        let Some(f) = fields.iter().find(|f| f.key == key) else {
            out.push(problem(
                "parameters",
                line,
                format!("No custom field is named {key}."),
            ));
            continue;
        };
        if f.archived {
            out.push(problem(
                "parameters",
                line,
                format!("The field {key} is archived."),
            ));
            continue;
        }
        let allows = |s: &str| f.scopes.iter().any(|x| x == s);
        let reachable = match level.as_str() {
            "global" => allows("global") || f.has_default,
            "org" => allows("organization") || allows("global") || f.has_default,
            "site" => {
                out.push(problem(
                    "parameters",
                    line,
                    "Site values are not available yet.",
                ));
                continue;
            }
            _ => true,
        };
        if !reachable {
            out.push(problem(
                "parameters",
                line,
                format!("{key} can never have a value at the {level} level: no value is allowed there or above it, and there is no default."),
            ));
        }
    }
    out
}

/// Lines of the source that look like field placeholders: they would reach the script as literal text.
pub fn placeholders_in_source(source: &str) -> Vec<ScriptProblem> {
    source
        .lines()
        .enumerate()
        .filter(|(_, l)| {
            l.match_indices("{{").any(|(i, _)| {
                let rest = l[i + 2..].trim_start();
                ["global.", "org.", "site.", "device."].iter().any(|p| rest.starts_with(p))
            })
        })
        .map(|(i, _)| {
            problem(
                "source",
                Some(i as u32 + 1),
                "Values are never put into the script text, so this stays as written. Declare a parameter for it instead.",
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// Diffs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Same,
    Removed,
    Added,
}

/// Line diff by longest common subsequence, after taking off the common start and end. `None` when the changed middle
/// is too large to compare here.
fn diff_ops<'a>(old: &[&'a str], new: &[&'a str]) -> Option<Vec<(Op, &'a str)>> {
    let pre = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let suf = old[pre..]
        .iter()
        .rev()
        .zip(new[pre..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let (a, b) = (&old[pre..old.len() - suf], &new[pre..new.len() - suf]);
    if a.len().saturating_mul(b.len()) > DIFF_CELLS {
        return None;
    }
    // lcs[i][j]: common subsequence length of a[i..] and b[j..]
    let w = b.len() + 1;
    let mut lcs = vec![0u32; (a.len() + 1) * w];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i * w + j] = if a[i] == b[j] {
                lcs[(i + 1) * w + j + 1] + 1
            } else {
                lcs[(i + 1) * w + j].max(lcs[i * w + j + 1])
            };
        }
    }
    let mut ops: Vec<(Op, &str)> = old[..pre].iter().map(|l| (Op::Same, *l)).collect();
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            ops.push((Op::Same, a[i]));
            i += 1;
            j += 1;
        // On a tie, a removal comes before the addition that replaces it.
        } else if j < b.len() && (i == a.len() || lcs[i * w + j + 1] > lcs[(i + 1) * w + j]) {
            ops.push((Op::Added, b[j]));
            j += 1;
        } else {
            ops.push((Op::Removed, a[i]));
            i += 1;
        }
    }
    ops.extend(old[old.len() - suf..].iter().map(|l| (Op::Same, *l)));
    Some(ops)
}

/// The diff from `old` to `new` as rows to show: changes with a few lines around them, the rest folded. `None` when too
/// large to compare.
pub fn diff(old: &str, new: &str) -> Option<Vec<DiffRow>> {
    let (o, n): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
    let ops = diff_ops(&o, &n)?;
    let near: Vec<bool> = (0..ops.len())
        .map(|k| {
            ops[k.saturating_sub(CONTEXT)..(k + CONTEXT + 1).min(ops.len())]
                .iter()
                .any(|(op, _)| *op != Op::Same)
        })
        .collect();
    let (mut rows, mut folded, mut ol, mut nl) = (Vec::new(), 0usize, 0usize, 0usize);
    for (k, (op, text)) in ops.iter().enumerate() {
        let text = text.to_string();
        match op {
            Op::Same => {
                ol += 1;
                nl += 1;
                if near[k] {
                    if folded > 0 {
                        rows.push(DiffRow::Folded(std::mem::take(&mut folded)));
                    }
                    rows.push(DiffRow::Same {
                        old: ol,
                        new: nl,
                        text,
                    });
                } else {
                    folded += 1;
                }
            }
            Op::Removed => {
                ol += 1;
                rows.push(DiffRow::Removed { old: ol, text });
            }
            Op::Added => {
                nl += 1;
                rows.push(DiffRow::Added { new: nl, text });
            }
        }
    }
    if folded > 0 {
        rows.push(DiffRow::Folded(folded));
    }
    Some(rows)
}

// ---------------------------------------------------------------------------------------
// Loading, with the viewer's scope

#[derive(Debug, Clone, sqlx::FromRow)]
struct ScriptRow {
    id: Uuid,
    organization_id: Option<Uuid>,
    org_name: Option<String>,
    name: String,
    language: String,
    description: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct RevisionRow {
    number: i32,
    source: String,
    risk_class: String,
    parameters: String,
    content_hash: Vec<u8>,
    syntax_check: sqlx::types::Json<SyntaxCheck>,
    note: String,
    author: String,
    created_at: OffsetDateTime,
}

const REVISION_COLUMNS: &str =
    "r.number, r.source, r.risk_class, r.parameters, r.content_hash, r.syntax_check, r.note, \
     u.email AS author, r.created_at";

/// A script the viewer may read (global, or in one of their organizations); otherwise not found.
async fn load(state: &Shared, p: &Principal, id: Uuid) -> AppResult<ScriptRow> {
    p.require(Permission::ViewScripts)?;
    let (all, orgs) = p.scope();
    sqlx::query_as(
        "SELECT s.id, s.organization_id, o.name AS org_name, s.name, s.language, s.description
           FROM scripts s LEFT JOIN organizations o ON o.id = s.organization_id
          WHERE s.id = $1 AND (s.organization_id IS NULL OR $2 OR s.organization_id = ANY($3))",
    )
    .bind(id)
    .bind(all)
    .bind(&orgs)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)
}

async fn revision(
    state: &Shared,
    script: Uuid,
    number: Option<i32>,
) -> sqlx::Result<Option<RevisionRow>> {
    sqlx::query_as(&format!(
        "SELECT {REVISION_COLUMNS} FROM script_revisions r JOIN users u ON u.id = r.author
          WHERE r.script_id = $1 AND ($2::int IS NULL OR r.number = $2) ORDER BY r.number DESC LIMIT 1"
    ))
    .bind(script)
    .bind(number)
    .fetch_optional(&state.db)
    .await
}

fn script_view(s: &ScriptRow) -> ScriptView {
    let (_, label, ext) = language(&s.language).unwrap_or(("", "?", "txt"));
    ScriptView {
        id: s.id,
        name: s.name.clone(),
        description: s.description.clone(),
        organization: s.organization_id.map(|id| OrgRef {
            id,
            name: s.org_name.clone().unwrap_or_default(),
        }),
        language: s.language.clone(),
        language_label: label,
        extension: ext,
    }
}

fn revision_view(r: &RevisionRow) -> RevisionView {
    let sc = &r.syntax_check.0;
    RevisionView {
        number: r.number,
        source: r.source.clone(),
        risk_class: r.risk_class.clone(),
        parameters: r.parameters.clone(),
        hash: hex::encode(&r.content_hash),
        note: r.note.clone(),
        author: r.author.clone(),
        created_at: r.created_at,
        checker: sc.checker.clone(),
        unchecked: sc.unchecked.clone(),
    }
}

/// Everything the checks have to say about a revision: its stored syntax check, plus parameters and references checked
/// against the fields as they are now.
async fn problems(
    state: &Shared,
    p: &Principal,
    r: &RevisionRow,
) -> sqlx::Result<(Vec<ScriptProblem>, Vec<MissingRequired>)> {
    let mut out: Vec<ScriptProblem> = r
        .syntax_check
        .0
        .problems
        .iter()
        .map(|x| problem("source", x.line, x.message.clone()))
        .collect();
    out.extend(placeholders_in_source(&r.source));
    let (params, mut parse) = parse_parameters(&r.parameters);
    out.append(&mut parse);
    let defs = crate::fields::definitions(state, true).await?;
    let infos: Vec<FieldInfo> = defs
        .iter()
        .map(|d| FieldInfo {
            key: &d.key,
            scopes: &d.scopes,
            has_default: d.default_value.is_some(),
            archived: d.archived_at.is_some(),
        })
        .collect();
    out.extend(check_references(&params, &infos));
    out.sort_by_key(|x| (x.section != "parameters", x.line));
    let used: Vec<&str> = params
        .iter()
        .filter_map(|p| match &p.source {
            ParamSource::Field { key, .. } => Some(key.as_str()),
            _ => None,
        })
        .collect();
    let missing = if used.is_empty() {
        vec![]
    } else {
        crate::fields::missing_required(state, p)
            .await?
            .into_iter()
            .filter(|m| used.contains(&m.key.as_str()))
            .collect()
    };
    Ok((out, missing))
}

fn can_edit(p: &Principal) -> bool {
    p.can(Permission::EditScripts)
}

// ---------------------------------------------------------------------------------------
// Handlers

pub async fn list_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewScripts)?;
        let (all, orgs) = p.scope();
        let rows: Vec<(Uuid, String, String, Option<String>, Option<i32>, Option<String>, Option<String>, Option<OffsetDateTime>)> =
            sqlx::query_as(
                "SELECT s.id, s.name, s.language, o.name, r.number, r.risk_class, u.email, r.created_at
                   FROM scripts s
                   LEFT JOIN organizations o ON o.id = s.organization_id
                   LEFT JOIN LATERAL (SELECT number, risk_class, author, created_at FROM script_revisions
                                       WHERE script_id = s.id ORDER BY number DESC LIMIT 1) r ON true
                   LEFT JOIN users u ON u.id = r.author
                  WHERE s.organization_id IS NULL OR $1 OR s.organization_id = ANY($2)
                  ORDER BY s.organization_id IS NOT NULL, lower(coalesce(o.name, '')), lower(s.name)",
            )
            .bind(all)
            .bind(&orgs)
            .fetch_all(&state.db)
            .await?;
        let rows = rows
            .into_iter()
            .map(|(id, name, lang, org, number, risk, by, at)| ScriptListRow {
                id,
                name,
                language_label: language(&lang).map(|l| l.1).unwrap_or("?"),
                organization: org,
                latest: number,
                risk_class: risk,
                updated_by: by,
                updated_at: at,
            })
            .collect();
        let orgs: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM organizations WHERE ($1 OR id = ANY($2)) ORDER BY lower(name)")
                .bind(all)
                .bind(&orgs)
                .fetch_all(&state.db)
                .await?;
        let orgs = orgs.into_iter().map(|(id, name)| OrgRef { id, name }).collect();
        html(flyw8t_web::scripts_page(&ctx(&p, flash(m.m.as_deref())), rows, orgs, can_edit(&p)))
    })
    .await
}

pub async fn create(State(state): State<Shared>, WebUser(p): WebUser, body: Bytes) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::EditScripts)?;
        let name = form.get("name").unwrap_or("").trim().to_string();
        if name.is_empty() || name.chars().count() > 100 {
            return Err(AppError::BadRequest("The name must be 1-100 characters.".into()));
        }
        let lang = form.get("language").and_then(language).ok_or_else(|| AppError::BadRequest("Unknown language.".into()))?.0;
        let description = normalize(form.get("description").unwrap_or("")).trim().to_string();
        if description.chars().count() > 2000 {
            return Err(AppError::BadRequest("The description is at most 2000 characters.".into()));
        }
        let org = match form.get("scope").unwrap_or("") {
            "global" => None,
            v => {
                let id: Uuid = v.parse().map_err(|_| AppError::NotFound)?;
                let (all, orgs) = p.scope();
                if !(all || orgs.contains(&id)) {
                    return Err(AppError::NotFound);
                }
                Some(id)
            }
        };
        let mut tx = state.db.begin().await?;
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO scripts (organization_id, name, language, description, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(org)
        .bind(&name)
        .bind(lang)
        .bind(&description)
        .bind(p.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                AppError::Conflict("A script with that name exists there already.".into())
            }
            sqlx::Error::Database(d) if d.is_foreign_key_violation() => AppError::NotFound,
            _ => e.into(),
        })?;
        let mut audit = Audit::user(&p, "script.create")
            .target("script", id)
            .detail(json!({ "name": name, "language": lang, "global": org.is_none() }));
        if let Some(o) = org {
            audit = audit.org(o);
        }
        audit.record(&mut *tx).await?;
        tx.commit().await?;
        to(format!("/scripts/{id}?m=script-created"))
    })
    .await
}

async fn editor(
    state: &Shared,
    p: &Principal,
    s: &ScriptRow,
    flash: Option<Flash>,
    draft: Option<ScriptDraft>,
) -> AppResult<String> {
    let latest = revision(state, s.id, None).await?;
    let (found, missing) = match &latest {
        Some(r) => problems(state, p, r).await?,
        None => (vec![], vec![]),
    };
    let draft = draft.unwrap_or_else(|| match &latest {
        Some(r) => ScriptDraft {
            base: r.number,
            source: r.source.clone(),
            parameters: r.parameters.clone(),
            risk_class: r.risk_class.clone(),
            note: String::new(),
        },
        None => ScriptDraft {
            base: 0,
            source: String::new(),
            parameters: String::new(),
            risk_class: "C0".into(),
            note: String::new(),
        },
    });
    let history: Vec<(i32, String, String, String, OffsetDateTime, Vec<u8>)> = sqlx::query_as(
        "SELECT r.number, r.risk_class, r.note, u.email, r.created_at, r.content_hash
           FROM script_revisions r JOIN users u ON u.id = r.author WHERE r.script_id = $1 ORDER BY r.number DESC LIMIT 200",
    )
    .bind(s.id)
    .fetch_all(&state.db)
    .await?;
    let history = history
        .into_iter()
        .map(
            |(number, risk_class, note, author, created_at, hash)| RevisionSummary {
                number,
                risk_class,
                note,
                author,
                created_at,
                hash_prefix: hex::encode(&hash[..6]),
            },
        )
        .collect();
    Ok(flyw8t_web::script_page(
        &ctx(p, flash),
        script_view(s),
        latest.as_ref().map(revision_view),
        found,
        missing,
        history,
        draft,
        can_edit(p),
    ))
}

fn with_csp(mut resp: Response) -> Response {
    resp.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(EDITOR_CSP),
    );
    resp
}

pub async fn script_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    Query(m): Query<MsgQuery>,
) -> Response {
    with_csp(
        page(&p, async {
            let s = load(&state, &p, id).await?;
            html(editor(&state, &p, &s, flash(m.m.as_deref()), None).await?)
        })
        .await,
    )
}

/// Save a new revision. The text the person typed is never lost: a problem that stops the save shows the editor again
/// with their text in it.
pub async fn save(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    with_csp(
        page(&p, async {
            let form = Form::parse(&body);
            check_csrf(&p, &form)?;
            p.require(Permission::EditScripts)?;
            let s = load(&state, &p, id).await?;
            let draft = ScriptDraft {
                base: form.get("base").and_then(|b| b.parse().ok()).unwrap_or(-1),
                source: form.get("source").unwrap_or("").to_string(),
                parameters: form.get("parameters").unwrap_or("").to_string(),
                risk_class: form.get("risk_class").unwrap_or("").to_string(),
                note: form.get("note").unwrap_or("").trim().to_string(),
            };
            let refuse = |status: StatusCode, msg: String, draft: ScriptDraft| {
                let (state, p, s) = (&state, &p, &s);
                async move {
                    let page = editor(state, p, s, Some(Flash { ok: false, message: msg }), Some(draft)).await?;
                    Ok::<Response, AppError>((status, axum::response::Html(page)).into_response())
                }
            };
            if !RISK_CLASSES.contains(&draft.risk_class.as_str()) {
                return refuse(StatusCode::UNPROCESSABLE_ENTITY, "Choose a risk class.".into(), draft).await;
            }
            if draft.note.chars().count() > 500 {
                return refuse(StatusCode::UNPROCESSABLE_ENTITY, "The note is at most 500 characters.".into(), draft).await;
            }
            let source = match normalize_source(&draft.source) {
                Ok(v) => v,
                Err(e) => return refuse(StatusCode::UNPROCESSABLE_ENTITY, e, draft).await,
            };
            let parameters = match normalize_parameters(&draft.parameters) {
                Ok(v) => v,
                Err(e) => return refuse(StatusCode::UNPROCESSABLE_ENTITY, e, draft).await,
            };
            let hash = content_hash(s.id, &s.language, &draft.risk_class, &parameters, &source);
            // Checked before taking any lock: a parser can take seconds.
            let check = script_check::check(state.config.script_checks, &s.language, &source).await;
            let mut tx = state.db.begin().await?;
            // One save at a time per script, so revision numbers and the "changed meanwhile" check are exact.
            sqlx::query("SELECT 1 FROM scripts WHERE id = $1 FOR UPDATE").bind(s.id).execute(&mut *tx).await?;
            let latest: Option<(i32, Vec<u8>, String)> = sqlx::query_as(
                "SELECT r.number, r.content_hash, u.email FROM script_revisions r JOIN users u ON u.id = r.author
                  WHERE r.script_id = $1 ORDER BY r.number DESC LIMIT 1",
            )
            .bind(s.id)
            .fetch_optional(&mut *tx)
            .await?;
            let current = latest.as_ref().map_or(0, |l| l.0);
            if current != draft.base {
                drop(tx);
                let by = latest.map(|l| l.2).unwrap_or_default();
                let msg = format!(
                    "Not saved: {by} saved revision {current} while you were editing. Your text is below; compare it with revision {current} before saving again."
                );
                let draft = ScriptDraft { base: current, ..draft };
                return refuse(StatusCode::CONFLICT, msg, draft).await;
            }
            if latest.as_ref().is_some_and(|l| l.1 == hash) {
                return to(format!("/scripts/{id}?m=script-unchanged"));
            }
            let number = current + 1;
            sqlx::query(
                "INSERT INTO script_revisions (script_id, number, source, risk_class, parameters, content_hash, syntax_check, note, author)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(s.id)
            .bind(number)
            .bind(&source)
            .bind(&draft.risk_class)
            .bind(&parameters)
            .bind(hash.as_slice())
            .bind(sqlx::types::Json(&check))
            .bind(&draft.note)
            .bind(p.user_id)
            .execute(&mut *tx)
            .await?;
            let mut audit = Audit::user(&p, "script.revise").target("script", s.id).detail(json!({
                "number": number,
                "sha256": hex::encode(hash),
                "risk_class": draft.risk_class,
                "checked_by": check.checker,
                "syntax_problems": check.problems.len(),
            }));
            if let Some(o) = s.organization_id {
                audit = audit.org(o);
            }
            audit.record(&mut *tx).await?;
            tx.commit().await?;
            to(format!("/scripts/{id}?m=script-saved"))
        })
        .await,
    )
}

pub async fn revision_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path((id, number)): Path<(Uuid, i32)>,
) -> Response {
    page(&p, async {
        let s = load(&state, &p, id).await?;
        let r = revision(&state, s.id, Some(number))
            .await?
            .ok_or(AppError::NotFound)?;
        let (found, missing) = problems(&state, &p, &r).await?;
        let previous = if number > 1 {
            revision(&state, s.id, Some(number - 1)).await?
        } else {
            None
        };
        let changes = previous.as_ref().map(|prev| RevisionChanges {
            source: diff(&prev.source, &r.source),
            parameters: diff(&prev.parameters, &r.parameters),
            risk_from: (prev.risk_class != r.risk_class).then(|| prev.risk_class.clone()),
        });
        html(flyw8t_web::script_revision_page(
            &ctx(&p, None),
            script_view(&s),
            revision_view(&r),
            found,
            missing,
            changes,
        ))
    })
    .await
}

/// A revision's source as a file, to edit elsewhere and paste or load back.
pub async fn download(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path((id, number)): Path<(Uuid, i32)>,
) -> Response {
    page(&p, async {
        let s = load(&state, &p, id).await?;
        let r = revision(&state, s.id, Some(number))
            .await?
            .ok_or(AppError::NotFound)?;
        let ext = language(&s.language).map_or("txt", |l| l.2);
        let stem: String = s
            .name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let disposition = format!("attachment; filename=\"{stem}-r{number}.{ext}\"");
        Ok((
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                ),
                (
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_str(&disposition).map_err(|_| AppError::NotFound)?,
                ),
            ],
            r.source,
        )
            .into_response())
    })
    .await
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
        // Moving text from one part to the next is a different revision.
        assert_ne!(
            content_hash(id, "bash", "C0", "x", "y"),
            content_hash(id, "bash", "C0", "", "xy")
        );
    }

    #[test]
    fn parameters_take_fields_constants_or_questions() {
        let (p, problems) = parse_parameters(
            "# comment\nShare = {{ org.backup_share }}\nTag={{device.asset_tag}}\nRetries = \"3\"\nWhy = ask \"Reason?\"\nOk = ask\n",
        );
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(p.len(), 5);
        assert_eq!(
            p[0].source,
            ParamSource::Field {
                level: "org".into(),
                key: "backup_share".into()
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
    }

    #[test]
    fn bad_parameters_are_named_by_line() {
        let (p, problems) = parse_parameters(
            "A = {{tenant.x}}\n9b = ask\nC = bare\nD\nE = ask\ne = ask\nF = \"unterminated\n",
        );
        assert_eq!(p.len(), 1, "only E survives");
        let lines: Vec<Option<u32>> = problems.iter().map(|x| x.line).collect();
        assert_eq!(
            lines,
            vec![Some(1), Some(2), Some(3), Some(4), Some(6), Some(7)]
        );
        assert!(problems[4].message.contains("twice"));
    }

    #[test]
    fn references_must_name_a_field_that_can_have_a_value_there() {
        let (params, _) = parse_parameters(
            "A = {{org.share}}\nB = {{global.share}}\nC = {{device.gone}}\nD = {{device.old}}\nE = {{global.tag}}\nF = {{site.share}}\nG = {{global.dflt}}\n",
        );
        let org = vec!["organization".to_string()];
        let dev = vec!["device".to_string()];
        let fields = [
            FieldInfo {
                key: "share",
                scopes: &org,
                has_default: false,
                archived: false,
            },
            FieldInfo {
                key: "old",
                scopes: &dev,
                has_default: false,
                archived: true,
            },
            FieldInfo {
                key: "tag",
                scopes: &dev,
                has_default: false,
                archived: false,
            },
            FieldInfo {
                key: "dflt",
                scopes: &dev,
                has_default: true,
                archived: false,
            },
        ];
        let lines: Vec<Option<u32>> = check_references(&params, &fields)
            .iter()
            .map(|x| x.line)
            .collect();
        assert_eq!(lines, vec![Some(2), Some(3), Some(4), Some(5), Some(6)]);
    }

    #[test]
    fn placeholders_in_the_source_are_flagged() {
        let p = placeholders_in_source("echo hi\necho {{ org.share }}\nx = {{notafield}}\n");
        assert_eq!(p.iter().map(|x| x.line).collect::<Vec<_>>(), vec![Some(2)]);
    }

    fn render(rows: &[DiffRow]) -> Vec<String> {
        rows.iter()
            .map(|r| match r {
                DiffRow::Same { text, .. } => format!(" {text}"),
                DiffRow::Removed { text, .. } => format!("-{text}"),
                DiffRow::Added { text, .. } => format!("+{text}"),
                DiffRow::Folded(n) => format!("~{n}"),
            })
            .collect()
    }

    #[test]
    fn diffs_show_changes_with_context_and_fold_the_rest() {
        let old: String = (1..=20).map(|i| format!("l{i}\n")).collect();
        let new = old.replace("l10\n", "ten\n").replace("l20\n", "");
        let rows = diff(&old, &new).unwrap();
        assert_eq!(
            render(&rows),
            [
                "~6", " l7", " l8", " l9", "-l10", "+ten", " l11", " l12", " l13", "~3", " l17",
                " l18", " l19", "-l20"
            ]
        );
        // Line numbers count on both sides.
        assert!(rows.contains(&DiffRow::Same {
            old: 11,
            new: 11,
            text: "l11".into()
        }));
        assert!(rows.contains(&DiffRow::Added {
            new: 10,
            text: "ten".into()
        }));
        assert_eq!(render(&diff("a\nb\n", "a\nb\n").unwrap()), ["~2"]);
        assert_eq!(render(&diff("", "x\n").unwrap()), ["+x"]);
    }

    #[test]
    fn diffs_are_minimal_where_lines_move() {
        let rows = diff("a\nb\nc\nd\n", "b\nc\nd\na\n").unwrap();
        assert_eq!(render(&rows), ["-a", " b", " c", " d", "+a"]);
    }

    #[test]
    fn huge_rewrites_are_declined_not_computed() {
        let old: String = (0..2000).map(|i| format!("a{i}\n")).collect();
        let new: String = (0..2000).map(|i| format!("b{i}\n")).collect();
        assert!(diff(&old, &new).is_none());
        let small: String = (0..1000).map(|i| format!("b{i}\n")).collect();
        assert!(diff(&old[..old.len() / 2], &small).is_some());
    }
}
