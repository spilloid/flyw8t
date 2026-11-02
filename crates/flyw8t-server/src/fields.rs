//! Custom fields (ADR-0014 step 1): values set globally, per organization or per device, resolved device →
//! organization → global → default. Every change is a new row, so the history of a value is the rows before it.
//!
//! Definitions and global values are for administrators (`ManageFields`). Organization and device values are for
//! administrators, and for technicians (`EditFieldValues`) on fields that allow it, in their own organizations. Secret
//! values are encrypted at rest with the server's field key and never shown again; nothing here runs anything.

use crate::audit::Audit;
use crate::auth::{Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::web::{check_csrf, ctx, flash, html, page, to, Form, MsgQuery};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::response::Response;
use flyw8t_domain::Permission;
use flyw8t_web::model::{
    FieldDefView, FieldHistoryRow, FieldValueView, MissingRequired, ResolvedField,
};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

pub const KINDS: &[&str] = &["text", "number", "boolean", "choice", "secret"];
pub const SCOPES: &[&str] = &["global", "organization", "device"];
const MAX_VALUE: usize = 1000;
const MASK: &str = "••••••";

// ---------------------------------------------------------------------------------------
// Secrets at rest

/// Encrypt a secret value: a fresh random nonce, then AES-256-GCM. Stored as nonce || ciphertext.
pub fn seal(key: &[u8; 32], plaintext: &str) -> AppResult<Vec<u8>> {
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow::anyhow!("field key"))?,
    );
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("random"))?;
    let mut buf = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
        .map_err(|_| anyhow::anyhow!("seal"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Decrypt a sealed value (for running scripts later, and for tests). `None` if the key is wrong or the data altered.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Option<String> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let (nonce, ct) = sealed.split_at_checked(NONCE_LEN)?;
    let mut buf = ct.to_vec();
    let plain = key
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).ok()?,
            Aad::empty(),
            &mut buf,
        )
        .ok()?;
    String::from_utf8(plain.to_vec()).ok()
}

// ---------------------------------------------------------------------------------------
// Definitions

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FieldDef {
    pub id: Uuid,
    pub key: String,
    pub label: String,
    pub kind: String,
    pub choices: Vec<String>,
    pub scopes: Vec<String>,
    pub required_at: Option<String>,
    pub default_value: Option<String>,
    pub technician_can_edit: bool,
    pub archived_at: Option<OffsetDateTime>,
}

impl FieldDef {
    fn allows(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// The value as it would be stored, or why it cannot be. Empty means "clear".
    fn check_value(&self, raw: &str) -> AppResult<Option<String>> {
        let v = raw.trim();
        if v.is_empty() {
            return Ok(None);
        }
        if v.chars().count() > MAX_VALUE || v.contains('\0') {
            return Err(AppError::BadRequest(format!(
                "A value must be at most {MAX_VALUE} characters."
            )));
        }
        let ok = match self.kind.as_str() {
            "number" => v.parse::<f64>().is_ok_and(f64::is_finite),
            "boolean" => v == "true" || v == "false",
            "choice" => self.choices.iter().any(|c| c == v),
            _ => true,
        };
        if !ok {
            return Err(AppError::BadRequest(match self.kind.as_str() {
                "number" => "That is not a number.".into(),
                "boolean" => "Choose yes or no.".into(),
                _ => "Choose one of the listed values.".into(),
            }));
        }
        Ok(Some(v.to_string()))
    }
}

const DEF_COLUMNS: &str =
    "id, key, label, kind, choices, scopes, required_at, default_value, technician_can_edit, archived_at";

pub async fn definitions(state: &Shared, archived: bool) -> sqlx::Result<Vec<FieldDef>> {
    sqlx::query_as(&format!(
        "SELECT {DEF_COLUMNS} FROM field_definitions WHERE ($1 OR archived_at IS NULL) ORDER BY lower(label), key"
    ))
    .bind(archived)
    .fetch_all(&state.db)
    .await
}

async fn definition(state: &Shared, id: Uuid) -> AppResult<FieldDef> {
    sqlx::query_as(&format!(
        "SELECT {DEF_COLUMNS} FROM field_definitions WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)
}

// ---------------------------------------------------------------------------------------
// Values and resolution

/// The latest row for a (field, scope, target): what is set there now (`None` value and secret = cleared).
#[derive(Debug, Clone, sqlx::FromRow)]
struct Latest {
    field_id: Uuid,
    // (One organization and one device are queried at a time, so the scope alone tells the rows apart.)
    scope: String,
    value: Option<String>,
    has_secret: bool,
    set_by: String,
    set_at: OffsetDateTime,
}

impl Latest {
    fn view(&self) -> Option<FieldValueView> {
        let display = if self.has_secret {
            MASK.to_string()
        } else {
            self.value.clone()?
        };
        Some(FieldValueView {
            display,
            secret: self.has_secret,
            set_by: self.set_by.clone(),
            set_at: self.set_at,
        })
    }
}

/// Current rows for the global scope, one organization, and one device (any of them optional).
async fn latest(
    state: &Shared,
    org: Option<Uuid>,
    device: Option<Uuid>,
) -> sqlx::Result<Vec<Latest>> {
    sqlx::query_as(
        "SELECT DISTINCT ON (v.field_id, v.scope, v.organization_id, v.device_id)
                v.field_id, v.scope, v.organization_id, v.device_id, v.value, v.secret IS NOT NULL AS has_secret,
                u.email AS set_by, v.set_at
           FROM field_values v JOIN users u ON u.id = v.set_by
          WHERE v.scope = 'global'
             OR (v.scope = 'organization' AND v.organization_id = $1)
             OR (v.scope = 'device' AND v.device_id = $2)
          ORDER BY v.field_id, v.scope, v.organization_id, v.device_id, v.set_at DESC, v.id DESC",
    )
    .bind(org)
    .bind(device)
    .fetch_all(&state.db)
    .await
}

/// May this person set values of this field at this level?
pub fn can_edit(p: &Principal, def: &FieldDef, scope: &str) -> bool {
    if def.archived_at.is_some() || !def.allows(scope) {
        return false;
    }
    if p.can(Permission::ManageFields) {
        return true;
    }
    scope != "global" && def.technician_can_edit && p.can(Permission::EditFieldValues)
}

/// Every active field as it applies to an organization (`device` = None) or a device in it.
pub async fn resolve(
    state: &Shared,
    p: &Principal,
    org: Uuid,
    device: Option<Uuid>,
) -> sqlx::Result<Vec<ResolvedField>> {
    let defs = definitions(state, false).await?;
    let rows = latest(state, Some(org), device).await?;
    let find = |id: Uuid, scope: &str| {
        rows.iter()
            .find(|r| r.field_id == id && r.scope == scope)
            .and_then(Latest::view)
    };
    let level = if device.is_some() {
        "device"
    } else {
        "organization"
    };
    Ok(defs
        .into_iter()
        .map(|d| {
            let dev = device.and(find(d.id, "device"));
            let org_v = find(d.id, "organization");
            let glob = find(d.id, "global");
            let default = d.default_value.clone().map(|v| FieldValueView {
                display: v,
                secret: false,
                set_by: "default".into(),
                set_at: OffsetDateTime::UNIX_EPOCH,
            });
            let (value, source) = match (dev.clone(), org_v.clone(), glob, default) {
                (Some(v), ..) => (Some(v), "device"),
                (None, Some(v), ..) => (Some(v), "organization"),
                (None, None, Some(v), _) => (Some(v), "global"),
                (None, None, None, Some(v)) => (Some(v), "default"),
                _ => (None, "unset"),
            };
            let own = if device.is_some() { dev } else { org_v };
            let missing = match d.required_at.as_deref() {
                Some("organization") if level == "organization" => own.is_none(),
                Some("device") => value.is_none(),
                _ => false,
            };
            ResolvedField {
                id: d.id,
                settable_here: d.allows(level),
                can_edit: can_edit(p, &d, level),
                key: d.key,
                label: d.label,
                kind: d.kind,
                choices: d.choices,
                value,
                source,
                own,
                missing,
            }
        })
        .collect())
}

/// Required fields and who lacks them, within the viewer's organizations.
pub async fn missing_required(state: &Shared, p: &Principal) -> sqlx::Result<Vec<MissingRequired>> {
    let defs: Vec<FieldDef> = definitions(state, false)
        .await?
        .into_iter()
        .filter(|d| d.required_at.is_some())
        .collect();
    if defs.is_empty() {
        return Ok(vec![]);
    }
    let (all, orgs) = p.scope();
    let org_rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM organizations WHERE ($1 OR id = ANY($2)) ORDER BY lower(name)",
    )
    .bind(all)
    .bind(&orgs)
    .fetch_all(&state.db)
    .await?;
    let device_rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT id, organization_id, coalesce(display_name, hostname) FROM devices
          WHERE retired_at IS NULL AND ($1 OR organization_id = ANY($2)) ORDER BY lower(coalesce(display_name, hostname))",
    )
    .bind(all)
    .bind(&orgs)
    .fetch_all(&state.db)
    .await?;
    // Every current non-empty value, by (field, scope, target).
    let set: Vec<(Uuid, String, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT field_id, scope, organization_id, device_id FROM (
             SELECT DISTINCT ON (field_id, scope, organization_id, device_id)
                    field_id, scope, organization_id, device_id, value IS NOT NULL OR secret IS NOT NULL AS present
               FROM field_values ORDER BY field_id, scope, organization_id, device_id, set_at DESC, id DESC) latest
          WHERE present",
    )
    .fetch_all(&state.db)
    .await?;
    let has = |f: Uuid, scope: &str, org: Option<Uuid>, dev: Option<Uuid>| {
        set.iter()
            .any(|(id, s, o, d)| *id == f && s == scope && *o == org && *d == dev)
    };
    let mut out = Vec::new();
    for d in defs {
        let (level, targets): (&'static str, Vec<(Uuid, String)>) = match d.required_at.as_deref() {
            Some("organization") => (
                "organization",
                org_rows
                    .iter()
                    .filter(|(o, _)| !has(d.id, "organization", Some(*o), None))
                    .cloned()
                    .collect(),
            ),
            _ => {
                let inherited = d.default_value.is_some() || has(d.id, "global", None, None);
                let targets = if inherited {
                    vec![]
                } else {
                    device_rows
                        .iter()
                        .filter(|(dev, org, _)| {
                            !has(d.id, "device", None, Some(*dev))
                                && !has(d.id, "organization", Some(*org), None)
                        })
                        .map(|(dev, _, name)| (*dev, name.clone()))
                        .collect()
                };
                ("device", targets)
            }
        };
        if !targets.is_empty() {
            out.push(MissingRequired {
                key: d.key,
                label: d.label,
                level,
                total: targets.len(),
                targets: targets.into_iter().take(50).collect(),
            });
        }
    }
    Ok(out)
}

fn def_view(d: &FieldDef, global: Option<FieldValueView>) -> FieldDefView {
    FieldDefView {
        id: d.id,
        key: d.key.clone(),
        label: d.label.clone(),
        kind: d.kind.clone(),
        choices: d.choices.clone(),
        scopes: d.scopes.clone(),
        required_at: d.required_at.clone(),
        default_value: d.default_value.clone(),
        technician_can_edit: d.technician_can_edit,
        archived: d.archived_at.is_some(),
        global,
    }
}

// ---------------------------------------------------------------------------------------
// Handlers

pub async fn admin_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        p.require(Permission::ManageFields)?;
        let defs = definitions(&state, true).await?;
        let globals = latest(&state, None, None).await?;
        let views = defs
            .iter()
            .map(|d| {
                let g = globals
                    .iter()
                    .find(|r| r.field_id == d.id && r.scope == "global")
                    .and_then(Latest::view);
                def_view(d, g)
            })
            .collect();
        let missing = missing_required(&state, &p).await?;
        html(flyw8t_web::fields_page(
            &ctx(&p, flash(m.m.as_deref())),
            views,
            missing,
            state.config.field_key.is_some(),
        ))
    })
    .await
}

pub async fn define(State(state): State<Shared>, WebUser(p): WebUser, body: Bytes) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageFields)?;
        let key = form.get("key").unwrap_or("").trim().to_lowercase();
        let key_ok = (1..=40).contains(&key.len())
            && key.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !key_ok {
            return Err(AppError::BadRequest(
                "The key must start with a letter and use lowercase letters, digits and _ (at most 40).".into(),
            ));
        }
        let label = form.get("label").unwrap_or("").trim().to_string();
        if label.is_empty() || label.chars().count() > 100 {
            return Err(AppError::BadRequest("The label must be 1-100 characters.".into()));
        }
        let kind = form.get("kind").unwrap_or("");
        if !KINDS.contains(&kind) {
            return Err(AppError::BadRequest("Unknown kind.".into()));
        }
        let mut choices: Vec<String> = form
            .get("choices")
            .unwrap_or("")
            .split(',')
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .collect();
        choices.dedup();
        if kind == "choice" && (choices.is_empty() || choices.len() > 50 || choices.iter().any(|c| c.chars().count() > 100)) {
            return Err(AppError::BadRequest("A choice field needs 1-50 choices, separated by commas.".into()));
        }
        if kind != "choice" {
            choices.clear();
        }
        let scopes: Vec<String> =
            form.all("scope").into_iter().filter(|s| SCOPES.contains(s)).map(str::to_string).collect();
        if scopes.is_empty() {
            return Err(AppError::BadRequest("Choose where values may be set.".into()));
        }
        let required_at = match form.get("required_at").unwrap_or("") {
            "" => None,
            r @ ("organization" | "device") => {
                if !scopes.iter().any(|s| s == r) && !(r == "device" && scopes.iter().any(|s| s == "organization")) {
                    return Err(AppError::BadRequest(
                        "A value cannot be required where it cannot be set.".into(),
                    ));
                }
                Some(r.to_string())
            }
            _ => return Err(AppError::BadRequest("Unknown requirement.".into())),
        };
        let probe = FieldDef {
            id: Uuid::nil(),
            key: key.clone(),
            label: label.clone(),
            kind: kind.to_string(),
            choices: choices.clone(),
            scopes: scopes.clone(),
            required_at: required_at.clone(),
            default_value: None,
            technician_can_edit: false,
            archived_at: None,
        };
        let default_value = match form.get("default_value").unwrap_or("") {
            "" => None,
            _ if kind == "secret" => return Err(AppError::BadRequest("A secret field cannot have a default.".into())),
            v => probe.check_value(v)?,
        };
        let technician_can_edit = form.get("technician_can_edit") == Some("yes");
        let mut tx = state.db.begin().await?;
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO field_definitions (key, label, kind, choices, scopes, required_at, default_value, technician_can_edit, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
        )
        .bind(&key)
        .bind(&label)
        .bind(kind)
        .bind(&choices)
        .bind(&scopes)
        .bind(&required_at)
        .bind(&default_value)
        .bind(technician_can_edit)
        .bind(p.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict("A field with that key exists.".into()),
            _ => e.into(),
        })?;
        Audit::user(&p, "field.define")
            .target("field", id)
            .detail(json!({ "key": key, "kind": kind, "scopes": scopes, "required_at": required_at, "technician_can_edit": technician_can_edit }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        to("/admin/fields?m=field-defined")
    })
    .await
}

pub async fn archive(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require(Permission::ManageFields)?;
        let n = sqlx::query("UPDATE field_definitions SET archived_at = now() WHERE id = $1 AND archived_at IS NULL")
            .bind(id)
            .execute(&state.db)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound);
        }
        Audit::user(&p, "field.archive").target("field", id).record(&state.db).await?;
        to("/admin/fields?m=field-archived")
    })
    .await
}

/// Which level a value is for, checked against the viewer's organizations. Returns (scope, org, device, the organization
/// the change belongs to, where to go back to).
async fn target(
    state: &Shared,
    p: &Principal,
    form: &Form,
) -> AppResult<(
    &'static str,
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    String,
)> {
    let id = |k: &str| form.get(k).and_then(|v| v.parse::<Uuid>().ok());
    let (all, orgs) = p.scope();
    match form.get("scope").unwrap_or("") {
        "global" => Ok(("global", None, None, None, "/admin/fields".into())),
        "organization" => {
            let org = id("target").ok_or(AppError::NotFound)?;
            if !(all || orgs.contains(&org)) {
                return Err(AppError::NotFound);
            }
            let exists: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM organizations WHERE id = $1")
                    .bind(org)
                    .fetch_optional(&state.db)
                    .await?;
            exists.ok_or(AppError::NotFound)?;
            Ok((
                "organization",
                Some(org),
                None,
                Some(org),
                format!("/organizations/{org}"),
            ))
        }
        "device" => {
            let dev = id("target").ok_or(AppError::NotFound)?;
            let row: Option<(Uuid,)> = sqlx::query_as(
                "SELECT organization_id FROM devices WHERE id = $1 AND ($2 OR organization_id = ANY($3))",
            )
            .bind(dev)
            .bind(all)
            .bind(&orgs)
            .fetch_optional(&state.db)
            .await?;
            let (org,) = row.ok_or(AppError::NotFound)?;
            Ok((
                "device",
                None,
                Some(dev),
                Some(org),
                format!("/devices/{dev}"),
            ))
        }
        _ => Err(AppError::BadRequest("Unknown scope.".into())),
    }
}

pub async fn set_value(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        let def = definition(&state, id).await?;
        let (scope, org, device, belongs, back) = target(&state, &p, &form).await?;
        if !can_edit(&p, &def, scope) {
            return Err(AppError::Forbidden);
        }
        let value = def.check_value(form.get("value").unwrap_or(""))?;
        let (plain, secret) = match (def.kind.as_str(), value) {
            ("secret", Some(v)) => {
                let key = state.config.field_key.as_ref().ok_or_else(|| {
                    AppError::Conflict("Secret values need FLYW8T_FIELD_KEY set on the server.".into())
                })?;
                (None, Some(seal(key, &v)?))
            }
            (_, v) => (v, None),
        };
        let cleared = plain.is_none() && secret.is_none();
        let mut tx = state.db.begin().await?;
        sqlx::query(
            "INSERT INTO field_values (field_id, scope, organization_id, device_id, value, secret, set_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(scope)
        .bind(org)
        .bind(device)
        .bind(&plain)
        .bind(&secret)
        .bind(p.user_id)
        .execute(&mut *tx)
        .await?;
        // A secret's value never reaches the audit log; other values do, for the record.
        let shown = if def.kind == "secret" { None } else { plain.clone() };
        let mut audit = Audit::user(&p, "field.set")
            .target("field", id)
            .detail(json!({ "key": def.key, "scope": scope, "organization_id": org, "device_id": device, "value": shown, "cleared": cleared }));
        if let Some(o) = belongs {
            audit = audit.org(o);
        }
        audit.record(&mut *tx).await?;
        tx.commit().await?;
        to(format!("{back}?m=field-saved"))
    })
    .await
}

#[derive(Deserialize)]
pub struct HistoryQs {
    scope: String,
    target: Option<Uuid>,
}

pub async fn history(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    Query(q): Query<HistoryQs>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewDevices)?;
        let def = definition(&state, id).await?;
        let mut form_fields = vec![("scope".to_string(), q.scope.clone())];
        if let Some(t) = q.target {
            form_fields.push(("target".to_string(), t.to_string()));
        }
        let encoded = form_urlencoded::Serializer::new(String::new()).extend_pairs(&form_fields).finish();
        let form = Form::parse(encoded.as_bytes());
        let (scope, org, device, _, back) = target(&state, &p, &form).await?;
        let rows: Vec<(Option<String>, bool, String, OffsetDateTime)> = sqlx::query_as(
            "SELECT v.value, v.secret IS NOT NULL, u.email, v.set_at FROM field_values v JOIN users u ON u.id = v.set_by
              WHERE v.field_id = $1 AND v.scope = $2
                AND v.organization_id IS NOT DISTINCT FROM $3 AND v.device_id IS NOT DISTINCT FROM $4
              ORDER BY v.set_at DESC, v.id DESC LIMIT 200",
        )
        .bind(id)
        .bind(scope)
        .bind(org)
        .bind(device)
        .fetch_all(&state.db)
        .await?;
        let rows = rows
            .into_iter()
            .map(|(value, secret, set_by, set_at)| FieldHistoryRow {
                display: if secret { Some(MASK.into()) } else { value },
                set_by,
                set_at,
            })
            .collect();
        html(flyw8t_web::field_history_page(&ctx(&p, None), &def.label, &def.key, scope, &back, rows))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_values_open_only_with_their_key_and_unaltered() {
        let k = [7u8; 32];
        let s = seal(&k, "hunter2").unwrap();
        assert!(!s.windows(7).any(|w| w == b"hunter2"));
        assert_eq!(open(&k, &s).as_deref(), Some("hunter2"));
        assert_eq!(open(&[8u8; 32], &s), None);
        let mut altered = s.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert_eq!(open(&k, &altered), None);
        assert_ne!(seal(&k, "hunter2").unwrap(), s, "a fresh nonce each time");
    }

    #[test]
    fn values_are_checked_by_kind() {
        let d = |kind: &str, choices: &[&str]| FieldDef {
            id: Uuid::nil(),
            key: "k".into(),
            label: "K".into(),
            kind: kind.into(),
            choices: choices.iter().map(|c| c.to_string()).collect(),
            scopes: vec!["global".into()],
            required_at: None,
            default_value: None,
            technician_can_edit: false,
            archived_at: None,
        };
        assert_eq!(
            d("number", &[]).check_value(" 42.5 ").unwrap().as_deref(),
            Some("42.5")
        );
        assert!(d("number", &[]).check_value("NaN").is_err());
        assert!(d("number", &[]).check_value("lots").is_err());
        assert!(d("boolean", &[]).check_value("yes").is_err());
        assert_eq!(
            d("boolean", &[]).check_value("true").unwrap().as_deref(),
            Some("true")
        );
        assert!(d("choice", &["a", "b"]).check_value("c").is_err());
        assert_eq!(
            d("text", &[]).check_value("   ").unwrap(),
            None,
            "blank clears"
        );
        assert!(d("text", &[]).check_value(&"x".repeat(1001)).is_err());
    }
}
