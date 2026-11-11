//! Script trust on the server (ADR-0015 build step 3): it stores the trust chain and revision approvals and hands
//! them out. It verifies each upload as an agent would, so a bad one is refused at once, but nothing an agent or
//! `flyw8t-sign` does depends on these checks: they verify everything again.

use crate::audit::Audit;
use crate::auth::{Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::web::{check_csrf, ctx, flash, html, page, to, Form, MsgQuery};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use flyw8t_domain::Permission;
use flyw8t_protocol::script::Revision;
use flyw8t_protocol::trust::{self, Hash, RiskClass, SignedApproval, SignedList, Verified};
use flyw8t_web::model::{ApprovalRow, Flash, SignerRow, TrustView};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Versions after `after` (all of them for `None`), in order.
pub async fn chain_after(db: &PgPool, after: Option<u64>) -> anyhow::Result<Vec<SignedList>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT body FROM trust_versions WHERE version > $1 ORDER BY version")
            .bind(after.unwrap_or(0) as i64)
            .fetch_all(db)
            .await?;
    rows.into_iter()
        .map(|(b,)| serde_json::from_str(&b).map_err(Into::into))
        .collect()
}

/// The chain as stored, verified from its own first version. `None` before genesis. The server's fingerprint is
/// only the hash of the first version it was given: agents pin the operator's own copy.
pub async fn head(db: &PgPool) -> anyhow::Result<Option<(Hash, Verified)>> {
    let chain = chain_after(db, None).await?;
    let Some(first) = chain.first() else {
        return Ok(None);
    };
    let fp = first.list.hash()?;
    Ok(Some((fp, trust::verify_chain(&fp, &chain)?)))
}

fn require_admin(p: &Principal) -> AppResult<()> {
    p.require(Permission::ManageUsers)
}

fn short(h: &Hash) -> String {
    h.to_string()
}

pub async fn trust_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        require_admin(&p)?;
        let head = head(&state.db).await?;
        let (rp, origin) = flyw8t_protocol::webauthn::origin_and_rp_id(&state.config.public_url)
            .map(|(o, r)| (r, o))
            .unwrap_or_default();
        let passkeys: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(p.user_id)
        .fetch_all(&state.db)
        .await?;
        let view = head.map(|(fp, v)| TrustView {
            fingerprint: short(&fp),
            deployment: v.list.deployment_id.to_string(),
            version: v.list.version,
            head: short(&v.hash),
            rp_id: v.list.rp_id.clone(),
            origins: v.list.origins.clone(),
            threshold: v.list.threshold,
            signers: v
                .list
                .signers
                .iter()
                .map(|s| SignerRow {
                    person: s.person_name.clone(),
                    key_id: short(&s.key_id()),
                    kind: format!("{:?}", s.kind).to_lowercase(),
                    role: format!("{:?}", s.role),
                    may_approve: format!("{:?}", s.may_approve),
                })
                .collect(),
            removed: v.list.removed_keys.iter().map(short).collect(),
            revoked: v.list.revoked_revisions.iter().map(short).collect(),
        });
        html(flyw8t_web::trust_page(
            &ctx(&p, flash(m.m.as_deref())),
            view,
            rp,
            origin,
            passkeys,
        ))
    })
    .await
}

/// The whole chain, for `flyw8t-sign trust import` / `update`.
pub async fn chain_json(State(state): State<Shared>, WebUser(p): WebUser) -> Response {
    page(&p, async {
        require_admin(&p)?;
        let chain = chain_after(&state.db, None).await?;
        Ok((
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::to_string_pretty(&chain).map_err(anyhow::Error::from)?,
        )
            .into_response())
    })
    .await
}

/// Upload a signed version: the first one, or the next.
pub async fn upload_version(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    body: Bytes,
) -> Response {
    let form = Form::parse(&body);
    page(&p, async {
        require_admin(&p)?;
        p.require_sudo("/admin/trust")?;
        check_csrf(&p, &form)?;
        let text = form.get("version").unwrap_or("").trim().to_string();
        let back = |code: &str| to(format!("/admin/trust?m={code}"));
        let Ok(signed) = serde_json::from_str::<SignedList>(&text) else {
            return back("trust-bad-json");
        };
        let verified = match head(&state.db).await? {
            None => trust::verify_genesis(&signed, &signed.list.hash().map_err(anyhow::Error::from)?),
            Some((_, held)) => trust::verify_next(&held, &signed),
        };
        let v = match verified {
            Ok(v) => v,
            Err(e) => {
                Audit::user(&p, "trust.version.upload")
                    .denied()
                    .detail(json!({ "reason": e.to_string() }))
                    .record(&state.db)
                    .await?;
                return back("trust-refused");
            }
        };
        let inserted = sqlx::query(
            "INSERT INTO trust_versions (version, deployment_id, hash, body, uploaded_by) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING",
        )
        .bind(v.list.version as i64)
        .bind(v.list.deployment_id)
        .bind(v.hash.0.to_vec())
        .bind(&text)
        .bind(p.user_id)
        .execute(&state.db)
        .await?;
        if inserted.rows_affected() == 0 {
            return back("trust-refused");
        }
        Audit::user(&p, "trust.version.upload")
            .detail(json!({ "version": v.list.version, "hash": v.hash.to_string() }))
            .record(&state.db)
            .await?;
        back("trust-stored")
    })
    .await
}

/// One of the signed-in user's passkeys as a trust-list signer entry, for `flyw8t-sign draft-genesis --signer`.
/// It comes from this server, so the operator compares its key id with the one this page shows (ADR-0015 section 3).
pub async fn passkey_signer(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
) -> Response {
    page(&p, async {
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT credential_id, public_key FROM webauthn_credentials WHERE id = $1 AND user_id = $2",
        )
        .bind(id)
        .bind(p.user_id)
        .fetch_optional(&state.db)
        .await?;
        let (cred, pk) = row.ok_or(AppError::NotFound)?;
        let s = trust::Signer {
            kind: trust::SignerKind::Passkey,
            public_key: trust::Bytes(pk),
            credential_id: Some(trust::Bytes(cred)),
            person_id: p.user_id,
            person_name: p.display_name.clone(),
            may_approve: trust::MayApprove::C3,
            scope: trust::Scope::All,
            role: trust::Role::Signer,
        };
        Ok((
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"passkey-signer.json\""),
            ],
            serde_json::to_string_pretty(&s).map_err(anyhow::Error::from)?,
        )
            .into_response())
    })
    .await
}

// ---------------------------------------------------------------------------------------
// Approvals

/// A stored revision as signed statements see it.
pub async fn revision_for(state: &Shared, script: Uuid, number: i32) -> AppResult<Revision> {
    let row: Option<(String, Option<Uuid>, String, String, String)> = sqlx::query_as(
        "SELECT s.language, s.organization_id, r.risk_class, r.parameters, r.source
           FROM script_revisions r JOIN scripts s ON s.id = r.script_id
          WHERE r.script_id = $1 AND r.number = $2",
    )
    .bind(script)
    .bind(number)
    .fetch_optional(&state.db)
    .await?;
    let (language, scope, risk, parameters, source) = row.ok_or(AppError::NotFound)?;
    Ok(Revision {
        script_id: script,
        revision: number as u64,
        language,
        risk: RiskClass::parse(&risk).ok_or(AppError::NotFound)?,
        scope,
        parameters,
        source,
    })
}

/// The approvals of a revision that still verify under the current head.
pub async fn approvals(
    state: &Shared,
    rev: &Revision,
) -> anyhow::Result<(Vec<SignedApproval>, Vec<ApprovalRow>)> {
    let Some((_, head)) = head(&state.db).await? else {
        return Ok((vec![], vec![]));
    };
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT body FROM script_approvals WHERE script_id = $1 AND revision_number = $2 ORDER BY created_at",
    )
    .bind(rev.script_id)
    .bind(rev.revision as i32)
    .fetch_all(&state.db)
    .await?;
    let (mut good, mut view) = (vec![], vec![]);
    for (body,) in rows {
        let Ok(a) = serde_json::from_str::<SignedApproval>(&body) else {
            continue;
        };
        let valid = a.approval.matches(&head.list.deployment_id, rev)
            && !head.list.revoked_revisions.contains(&rev.content_hash())
            && trust::verify_approval(&a, &head.list).is_ok();
        let who = head.list.signer(&a.approval.signer);
        view.push(ApprovalRow {
            person: who
                .map(|s| s.person_name.clone())
                .unwrap_or_else(|| "removed key".into()),
            key_id: a.approval.signer.to_string(),
            valid,
            approved_at: time::OffsetDateTime::from_unix_timestamp(a.approval.approved_at as i64)
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH),
        });
        if valid {
            good.push(a);
        }
    }
    Ok((good, view))
}

/// The request `flyw8t-sign approve` signs from.
pub async fn approval_request(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path((id, number)): Path<(Uuid, i32)>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewScripts)?;
        crate::scripts::visible(&state, &p, id).await?;
        let rev = revision_for(&state, id, number).await?;
        let (_, head) = head(&state.db).await?.ok_or(AppError::NotFound)?;
        let body = json!({ "deployment_id": head.list.deployment_id, "revision": rev });
        Ok((
            [
                (header::CONTENT_TYPE, "application/json"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"approval-request.json\"",
                ),
            ],
            serde_json::to_string_pretty(&body).map_err(anyhow::Error::from)?,
        )
            .into_response())
    })
    .await
}

/// Store an approval made with `flyw8t-sign approve`, verified first as an agent would.
pub async fn upload_approval(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path((id, number)): Path<(Uuid, i32)>,
    body: Bytes,
) -> Response {
    let form = Form::parse(&body);
    let back_to = format!("/scripts/{id}/revisions/{number}");
    page(&p, async {
        p.require(Permission::EditScripts)?;
        p.require_sudo(&back_to)?;
        check_csrf(&p, &form)?;
        crate::scripts::visible(&state, &p, id).await?;
        let back = |code: &str| to(format!("{back_to}?m={code}"));
        let rev = revision_for(&state, id, number).await?;
        let Some((_, head)) = head(&state.db).await? else {
            return back("approval-no-trust");
        };
        let text = form.get("approval").unwrap_or("").trim().to_string();
        let Ok(a) = serde_json::from_str::<SignedApproval>(&text) else {
            return back("approval-refused");
        };
        let signer = match trust::verify_approval(&a, &head.list) {
            Ok(s) if a.approval.matches(&head.list.deployment_id, &rev) && s.may_approve.allows(rev.risk) => s,
            _ => return back("approval-refused"),
        };
        sqlx::query(
            "INSERT INTO script_approvals (script_id, revision_number, signer_key_id, body, uploaded_by)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (script_id, revision_number, signer_key_id) DO NOTHING",
        )
        .bind(id)
        .bind(number)
        .bind(a.approval.signer.0.to_vec())
        .bind(&text)
        .bind(p.user_id)
        .execute(&state.db)
        .await?;
        Audit::user(&p, "script.approve")
            .target("script", id)
            .detail(json!({ "revision": number, "signer": signer.key_id().to_string(), "person": signer.person_name }))
            .record(&state.db)
            .await?;
        back("approval-stored")
    })
    .await
}

pub fn flash_for(code: &str) -> Option<Flash> {
    let (ok, text) = match code {
        "trust-stored" => (true, "Stored. Agents receive it on their next connection."),
        "trust-refused" => (false, "Refused: that version does not verify against the chain held here."),
        "trust-bad-json" => (false, "That is not a signed trust-list version."),
        "approval-stored" => (true, "Approval stored."),
        "approval-refused" => (false, "Refused: that approval does not verify for this revision under the current trust list."),
        "approval-no-trust" => (false, "There is no trust list yet: set one up on the Trust page first."),
        _ => return None,
    };
    Some(Flash {
        ok,
        message: text.into(),
    })
}
