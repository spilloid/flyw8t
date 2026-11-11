//! Running approved scripts from the console (ADR-0015 build step 4): choose an approved revision, give the asked
//! values, and for C2 and C3 have someone sign the run with `flyw8t-sign authorize` and upload the signature.

use crate::auth::{Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::web::{check_csrf, ctx, flash, html, page, to, Form, MsgQuery};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use flyw8t_domain::Permission;
use flyw8t_protocol::messages::ScriptOffer;
use flyw8t_protocol::script::{parse_parameters, ParamSource};
use flyw8t_protocol::trust::run::{check_approvals, check_values, RunRequest};
use flyw8t_protocol::trust::statement::window_cap;
use flyw8t_protocol::trust::{
    commitment, key_id, verify_authorization, Bytes as B64, Hash, KeyKind, RiskClass,
    SignedAuthorization, TrustList,
};
use flyw8t_web::model::RunOption;
use ring::rand::SecureRandom;
use serde_json::json;
use std::collections::BTreeMap;
use uuid::Uuid;

/// The device's key id: what run signatures name (ADR-0015 section 3).
pub async fn device_key_id(state: &Shared, device: Uuid) -> AppResult<Hash> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT public_key FROM device_credentials WHERE device_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
    )
    .bind(device)
    .fetch_optional(&state.db)
    .await?;
    let (pk,) =
        row.ok_or_else(|| AppError::Conflict("this device has no active credential".into()))?;
    Ok(key_id(KeyKind::Device, &pk))
}

/// What a person signs for this job.
pub async fn run_request(
    state: &Shared,
    offer: &ScriptOffer,
    device: Uuid,
) -> AppResult<RunRequest> {
    Ok(RunRequest {
        deployment_id: offer.deployment_id,
        job_id: offer.job_id,
        revision: offer.revision.clone(),
        approvals: offer.approvals.clone(),
        values: offer.values.clone(),
        salt: offer.salt.clone(),
        devices: vec![device_key_id(state, device).await?],
        timeout_secs: offer.timeout_secs.into(),
    })
}

/// The checks an agent will make of a run signature, made here so a wrong one is refused at once.
pub fn check_authorization(
    head: &TrustList,
    req: &RunRequest,
    a: &SignedAuthorization,
    now: u64,
) -> Result<(), String> {
    let rev = &req.revision;
    let cap = window_cap(rev.risk).ok_or("this class needs no run signature")?;
    let approvers = check_approvals(head, rev, &req.approvals, None).map_err(|e| e.to_string())?;
    let signer = verify_authorization(a, head).map_err(|e| e.to_string())?;
    let auth = &a.authorization;
    if !signer.may_approve.allows(rev.risk) {
        return Err("the signer may not sign runs of this class".into());
    }
    if auth.deployment_id != req.deployment_id
        || auth.job_id != req.job_id
        || auth.devices != req.devices
        || auth.content_hash != rev.content_hash()
        || auth.timeout_secs != req.timeout_secs
    {
        return Err("the signature is for another job, device, revision or timeout".into());
    }
    let values = check_values(rev, &req.values, &BTreeMap::new()).map_err(|e| e.to_string())?;
    let salt: [u8; 32] = req.salt.0.as_slice().try_into().map_err(|_| "bad salt")?;
    let c = commitment(&salt, values.iter().map(|(n, v)| (n.as_str(), v.as_str())))
        .map_err(|e| e.to_string())?;
    if c != auth.parameters {
        return Err("the signature is for other values".into());
    }
    let window = auth
        .expires_at
        .checked_sub(auth.issued_at)
        .ok_or("bad window")?;
    if window > cap || now >= auth.expires_at {
        return Err("the signature has expired, or is valid for too long".into());
    }
    if rev.risk == RiskClass::C2 && approvers.iter().any(|x| x.person_id == signer.person_id) {
        return Err("a C2 run must be signed by someone other than its approver".into());
    }
    if rev.risk == RiskClass::C3 && auth.devices.len() != 1 {
        return Err("a C3 run names exactly one device".into());
    }
    Ok(())
}

async fn device_row(state: &Shared, p: &Principal, device: Uuid) -> AppResult<(Uuid, String)> {
    let (all, orgs) = p.scope();
    sqlx::query_as(
        "SELECT organization_id, hostname FROM devices WHERE id = $1 AND retired_at IS NULL AND ($2 OR organization_id = ANY($3))",
    )
    .bind(device)
    .bind(all)
    .bind(&orgs)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)
}

/// Approved revisions that could run on this device, newest revision of each script first.
async fn options(
    state: &Shared,
    org: Uuid,
) -> anyhow::Result<Vec<(RunOption, flyw8t_protocol::script::Revision)>> {
    let rows: Vec<(Uuid, i32, String)> = sqlx::query_as(
        "SELECT DISTINCT a.script_id, a.revision_number, s.name FROM script_approvals a
           JOIN scripts s ON s.id = a.script_id
          WHERE s.organization_id IS NULL OR s.organization_id = $1
          ORDER BY s.name, a.revision_number DESC",
    )
    .bind(org)
    .fetch_all(&state.db)
    .await?;
    let mut out = vec![];
    for (script, number, name) in rows {
        let rev = match crate::trust::revision_for(state, script, number).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let (valid, _) = crate::trust::approvals(state, &rev).await?;
        if valid.is_empty() {
            continue;
        }
        let (params, problems) = parse_parameters(&rev.parameters);
        let mut blocked =
            (!problems.is_empty()).then(|| "its parameter declarations have problems".to_string());
        if rev.language != "powershell" {
            blocked = Some("agents run PowerShell scripts only in this version".into());
        }
        let mut asks = vec![];
        for p in &params {
            match &p.source {
                ParamSource::Ask { prompt } => asks.push((p.name.clone(), prompt.clone())),
                ParamSource::Constant(_) => {}
                ParamSource::Field { .. } => {
                    blocked = Some(
                        "parameters bound to custom fields are not supported in runs yet".into(),
                    )
                }
            }
        }
        out.push((
            RunOption {
                script_id: script,
                number,
                name,
                risk: rev.risk.as_str().into(),
                asks,
                blocked,
            },
            rev,
        ));
    }
    Ok(out)
}

pub async fn run_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(device): Path<Uuid>,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        p.require(Permission::RunScripts)?;
        let (org, hostname) = device_row(&state, &p, device).await?;
        let key = device_key_id(&state, device)
            .await
            .map(|h| h.to_string())
            .unwrap_or_default();
        let opts = options(&state, org)
            .await?
            .into_iter()
            .map(|(o, _)| o)
            .collect();
        html(flyw8t_web::run_script_page(
            &ctx(&p, flash(m.m.as_deref())),
            device,
            &hostname,
            &key,
            opts,
        ))
    })
    .await
}

/// Start a run of an approved revision on this device.
pub async fn start(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(device): Path<Uuid>,
    body: Bytes,
) -> Response {
    let form = Form::parse(&body);
    page(&p, async {
        check_csrf(&p, &form)?;
        p.require(Permission::RunScripts)?;
        let (org, hostname) = device_row(&state, &p, device).await?;
        let script: Uuid = form.get("script").and_then(|s| s.parse().ok()).ok_or(AppError::BadRequest("no script".into()))?;
        let number: i32 = form.get("number").and_then(|s| s.parse().ok()).ok_or(AppError::BadRequest("no revision".into()))?;
        let timeout: u32 = form.get("timeout").and_then(|s| s.trim().parse().ok()).unwrap_or(300);
        if !(1..=3600).contains(&timeout) {
            return Err(AppError::BadRequest("the timeout is 1 to 3600 seconds".into()));
        }
        let (opt, rev) = options(&state, org)
            .await?
            .into_iter()
            .find(|(o, _)| o.script_id == script && o.number == number)
            .ok_or(AppError::NotFound)?;
        if let Some(why) = opt.blocked {
            return Err(AppError::BadRequest(format!("This revision cannot run here: {why}.")));
        }
        let (params, _) = parse_parameters(&rev.parameters);
        let mut values = BTreeMap::new();
        for prm in &params {
            let v = match &prm.source {
                ParamSource::Constant(c) => c.clone(),
                ParamSource::Ask { .. } => form.get(&format!("v_{}", prm.name)).unwrap_or("").to_string(),
                ParamSource::Field { .. } => return Err(AppError::BadRequest("field parameters are not supported yet".into())),
            };
            values.insert(prm.name.clone(), v);
        }
        check_values(&rev, &values, &BTreeMap::new()).map_err(|e| AppError::BadRequest(e.to_string()))?;
        let (_, head) = crate::trust::head(&state.db).await?.ok_or(AppError::NotFound)?;
        let (approvals, _) = crate::trust::approvals(&state, &rev).await?;
        let mut salt = [0u8; 32];
        ring::rand::SystemRandom::new().fill(&mut salt).map_err(|_| anyhow::anyhow!("no randomness"))?;
        let offer = ScriptOffer {
            job_id: Uuid::new_v4(),
            deployment_id: head.list.deployment_id,
            timeout_secs: timeout,
            revision: rev.clone(),
            approvals,
            authorization: None,
            salt: B64(salt.to_vec()),
            values: values.clone(),
            secrets: BTreeMap::new(),
        };
        let summary = json!({ "script": opt.name, "revision": number, "risk": rev.risk.as_str(), "values": values, "device": hostname });
        let job = crate::jobs::create_script(&state, &p, device, &offer, summary).await?;
        if rev.risk.needs_run_signature() {
            to(format!("/jobs/{job}/authorize"))
        } else {
            to(format!("/jobs/{job}"))
        }
    })
    .await
}

async fn waiting_offer(
    state: &Shared,
    p: &Principal,
    job: Uuid,
) -> AppResult<(ScriptOffer, Uuid, String)> {
    let row: Option<(Uuid, Uuid, Option<String>, String)> = sqlx::query_as(
        "SELECT organization_id, device_id, script_request, state FROM jobs WHERE id = $1",
    )
    .bind(job)
    .fetch_optional(&state.db)
    .await?;
    let (org, device, request, st) = row.ok_or(AppError::NotFound)?;
    if !p.can_see_org(org) {
        return Err(AppError::NotFound);
    }
    let offer: ScriptOffer =
        serde_json::from_str(&request.ok_or(AppError::NotFound)?).map_err(anyhow::Error::from)?;
    Ok((offer, device, st))
}

pub async fn authorize_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(job): Path<Uuid>,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        p.require(Permission::RunScripts)?;
        let (offer, device, st) = waiting_offer(&state, &p, job).await?;
        let key = device_key_id(&state, device).await?;
        let error =
            m.m.as_deref()
                .and_then(|c| c.strip_prefix("refused:"))
                .map(str::to_string);
        html(flyw8t_web::authorize_run_page(
            &ctx(&p, None),
            job,
            offer.revision.risk.as_str(),
            &key.to_string(),
            st == "created",
            error,
        ))
    })
    .await
}

pub async fn run_request_json(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(job): Path<Uuid>,
) -> Response {
    page(&p, async {
        p.require(Permission::RunScripts)?;
        let (offer, device, _) = waiting_offer(&state, &p, job).await?;
        let req = run_request(&state, &offer, device).await?;
        Ok((
            [
                (header::CONTENT_TYPE, "application/json"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"run-request.json\"",
                ),
            ],
            serde_json::to_string_pretty(&req).map_err(anyhow::Error::from)?,
        )
            .into_response())
    })
    .await
}

pub async fn upload_authorization(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(job): Path<Uuid>,
    body: Bytes,
) -> Response {
    let form = Form::parse(&body);
    page(&p, async {
        check_csrf(&p, &form)?;
        let text = form.get("authorization").unwrap_or("").trim().to_string();
        match crate::jobs::authorize_script(&state, &p, job, &text).await? {
            Ok(()) => to(format!("/jobs/{job}")),
            Err(why) => to(format!(
                "/jobs/{job}/authorize?m=refused:{}",
                form_urlencoded::byte_serialize(why.as_bytes()).collect::<String>()
            )),
        }
    })
    .await
}
