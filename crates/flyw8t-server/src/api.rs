//! JSON API, version 1. Bearer tokens only. This is the surface AnchorDesk integrates with;
//! see `docs/anchordesk-integration.md`.

use crate::auth::ApiUser;
use crate::error::{AppError, AppResult};
use crate::jobs::{self, NewJob};
use crate::queries::{self, JobQuery};
use crate::Shared;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use flyw8t_domain::job::outcome;
use flyw8t_domain::Permission;
use flyw8t_protocol::{Action, CATALOG};
use flyw8t_web::model::{DeviceDetail, DeviceFilter, DeviceRow, JobDetail};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

pub async fn catalog(ApiUser(p): ApiUser) -> AppResult<Json<Value>> {
    p.require(Permission::ViewDevices)?;
    Ok(Json(json!({ "actions": CATALOG })))
}

#[derive(Deserialize, Default)]
pub struct DevicesQs {
    q: Option<String>,
    organization: Option<Uuid>,
}

pub async fn devices(
    State(state): State<Shared>,
    ApiUser(p): ApiUser,
    Query(qs): Query<DevicesQs>,
) -> AppResult<Json<Vec<DeviceRow>>> {
    p.require(Permission::ViewDevices)?;
    let filter = DeviceFilter {
        q: qs.q.unwrap_or_default(),
        organization: qs.organization,
        connection: String::new(),
    };
    Ok(Json(queries::devices(&state, &p, &filter).await?))
}

pub async fn device(
    State(state): State<Shared>,
    ApiUser(p): ApiUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<DeviceDetail>> {
    p.require(Permission::ViewDevices)?;
    queries::device(&state, &p, id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

#[derive(Deserialize)]
pub struct CreateJob {
    /// `{"action": "net.ping", "params": {"target": "10.0.0.1"}}`
    #[serde(flatten)]
    action: Value,
    timeout_secs: Option<u32>,
}

#[derive(Serialize)]
pub struct Created {
    job_id: Uuid,
    url: String,
}

pub async fn create_job(
    State(state): State<Shared>,
    ApiUser(p): ApiUser,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<CreateJob>,
) -> AppResult<(StatusCode, Json<Created>)> {
    let mut action_json = body.action;
    if let Some(o) = action_json.as_object_mut() {
        o.remove("timeout_secs");
    }
    let action: Action = serde_json::from_value(action_json)
        .map_err(|e| AppError::BadRequest(format!("unknown action or bad parameters: {e}")))?;
    // STD-005: unattended creation requires an idempotency key.
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| AppError::BadRequest("Idempotency-Key header is required".into()))?;
    let job_id = jobs::create(
        &state,
        &p,
        NewJob {
            device_id,
            action,
            timeout_secs: body.timeout_secs,
            idempotency_key: Some(key),
        },
    )
    .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(Created {
            job_id,
            url: format!("{}/jobs/{job_id}", state.config.public_url),
        }),
    ))
}

#[derive(Serialize)]
pub struct JobResponse {
    #[serde(flatten)]
    job: JobDetail,
    outcome: flyw8t_domain::Outcome,
}

pub async fn job(
    State(state): State<Shared>,
    ApiUser(p): ApiUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<JobResponse>> {
    p.require(Permission::ViewDevices)?;
    let job = queries::job(&state, &p, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let outcome = outcome(job.row.state, job.row.verification);
    Ok(Json(JobResponse { job, outcome }))
}

pub async fn device_jobs(
    State(state): State<Shared>,
    ApiUser(p): ApiUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Value>> {
    p.require(Permission::ViewDevices)?;
    let rows = queries::jobs(
        &state,
        &p,
        &JobQuery {
            device: Some(id),
            limit: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(Json(json!({ "jobs": rows })))
}

pub async fn cancel_job(
    State(state): State<Shared>,
    ApiUser(p): ApiUser,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    jobs::cancel(&state, &p, id).await?;
    Ok(StatusCode::ACCEPTED)
}
