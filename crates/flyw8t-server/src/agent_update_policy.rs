//! Administrative update preferences. Policy and its audit event commit together.

use crate::audit::Audit;
use crate::auth::{self, WebUser};
use crate::error::AppError;
use crate::web::{check_csrf, page, to, Form};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::Response;
use flyw8t_domain::Permission;
use serde_json::json;
use uuid::Uuid;

pub(crate) async fn organization(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageOrganizations)?;
        let enabled = match form.all("policy").as_slice() {
            ["enabled"] => true,
            ["paused"] => false,
            _ => {
                return Err(AppError::BadRequest(
                    "Choose an organization update policy.".into(),
                ))
            }
        };
        let (global, orgs) = p.scope();
        let mut tx = state.db.begin().await?;
        auth::recheck_actor(&mut tx, &p, Some(id), false).await?;
        let old: bool = sqlx::query_scalar(
            "SELECT automatic_agent_updates FROM organizations
             WHERE id = $1 AND ($2 OR id = ANY($3)) FOR UPDATE",
        )
        .bind(id)
        .bind(global)
        .bind(orgs)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound)?;
        if old != enabled {
            sqlx::query("UPDATE organizations SET automatic_agent_updates = $2 WHERE id = $1")
                .bind(id)
                .bind(enabled)
                .execute(&mut *tx)
                .await?;
            Audit::user(&p, "organization.agent_update_policy")
                .org(id)
                .target("organization", id)
                .detail(json!({ "from_enabled": old, "to_enabled": enabled }))
                .record(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        to(format!(
            "/organizations/{id}?m=agent-update-policy-saved#agent-update-policy"
        ))
    })
    .await
}

pub(crate) async fn device(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageOrganizations)?;
        let opted_out = match form.all("policy").as_slice() {
            ["opt-out"] => true,
            ["inherit"] => false,
            _ => {
                return Err(AppError::BadRequest(
                    "Choose a device update policy.".into(),
                ))
            }
        };
        let (global, orgs) = p.scope();
        let mut tx = state.db.begin().await?;
        // ManageOrganizations grants global administration. Recheck the live session before taking the device lock.
        auth::recheck_actor(&mut tx, &p, None, false).await?;
        let (org, old): (Uuid, bool) = sqlx::query_as(
            "SELECT organization_id, agent_updates_opt_out FROM devices
             WHERE id = $1 AND ($2 OR organization_id = ANY($3)) AND retired_at IS NULL FOR UPDATE",
        )
        .bind(id)
        .bind(global)
        .bind(orgs)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound)?;
        if old != opted_out {
            sqlx::query("UPDATE devices SET agent_updates_opt_out = $2 WHERE id = $1")
                .bind(id)
                .bind(opted_out)
                .execute(&mut *tx)
                .await?;
            Audit::user(&p, "device.agent_update_policy")
                .org(org)
                .target("device", id)
                .detail(json!({ "from_opted_out": old, "to_opted_out": opted_out }))
                .record(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        to(format!(
            "/devices/{id}?m=agent-update-policy-saved#agent-update-policy"
        ))
    })
    .await
}
