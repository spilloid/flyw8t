//! Read-only terminal evidence for the initiating browser or its owner’s API token.

use crate::auth::{ApiUser, Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::Shared;
use axum::extract::{Path, State};
use axum::Json;
use flyw8t_domain::Permission;
use flyw8t_protocol::script::WindowsExecutionAccount;
use flyw8t_protocol::terminal::TerminalEndReason;
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Evidence {
    Starting,
    Attached,
    Detached,
    TerminationPending,
    Ended,
    Rejected,
    TerminationUnconfirmed,
}

#[derive(Serialize)]
pub(crate) struct Status {
    device_id: Uuid,
    session_id: Uuid,
    account: WindowsExecutionAccount,
    state: Evidence,
    #[serde(with = "time::serde::rfc3339")]
    observed_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<TerminalEndReason>,
}

pub(crate) async fn browser_status(
    State(state): State<Shared>,
    WebUser(actor): WebUser,
    Path((device, session)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<Status>> {
    actor.require(Permission::RunControlSessions)?;
    status(&state, &actor, device, session).await.map(Json)
}

pub(crate) async fn api_status(
    State(state): State<Shared>,
    ApiUser(actor): ApiUser,
    Path((device, session)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<Status>> {
    // API tokens cannot exercise RunControlSessions. For this read-only
    // resource require its owner to hold that role permission and a read token.
    if !api_permitted(&actor) {
        return Err(AppError::Forbidden);
    }
    status(&state, &actor, device, session).await.map(Json)
}

pub(crate) fn api_permitted(actor: &Principal) -> bool {
    actor.role.allows(Permission::RunControlSessions) && actor.can(Permission::ViewDevices)
}

async fn status(
    state: &Shared,
    actor: &Principal,
    device: Uuid,
    session: Uuid,
) -> AppResult<Status> {
    actor.require(Permission::ViewDevices)?;
    // The browser must have the exact initiating sign-in. An integration
    // represents the same user and receives lifecycle metadata only. Recheck
    // current credential validity, role, and organization in this observation.
    let (action, at, account, reason): (String, OffsetDateTime, Value, Value) = sqlx::query_as(
        "SELECT a.action, a.at, a.detail->'agent_account', a.detail->'reason'
           FROM audit_events a
           JOIN devices d ON d.id = a.target_id AND d.organization_id = a.organization_id
           JOIN users u ON u.id = a.actor_id
          WHERE d.id = $1 AND a.detail->>'session_id' = $2
            AND a.target_type = 'device' AND a.channel = 'web' AND a.actor_type = 'user'
            AND u.id = $3 AND u.role = $4 AND u.disabled_at IS NULL
            AND ($5 OR EXISTS (SELECT 1 FROM user_organizations m
                               WHERE m.user_id = u.id AND m.organization_id = d.organization_id))
            AND ((a.detail->>'browser_session_id' = $6::text
                  AND EXISTS (SELECT 1 FROM sessions s WHERE s.id = $6::uuid AND s.user_id = u.id
                    AND s.token_hash = $7 AND s.stage = 'full'
                    AND s.revoked_at IS NULL AND s.expires_at > now()))
                 OR EXISTS (SELECT 1 FROM api_tokens t WHERE t.id = $8 AND t.user_id = u.id
                    AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > now())
                    AND 'read' = ANY(t.scopes)))
            AND a.action IN ('device.background_terminal.attachment',
                 'device.background_terminal.started', 'device.background_terminal.detached',
                 'device.background_terminal.reattached', 'device.background_terminal.end_requested',
                 'device.background_terminal.ended', 'device.background_terminal.rejected',
                 'device.background_terminal.end_unconfirmed')
          ORDER BY a.id DESC LIMIT 1",
    )
    .bind(device)
    .bind(session.to_string())
    .bind(actor.user_id)
    .bind(actor.role.as_str())
    .bind(actor.sees_all())
    .bind(actor.session_id)
    .bind(actor.session_token.as_deref())
    .bind(actor.api_token.as_ref().map(|(id, _)| *id))
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let account = serde_json::from_value(account).map_err(|_| AppError::NotFound)?;
    let reason = serde_json::from_value(reason).ok();
    let evidence = match action.as_str() {
        "device.background_terminal.ended" => Evidence::Ended,
        "device.background_terminal.rejected" => Evidence::Rejected,
        "device.background_terminal.end_unconfirmed" => Evidence::TerminationUnconfirmed,
        // Durable attachment evidence alone cannot establish that a process
        // survived a server restart or that any cleanup happened.
        _ if !state
            .terminal_sessions
            .tracks(device, session, actor.user_id) =>
        {
            Evidence::TerminationUnconfirmed
        }
        "device.background_terminal.attachment" => Evidence::Starting,
        "device.background_terminal.started" | "device.background_terminal.reattached" => {
            Evidence::Attached
        }
        "device.background_terminal.detached" => Evidence::Detached,
        "device.background_terminal.end_requested" => Evidence::TerminationPending,
        _ => return Err(AppError::NotFound),
    };
    Ok(Status {
        device_id: device,
        session_id: session,
        account,
        state: evidence,
        observed_at: at,
        reason,
    })
}
