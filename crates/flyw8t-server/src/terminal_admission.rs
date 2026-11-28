//! Browser-bound admission for background PowerShell. Each confirmation rechecks the endpoint.

use crate::audit::Audit;
use crate::auth::{self, Channel, Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::registry::{BackgroundTerminalObservation, ConsoleCheckError, Registry};
use crate::web::{check_csrf, constant_time_eq, ctx, html, page, windows_observation_target, Form};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use flyw8t_domain::Permission;
use flyw8t_protocol::messages::BackgroundTerminalPolicy;
use flyw8t_protocol::script::WindowsExecutionAccount;
use flyw8t_protocol::terminal::CAP_BACKGROUND_TERMINAL;
use flyw8t_web::{BackgroundTerminalPolicyCheck as Check, BackgroundTerminalStep};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

const TTL: Duration = Duration::from_secs(30);
const MAX_PENDING: usize = 128;

#[derive(Default)]
pub(crate) struct Admissions(Mutex<HashMap<Vec<u8>, Admission>>);

struct Admission {
    user: Uuid,
    session: Uuid,
    cookie_digest: Vec<u8>,
    device: Uuid,
    organization: Uuid,
    connection: Uuid,
    live_terminal: bool,
    policy_check: Uuid,
    expires: Instant,
}

impl Admissions {
    fn issue(&self, operator: &Principal, admission: Admission) -> AppResult<String> {
        if operator.channel != Channel::Web {
            return Err(AppError::Forbidden);
        }
        let now = Instant::now();
        let mut pending = self.0.lock().unwrap();
        pending.retain(|_, grant| grant.expires > now);
        // A fresh confirmation replaces the previous one for this browser and device.
        pending.retain(|_, grant| {
            grant.session != admission.session || grant.device != admission.device
        });
        if pending.len() >= MAX_PENDING {
            return Err(AppError::RateLimited);
        }
        let secret = auth::random_secret(32);
        pending.insert(auth::digest(&secret), admission);
        Ok(secret)
    }

    fn claim(&self, operator: &Principal, device: Uuid, secret: &str) -> Option<Admission> {
        if operator.channel != Channel::Web || secret.len() != 43 {
            return None;
        }
        let digest = auth::digest(secret);
        let mut pending = self.0.lock().unwrap();
        let grant = pending.get(&digest)?;
        if grant.expires <= Instant::now() {
            pending.remove(&digest);
            return None;
        }
        let cookie = operator.session_token.as_deref()?;
        if operator.user_id != grant.user
            || operator.session_id != Some(grant.session)
            || !constant_time_eq(cookie, &grant.cookie_digest)
            || device != grant.device
            || !operator.can_see_org(grant.organization)
        {
            return None;
        }
        pending.remove(&digest)
    }
}

pub(crate) async fn check(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(device): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        authorize(&p, &Form::parse(&body))?;
        observe(&state, &p, device, None, false).await
    })
    .await
}

pub(crate) async fn confirm(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(device): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        authorize(&p, &form)?;
        let admission = form
            .get("admission")
            .and_then(|secret| state.terminal_admissions.claim(&p, device, secret))
            .ok_or(AppError::NotFound)?;
        observe(
            &state,
            &p,
            device,
            Some(admission),
            form.get("start_terminal") == Some("1"),
        )
        .await
    })
    .await
}

fn authorize(p: &Principal, form: &Form) -> AppResult<()> {
    check_csrf(p, form)?;
    p.require(Permission::ViewDevices)?;
    p.require(Permission::RunControlSessions)
}

async fn observe_agent(
    registry: &Registry,
    device: Uuid,
    request_id: Uuid,
    admission: Option<&Admission>,
) -> Option<Result<(Uuid, BackgroundTerminalObservation), ConsoleCheckError>> {
    let expected = admission.map(|grant| grant.connection);
    let expires = admission.map(|grant| grant.expires);
    let reply = registry
        .check_background_terminal_policy(device, request_id, expected, expires)
        .await;
    expires
        .is_none_or(|end| end > Instant::now())
        .then_some(reply)
}

async fn observe(
    state: &Shared,
    p: &Principal,
    device: Uuid,
    admission: Option<Admission>,
    start_terminal: bool,
) -> AppResult<Response> {
    let request_id = Uuid::new_v4();
    let (requested, result) = if admission.is_some() {
        (
            "device.background_terminal_admission.requested",
            "device.background_terminal_admission.result",
        )
    } else {
        (
            "device.background_terminal_policy.requested",
            "device.background_terminal_policy.result",
        )
    };
    let detail = |mut fields: Value| {
        fields["request_id"] = json!(request_id);
        if let Some(grant) = &admission {
            fields["policy_check_id"] = json!(grant.policy_check);
        }
        fields
    };
    let mut tx = state.db.begin().await?;
    let (org, _) = windows_observation_target(&mut tx, p, device).await?;
    if admission
        .as_ref()
        .is_some_and(|grant| grant.organization != org)
    {
        return Err(AppError::NotFound);
    }
    Audit::user(p, requested)
        .org(org)
        .target("device", device)
        .detail(detail(json!({})))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;

    let reply = observe_agent(&state.registry, device, request_id, admission.as_ref()).await;
    let mut tx = state.db.begin().await?;
    let audit = Audit::user(p, result).org(org).target("device", device);
    let target = windows_observation_target(&mut tx, p, device)
        .await
        .and_then(|(current_org, name)| {
            if current_org == org {
                Ok(name)
            } else {
                Err(AppError::NotFound)
            }
        });
    let name = match target {
        Ok(name) => name,
        Err(error @ (AppError::Forbidden | AppError::Unauthorized | AppError::NotFound)) => {
            audit
                .denied()
                .detail(detail(json!({"status": "access_changed"})))
                .record(&mut *tx)
                .await?;
            tx.commit().await?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let reply = reply
        .filter(|_| {
            admission
                .as_ref()
                .is_none_or(|grant| grant.expires > Instant::now())
        })
        .map(|reply| {
            reply.and_then(|(connection, report)| {
                if state.registry.current_conn(device) == Some(connection) {
                    Ok((connection, report))
                } else {
                    Err(ConsoleCheckError::NotConnected)
                }
            })
        });
    let (finding, status, connection, agent_account) = match reply {
        None => (Check::Expired, "expired", None, None),
        Some(Ok((conn, report))) => {
            let (finding, status) = match report.policy {
                BackgroundTerminalPolicy::Enabled => (Check::Enabled, "enabled"),
                BackgroundTerminalPolicy::Disabled => (Check::Disabled, "disabled"),
                BackgroundTerminalPolicy::Unavailable => (Check::Unavailable, "unavailable"),
            };
            (finding, status, Some(conn), report.agent_account)
        }
        Some(Err(ConsoleCheckError::NotConnected)) => (Check::Offline, "not_connected", None, None),
        Some(Err(ConsoleCheckError::Unsupported)) => {
            (Check::Unsupported, "unsupported", None, None)
        }
        Some(Err(ConsoleCheckError::Busy)) => (Check::Busy, "busy", None, None),
        Some(Err(ConsoleCheckError::Timeout)) => (Check::TimedOut, "timeout", None, None),
    };
    let audit = match (finding, admission.is_some()) {
        (Check::Enabled, _) | (Check::Disabled, false) => audit,
        (Check::Disabled | Check::Expired, true) => audit.denied(),
        _ => audit.failed(),
    };
    let mut fields = json!({"status": status, "connection": connection});
    if let Some(account) = agent_account {
        fields["agent_account"] = json!(account);
    }
    audit.detail(detail(fields)).record(&mut *tx).await?;
    tx.commit().await?;

    let live_connection = connection.filter(|connection| {
        matches!(finding, Check::Enabled)
            && agent_account == Some(WindowsExecutionAccount::LocalSystem)
            && state
                .registry
                .has_capability(device, *connection, CAP_BACKGROUND_TERMINAL)
    });
    if start_terminal {
        let connection = live_connection.filter(|_| {
            admission.as_ref().is_some_and(|grant| grant.live_terminal)
        }).ok_or_else(|| {
            AppError::Conflict(
                "The agent could not verify LocalSystem background terminal access. Check policy again."
                    .into(),
            )
        })?;
        let id = state
            .terminal_sessions
            .reserve(state, p, device, org, connection)?;
        return Ok(Redirect::to(&crate::terminal_session::url(device, id)).into_response());
    }

    let step = if admission.is_some() {
        BackgroundTerminalStep::Confirmation
    } else {
        let secret = match (finding, connection) {
            (Check::Enabled, Some(connection)) => {
                let grant = Admission {
                    user: p.user_id,
                    session: p.session_id.ok_or(AppError::Unauthorized)?,
                    cookie_digest: p.session_token.clone().ok_or(AppError::Unauthorized)?,
                    device,
                    organization: org,
                    connection,
                    live_terminal: live_connection.is_some(),
                    policy_check: request_id,
                    expires: Instant::now() + TTL,
                };
                Some(state.terminal_admissions.issue(p, grant)?)
            }
            _ => None,
        };
        match (live_connection, secret) {
            (Some(_), Some(admission)) => BackgroundTerminalStep::LivePolicy { admission },
            (_, secret) => BackgroundTerminalStep::Policy(secret),
        }
    };
    let mut response = html(flyw8t_web::background_terminal_policy_result(
        &ctx(p, None),
        device,
        &name,
        finding,
        step,
        agent_account,
    ))?;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Conn;
    use flyw8t_protocol::messages::CAP_BACKGROUND_TERMINAL_POLICY;
    use time::OffsetDateTime;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn expired_confirmation_does_not_probe_agent() {
        let registry = Registry::default();
        let device = Uuid::new_v4();
        let connection = Uuid::new_v4();
        let (tx, mut outbound) = mpsc::channel(1);
        assert!(registry.register(
            device,
            Conn {
                conn_id: connection,
                seq: Registry::next_seq(),
                since: OffsetDateTime::now_utc(),
                tx,
                close: CancellationToken::new(),
                physical_console_check: false,
                capabilities: vec![CAP_BACKGROUND_TERMINAL_POLICY.into()],
            },
        ));

        // Model a claimed confirmation whose window elapsed while awaiting the database.
        let grant = Admission {
            user: Uuid::new_v4(),
            session: Uuid::new_v4(),
            cookie_digest: Vec::new(),
            device,
            organization: Uuid::new_v4(),
            connection,
            live_terminal: false,
            policy_check: Uuid::new_v4(),
            expires: Instant::now() - Duration::from_secs(1),
        };
        assert!(
            observe_agent(&registry, device, Uuid::new_v4(), Some(&grant))
                .await
                .is_none()
        );
        assert_eq!(outbound.try_recv(), Err(mpsc::error::TryRecvError::Empty));
    }
}
