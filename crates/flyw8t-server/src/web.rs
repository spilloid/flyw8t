//! Web console handlers. Server-rendered; every mutation is a POST carrying the session's
//! CSRF token, answered with a redirect.

use crate::audit::Audit;
use crate::auth::{self, Principal, Stage, WebUser};
use crate::error::{AppError, AppResult};
use crate::jobs::{self, NewJob};
use crate::queries::{self, JobQuery};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use flyw8t_domain::job::ExecState;
use flyw8t_domain::{Permission, Role};
use flyw8t_protocol::Action;
use flyw8t_web::model::{
    AuditFilter, AuditPage, AuditRow, DeviceFilter, FamilyLink, Flash, PageCtx, RevealedSecret,
};
use serde::Deserialize;
use serde_json::json;
use std::future::Future;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

/// Parsed `application/x-www-form-urlencoded` body. Repeated keys are kept.
pub struct Form(Vec<(String, String)>);

impl Form {
    pub fn parse(body: &[u8]) -> Self {
        Form(form_urlencoded::parse(body).into_owned().collect())
    }
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    pub fn all(&self, key: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Reject a form that does not carry this session's CSRF token.
pub(crate) fn check_csrf(p: &Principal, form: &Form) -> AppResult<()> {
    match form.get("csrf") {
        Some(t) if !p.csrf.is_empty() && constant_time_eq(t.as_bytes(), p.csrf.as_bytes()) => {
            Ok(())
        }
        _ => Err(AppError::Forbidden),
    }
}

/// `s` as a PowerShell single-quoted string: nothing inside is expanded, and a quote is written twice. The curly
/// quotes PowerShell also reads as single quotes are doubled too.
pub(crate) fn powershell_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// The operator's other products, for the frame. Set once, when the server starts (`FLYW8T_FAMILY_LINKS`).
pub static FAMILY: std::sync::OnceLock<Vec<FamilyLink>> = std::sync::OnceLock::new();

fn enrollment_copy_policy() -> axum::http::HeaderValue {
    use base64::Engine;
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        flyw8t_web::ENROLLMENT_COPY_JS.as_bytes(),
    );
    let hash = base64::engine::general_purpose::STANDARD.encode(digest);
    format!("{}; script-src 'sha256-{hash}'", crate::CONSOLE_CSP)
        .parse()
        .expect("static policy and base64 digest are valid header text")
}

pub(crate) fn ctx(p: &Principal, flash: Option<Flash>) -> PageCtx {
    PageCtx {
        user_name: p.display_name.clone(),
        role: p.role.as_str(),
        csrf: p.csrf.clone(),
        now: OffsetDateTime::now_utc(),
        can_run: p.can(Permission::RunDiagnostics),
        is_admin: p.role == Role::Admin,
        can_view_device_activity: p.can(Permission::ViewDeviceActivity),
        can_enroll: p.can(Permission::ManageEnrollment),
        can_support: p.can(Permission::RunSupportSessions),
        can_control: p.can(Permission::RunControlSessions),
        can_manage_devices: p.can(Permission::ManageDevices),
        can_retire: p.can(Permission::RetireDevices),
        can_view_scripts: p.can(Permission::ViewScripts),
        flash,
        version: env!("CARGO_PKG_VERSION"),
        family: FAMILY.get().cloned().unwrap_or_default(),
    }
}

/// Fixed flash messages selected by code, so a URL cannot inject arbitrary text.
pub(crate) fn flash(code: Option<&str>) -> Option<Flash> {
    let (ok, message) = match code? {
        "job-cancelled" => (true, "Cancellation recorded."),
        "inventory-queued" => (true, "Inventory refresh requested. See Job history for the outcome."),
        "org-created" => (true, "Organization created."),
        "site-added" => (true, "Site added."),
        "token-revoked" => (true, "Token revoked."),
        "user-created" => (true, "User created."),
        "user-updated" => (true, "User updated."),
        "user-disabled" => (true, "Account disabled: they are signed out everywhere and their tokens are revoked."),
        "user-enabled" => (true, "Account enabled."),
        "password-changed" => (true, "Password changed. Every other browser was signed out."),
        "org-renamed" => (true, "Organization renamed."),
        "site-renamed" => (true, "Site renamed."),
        "passkey-added" => (true, "Passkey added."),
        "passkey-removed" => (true, "Passkey removed."),
        "session-revoked" => (true, "That session is signed out."),
        "sessions-revoked" => (true, "Signed out everywhere except this browser."),
        "user-signed-out" => (true, "That user was signed out everywhere."),
        "device-revoked" => (true, "Device credential revoked and its connection closed."),
        "device-updated" => (true, "Device updated."),
        "device-retired" => (true, "Device retired: its credential is revoked and its connection closed."),
        "devices-tagged" => (true, "Tag added to the selected devices."),
        "devices-untagged" => (true, "Tag removed from the selected devices."),
        "devices-retired" => (true, "Selected devices retired."),
        "field-defined" => (true, "Field defined."),
        "field-archived" => (true, "Field archived: it is hidden and its values can no longer change."),
        "field-saved" => (true, "Value saved."),
        "script-created" => (true, "Script created. Write its first revision below."),
        "script-saved" => (true, "Revision saved, as a draft."),
        "script-unchanged" => (true, "Nothing changed, so no new revision was saved."),
        "mfa-reset" => (true, "Two-step verification reset. That user was signed out everywhere and sets it up again at next sign-in."),
        "mfa-disabled" => (true, "Two-step verification turned off."),
        "codes-regenerated" => (true, "New recovery codes issued; the old ones no longer work."),
        other => return crate::trust::flash_for(other),
    };
    Some(Flash {
        ok,
        message: message.into(),
    })
}

#[derive(Deserialize, Default)]
pub struct MsgQuery {
    pub(crate) m: Option<String>,
}

pub fn error_response(ctx: Option<&PageCtx>, e: AppError) -> Response {
    if let AppError::SudoRequired(back) = &e {
        let next: String = form_urlencoded::byte_serialize(back.as_bytes()).collect();
        return Redirect::to(&format!("/sudo?next={next}")).into_response();
    }
    e.log();
    let status = e.status();
    (
        status,
        Html(flyw8t_web::error_page(ctx, status.as_u16(), &e.to_string())),
    )
        .into_response()
}

pub(crate) async fn page<F: Future<Output = AppResult<Response>>>(p: &Principal, f: F) -> Response {
    match f.await {
        Ok(r) => r,
        Err(e) => error_response(Some(&ctx(p, None)), e),
    }
}

pub(crate) fn html(s: String) -> AppResult<Response> {
    Ok(Html(s).into_response())
}

pub(crate) fn to(path: impl AsRef<str>) -> AppResult<Response> {
    Ok(Redirect::to(path.as_ref()).into_response())
}

// ---------------------------------------------------------------------------------------
// Sign-in

async fn no_users(state: &Shared) -> bool {
    sqlx::query_as::<_, (bool,)>("SELECT NOT EXISTS (SELECT 1 FROM users)")
        .fetch_one(&state.db)
        .await
        .map(|r| r.0)
        .unwrap_or(false)
}

/// The sign-in page with a fresh login CSRF token, and the cookie that holds it.
pub(crate) fn login_page_response(
    state: &Shared,
    status: StatusCode,
    error: Option<&str>,
    no_admin: bool,
) -> Response {
    let token = auth::random_secret(24);
    (
        status,
        [(header::SET_COOKIE, auth::set_login_cookie(state, &token))],
        Html(flyw8t_web::login_page(
            error.map(String::from),
            no_admin,
            &token,
            state.config.oidc.is_some(),
        )),
    )
        .into_response()
}

pub async fn login_form(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if let Ok(Some(_)) = auth::session_principal(&state, &headers).await {
        return Redirect::to("/").into_response();
    }
    login_page_response(&state, StatusCode::OK, None, no_users(&state).await)
}

pub async fn login(
    State(state): State<Shared>,
    crate::client_ip::ClientIp(ip): crate::client_ip::ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = Form::parse(&body);
    let email = form.get("email").unwrap_or("").trim().to_lowercase();
    let password = form.get("password").unwrap_or("");
    let ip: String = ip;
    let fail = |status: StatusCode, msg: &str, no_admin: bool| {
        login_page_response(&state, status, Some(msg), no_admin)
    };
    // Login CSRF: the form must carry the value of the cookie its page set. Checked before
    // anything else, so a forged sign-in costs no rate-limit place and leaves no audit row.
    let presented = form.get("login_csrf").unwrap_or("");
    if !auth::login_cookie_value(&state, &headers)
        .is_some_and(|c| constant_time_eq(c.as_bytes(), presented.as_bytes()))
    {
        return fail(
            StatusCode::FORBIDDEN,
            "This sign-in page had expired, or did not come from this console. Sign in again.",
            false,
        );
    }
    if !state
        .limiter
        .allow(&format!("login-ip:{ip}"), 20, Duration::from_secs(300))
        || !state.limiter.allow(
            &format!("login-email:{email}"),
            10,
            Duration::from_secs(300),
        )
    {
        return fail(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-in attempts. Wait a few minutes.",
            false,
        );
    }
    let user: Option<(Uuid, String, bool, bool)> = match sqlx::query_as(
        "SELECT id, password_hash, disabled_at IS NOT NULL, totp_enabled_at IS NOT NULL FROM users WHERE email = $1 AND NOT EXISTS (SELECT 1 FROM directory_users d WHERE d.user_id=users.id)",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    {
        Ok(u) => u,
        Err(e) => return error_response(None, e.into()),
    };
    let ok = match &user {
        Some((_, hash, disabled, _)) => auth::verify_password(hash, password) && !disabled,
        None => {
            auth::burn_password_check(password);
            false
        }
    };
    let audit = Audit::anonymous("web", email.clone(), "user.login").ip(&ip);
    let Some((user_id, verified_hash, _, _)) = user.filter(|_| ok) else {
        let _ = audit.denied().record(&state.db).await;
        return fail(
            StatusCode::UNAUTHORIZED,
            "Email or password is incorrect.",
            no_users(&state).await,
        );
    };
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let result: AppResult<(String, Stage)> = async {
        // Decide the stage holding the user row (shared), so a second factor being set up
        // in another request either happens first (and is seen here) or revokes this session
        // when it commits. The password alone reaches the console only when MFA is neither
        // set up nor required.
        // The same lock says whether the password just checked is still the account's and the account still
        // enabled: an administrator's disable or password replacement holds this row, so a sign-in that was
        // already past the password check waits for it and is then refused.
        let mut tx = state.db.begin().await?;
        let (has_totp, still_good): (bool, bool) = sqlx::query_as(
            "SELECT totp_secret IS NOT NULL, disabled_at IS NULL AND password_hash = $2
               FROM users WHERE id = $1 FOR SHARE",
        )
        .bind(user_id)
        .bind(&verified_hash)
        .fetch_one(&mut *tx)
        .await?;
        if !still_good {
            return Err(AppError::Unauthorized);
        }
        let stage = if has_totp {
            Stage::Mfa
        } else if state.config.require_mfa {
            Stage::Enroll
        } else {
            Stage::Full
        };
        let cookie = auth::create_session(&state, &mut tx, user_id, &ip, ua, stage).await?;
        let audit = if stage == Stage::Full {
            audit.target("user", user_id)
        } else {
            Audit::anonymous("web", email.clone(), "user.login.password")
                .ip(&ip)
                .target("user", user_id)
                .detail(json!({ "next": stage.as_str() }))
        };
        audit.record(&mut *tx).await?;
        tx.commit().await?;
        Ok((cookie, stage))
    }
    .await;
    match result {
        Ok((cookie, stage)) => {
            let next = match stage {
                Stage::Mfa => "/login/mfa",
                Stage::Enroll => "/account/mfa",
                Stage::Full => "/",
            };
            ([(header::SET_COOKIE, cookie)], Redirect::to(next)).into_response()
        }
        Err(AppError::Unauthorized) => {
            let _ = Audit::anonymous("web", email.clone(), "user.login")
                .ip(&ip)
                .denied()
                .record(&state.db)
                .await;
            fail(
                StatusCode::UNAUTHORIZED,
                "Email or password is incorrect.",
                false,
            )
        }
        Err(e) => error_response(None, e),
    }
}

pub async fn logout(State(state): State<Shared>, WebUser(p): WebUser, body: Bytes) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1")
            .bind(p.session_id)
            .execute(&state.db)
            .await?;
        Audit::user(&p, "user.logout").record(&state.db).await?;
        state.support.recheck_user(p.user_id);
        Ok((
            [(header::SET_COOKIE, auth::set_cookie(&state, "", 0))],
            Redirect::to("/login"),
        )
            .into_response())
    })
    .await
}

// ---------------------------------------------------------------------------------------
// Pages

pub async fn overview(State(state): State<Shared>, WebUser(p): WebUser) -> Response {
    page(&p, async {
        html(flyw8t_web::overview_page(
            &ctx(&p, None),
            queries::overview(&state, &p).await?,
        ))
    })
    .await
}

#[derive(Deserialize, Default)]
pub struct DeviceQs {
    q: Option<String>,
    org: Option<String>,
    connection: Option<String>,
    tag: Option<String>,
    status: Option<String>,
    sort: Option<String>,
    attention: Option<String>,
    m: Option<String>,
}

pub async fn devices(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(qs): Query<DeviceQs>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewDevices)?;
        let filter = DeviceFilter {
            q: qs.q.unwrap_or_default().chars().take(100).collect(),
            organization: qs.org.and_then(|o| o.parse().ok()),
            connection: qs.connection.unwrap_or_default(),
            tag: qs.tag.unwrap_or_default().chars().take(40).collect(),
            status: qs.status.unwrap_or_default(),
            // Anything but the two known orders is name order.
            sort: qs
                .sort
                .filter(|s| matches!(s.as_str(), "seen" | "disk"))
                .unwrap_or_default(),
            attention: qs.attention.as_deref() == Some("1"),
        };
        let rows = queries::devices(&state, &p, &filter).await?;
        let orgs = queries::org_refs(&state, &p).await?;
        let tags = queries::tags(&state, &p).await?;
        html(flyw8t_web::devices_page(
            &ctx(&p, flash(qs.m.as_deref())),
            rows,
            filter,
            orgs,
            tags,
        ))
    })
    .await
}

#[derive(Deserialize)]
pub struct DeviceDetailQs {
    m: Option<String>,
    refresh: Option<Uuid>,
}

pub async fn device(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    Query(q): Query<DeviceDetailQs>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewDevices)?;
        let d = queries::device(&state, &p, id)
            .await?
            .ok_or(AppError::NotFound)?;
        let history = queries::inventory_history(&state, &p, id).await?;
        let refreshing = d.recent_jobs.iter().any(|job| {
            Some(job.id) == q.refresh
                && job.action == "system.info"
                && !job.state.is_terminal()
                && job.state != flyw8t_domain::job::ExecState::OutcomeUnknown
        });
        html(flyw8t_web::device_page(
            &ctx(&p, flash(q.m.as_deref())),
            d,
            &history,
            refreshing,
        ))
    })
    .await
}

#[derive(Deserialize)]
pub struct ActivityQs {
    before: Option<String>,
}

pub async fn device_activity(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    Query(qs): Query<ActivityQs>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewDevices)?;
        let device = queries::device_summary(&state, &p, id)
            .await?
            .ok_or(AppError::NotFound)?;
        p.require(Permission::ViewDeviceActivity)?;
        let before = qs
            .before
            .as_deref()
            .map(|value| {
                queries::ActivityCursor::parse(value).ok_or_else(|| {
                    AppError::BadRequest("That activity page link is invalid.".into())
                })
            })
            .transpose()?;
        let (events, older) = queries::device_activity(&state, &p, id, before).await?;
        html(flyw8t_web::device_activity_page(
            &ctx(&p, None),
            &device,
            events,
            older.map(|cursor| cursor.as_query_value()),
        ))
    })
    .await
}

// Read the device and its live enrollment again before displaying a reply. A membership change,
// sign-out or retirement during the short agent round trip must take effect.
async fn windows_observation_target(
    tx: &mut sqlx::PgConnection,
    p: &Principal,
    device: Uuid,
) -> AppResult<(Uuid, String)> {
    let (global, orgs) = p.scope();
    let target: (Uuid, String) = sqlx::query_as(
        "SELECT d.organization_id, COALESCE(d.display_name, d.hostname)
         FROM devices d JOIN device_credentials c ON c.device_id = d.id
         WHERE d.id = $1 AND ($2 OR d.organization_id = ANY($3))
           AND d.retired_at IS NULL AND c.revoked_at IS NULL AND lower(d.os_family) = 'windows'
         FOR SHARE OF d, c",
    )
    .bind(device)
    .bind(global)
    .bind(orgs)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;
    auth::recheck_actor(tx, p, Some(target.0), false).await?;
    Ok(target)
}

pub async fn check_physical_console(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(device): Path<Uuid>,
    body: Bytes,
) -> Response {
    use crate::registry::ConsoleCheckError;
    use flyw8t_protocol::PhysicalConsoleState;
    use flyw8t_web::PhysicalConsoleCheck;

    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require(Permission::ViewDevices)?;
        p.require(Permission::RunSupportSessions)?;
        let request = Uuid::new_v4();
        let mut tx = state.db.begin().await?;
        let (org, _) = windows_observation_target(&mut tx, &p, device).await?;
        Audit::user(&p, "device.physical_console.requested")
            .org(org)
            .target("device", device)
            .detail(json!({"request_id":request}))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;

        // Never queue or repeat a desktop request across an agent reconnect.
        let reply = state.registry.check_physical_console(device, request).await;
        let (view, outcome) = match reply {
            Ok(PhysicalConsoleState::ActiveConsole) => {
                (PhysicalConsoleCheck::Active, "active_console")
            }
            Ok(PhysicalConsoleState::NoInteractiveUser) => {
                (PhysicalConsoleCheck::NoActiveLogin, "no_interactive_user")
            }
            Ok(PhysicalConsoleState::NoConsole) => (PhysicalConsoleCheck::NoConsole, "no_console"),
            Ok(PhysicalConsoleState::Unavailable) => (PhysicalConsoleCheck::Unknown, "unavailable"),
            Err(ConsoleCheckError::NotConnected) => {
                (PhysicalConsoleCheck::Offline, "not_connected")
            }
            Err(ConsoleCheckError::Unsupported) => {
                (PhysicalConsoleCheck::Unsupported, "unsupported")
            }
            Err(ConsoleCheckError::Busy) => (PhysicalConsoleCheck::Busy, "busy"),
            Err(ConsoleCheckError::Timeout) => (PhysicalConsoleCheck::TimedOut, "timeout"),
        };
        let mut tx = state.db.begin().await?;
        let (current_org, name) = windows_observation_target(&mut tx, &p, device).await?;
        if current_org != org {
            return Err(AppError::NotFound);
        }
        let audit = Audit::user(&p, "device.physical_console.result")
            .org(current_org)
            .target("device", device)
            .detail(json!({"request_id":request, "status":outcome}));
        if reply.is_err() {
            audit.failed()
        } else {
            audit
        }
        .record(&mut *tx)
        .await?;
        tx.commit().await?;
        html(flyw8t_web::physical_console_result(
            &ctx(&p, None),
            device,
            &name,
            view,
        ))
    })
    .await
}

pub async fn check_background_terminal_policy(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(device): Path<Uuid>,
    body: Bytes,
) -> Response {
    use crate::registry::ConsoleCheckError;
    use flyw8t_protocol::messages::BackgroundTerminalPolicy;
    use flyw8t_web::BackgroundTerminalPolicyCheck as Check;

    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require(Permission::ViewDevices)?;
        p.require(Permission::RunControlSessions)?;
        let request_id = Uuid::new_v4();
        let mut tx = state.db.begin().await?;
        let (org, _) = windows_observation_target(&mut tx, &p, device).await?;
        Audit::user(&p, "device.background_terminal_policy.requested")
            .org(org)
            .target("device", device)
            .detail(json!({"request_id": request_id}))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;

        let reply = state
            .registry
            .check_background_terminal_policy(device, request_id)
            .await;
        let mut tx = state.db.begin().await?;
        let (current_org, name) = windows_observation_target(&mut tx, &p, device).await?;
        if current_org != org {
            return Err(AppError::NotFound);
        }
        let observation = reply.and_then(|(connection, policy)| {
            if state.registry.current_conn(device) != Some(connection) {
                return Err(ConsoleCheckError::NotConnected);
            }
            Ok((connection, policy))
        });
        let (view, status, connection, verified) = match observation {
            Ok((connection, BackgroundTerminalPolicy::Enabled)) => {
                (Check::Enabled, "enabled", Some(connection), true)
            }
            Ok((connection, BackgroundTerminalPolicy::Disabled)) => {
                (Check::Disabled, "disabled", Some(connection), true)
            }
            Ok((connection, BackgroundTerminalPolicy::Unavailable)) => {
                (Check::Unavailable, "unavailable", Some(connection), false)
            }
            Err(ConsoleCheckError::NotConnected) => (Check::Offline, "not_connected", None, false),
            Err(ConsoleCheckError::Unsupported) => (Check::Unsupported, "unsupported", None, false),
            Err(ConsoleCheckError::Busy) => (Check::Busy, "busy", None, false),
            Err(ConsoleCheckError::Timeout) => (Check::TimedOut, "timeout", None, false),
        };
        let audit = Audit::user(&p, "device.background_terminal_policy.result")
            .org(org)
            .target("device", device)
            .detail(json!({"request_id": request_id, "status": status, "connection": connection}));
        if verified { audit } else { audit.failed() }
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        html(flyw8t_web::background_terminal_policy_result(
            &ctx(&p, None),
            device,
            &name,
            view,
        ))
    })
    .await
}

pub async fn run_job(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        let name = form.get("action").unwrap_or("");
        let action = Action::from_request(name, |k| form.get(k).map(str::to_string))
            .map_err(|e| AppError::BadRequest(e.to_string()))?;
        let refresh = action == Action::SystemInfo && form.get("return_to_device") == Some("yes");
        let job_id = jobs::create(
            &state,
            &p,
            NewJob {
                device_id: id,
                action,
                timeout_secs: None,
                idempotency_key: None,
                batch_id: None,
            },
        )
        .await?;
        if refresh {
            to(format!("/devices/{id}?m=inventory-queued&refresh={job_id}"))
        } else {
            to(format!("/jobs/{job_id}"))
        }
    })
    .await
}

pub async fn revoke_device(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::RetireDevices)?;
        if form.get("confirm") != Some("yes") {
            return Err(AppError::BadRequest("Confirm the revocation first.".into()));
        }
        let mut tx = state.db.begin().await?;
        let org: Option<(Uuid,)> = sqlx::query_as("SELECT organization_id FROM devices WHERE id = $1").bind(id).fetch_optional(&mut *tx).await?;
        let (org,) = org.ok_or(AppError::NotFound)?;
        let n = sqlx::query("UPDATE device_credentials SET revoked_at = now(), revoked_reason = $2 WHERE device_id = $1 AND revoked_at IS NULL")
            .bind(id)
            .bind(format!("revoked by {}", p.email))
            .execute(&mut *tx)
            .await?
            .rows_affected();
        Audit::user(&p, "device.revoke").org(org).target("device", id).detail(json!({ "credentials_revoked": n })).record(&mut *tx).await?;
        tx.commit().await?;
        state.registry.kick(id);
        to(format!("/devices/{id}?m=device-revoked"))
    })
    .await
}

/// The jobs list goes back this many pages (a million jobs); narrow it with the filters to reach older ones.
const MAX_JOBS_PAGE: u32 = 10_000;

#[derive(Deserialize, Default)]
pub struct JobsQs {
    state: Option<String>,
    batch: Option<Uuid>,
    action: Option<String>,
    page: Option<u32>,
}

pub async fn jobs_list(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(qs): Query<JobsQs>,
) -> Response {
    page(&p, async {
        let st = qs.state.as_deref().and_then(ExecState::parse);
        // Only a catalog action narrows the list; anything else is no filter.
        let action = qs
            .action
            .as_deref()
            .and_then(flyw8t_protocol::catalog::info)
            .map(|a| a.name.to_string());
        let page_number = qs.page.unwrap_or(1).clamp(1, MAX_JOBS_PAGE);
        let size = flyw8t_web::JOBS_PAGE_SIZE;
        // One more than a page, to know whether an older page exists.
        let mut rows = queries::jobs(
            &state,
            &p,
            &JobQuery {
                state: st,
                batch: qs.batch,
                limit: size + 1,
                action: action.clone(),
                offset: i64::from(page_number - 1) * size,
                ..Default::default()
            },
        )
        .await?;
        let more = rows.len() as i64 > size && page_number < MAX_JOBS_PAGE;
        rows.truncate(size as usize);
        let batch = match qs.batch {
            Some(b) => Some(
                queries::batch(&state, &p, b)
                    .await?
                    .ok_or(AppError::NotFound)?,
            ),
            None => None,
        };
        html(flyw8t_web::jobs_page(
            &ctx(&p, None),
            rows,
            flyw8t_web::JobsView {
                state: st,
                action: action.unwrap_or_default(),
                batch,
                page: page_number,
                more,
            },
        ))
    })
    .await
}

pub async fn job(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        let j = queries::job(&state, &p, id)
            .await?
            .ok_or(AppError::NotFound)?;
        html(flyw8t_web::job_page(
            &ctx(&p, flash(m.m.as_deref())),
            j,
            p.can(Permission::CancelJobs),
        ))
    })
    .await
}

pub async fn cancel_job(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        jobs::cancel(&state, &p, id).await?;
        to(format!("/jobs/{id}?m=job-cancelled"))
    })
    .await
}

// ---------------------------------------------------------------------------------------
// Organizations and enrollment

pub async fn organizations(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        html(flyw8t_web::organizations_page(
            &ctx(&p, flash(m.m.as_deref())),
            queries::organizations(&state, &p, None).await?,
        ))
    })
    .await
}

pub(crate) fn clean_name(raw: Option<&str>) -> AppResult<String> {
    let name = raw.unwrap_or("").trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(AppError::BadRequest(
            "Name must be 1-200 characters.".into(),
        ));
    }
    Ok(name.to_string())
}

pub async fn create_org(State(state): State<Shared>, WebUser(p): WebUser, body: Bytes) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageOrganizations)?;
        let name = clean_name(form.get("name"))?;
        let mut tx = state.db.begin().await?;
        let (id,): (Uuid,) =
            sqlx::query_as("INSERT INTO organizations (name) VALUES ($1) RETURNING id")
                .bind(&name)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| match &e {
                    sqlx::Error::Database(d) if d.is_unique_violation() => {
                        AppError::Conflict("An organization with that name exists.".into())
                    }
                    _ => e.into(),
                })?;
        sqlx::query("INSERT INTO sites (organization_id, name) VALUES ($1, 'Main')")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        Audit::user(&p, "organization.create")
            .org(id)
            .target("organization", id)
            .detail(json!({ "name": name }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        to(format!("/organizations/{id}?m=org-created"))
    })
    .await
}

async fn visible_org(
    state: &Shared,
    p: &Principal,
    id: Uuid,
) -> AppResult<flyw8t_web::model::OrgSummary> {
    queries::organizations(state, p, Some(id))
        .await?
        .into_iter()
        .next()
        .ok_or(AppError::NotFound)
}

pub async fn organization(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        let org = visible_org(&state, &p, id).await?;
        let tokens = queries::enrollment_tokens(&state, id).await?;
        let fields = crate::fields::resolve(&state, &p, id, None, None).await?;
        html(flyw8t_web::organization_page(
            &ctx(&p, flash(m.m.as_deref())),
            org,
            tokens,
            None,
            fields,
        ))
    })
    .await
}

/// A site: its devices and the custom field values set on it.
pub async fn site(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewDevices)?;
        let (all, orgs) = p.scope();
        let row: Option<(String, Uuid, String)> = sqlx::query_as(
            "SELECT s.name, o.id, o.name FROM sites s JOIN organizations o ON o.id = s.organization_id
              WHERE s.id = $1 AND ($2 OR s.organization_id = ANY($3))",
        )
        .bind(id)
        .bind(all)
        .bind(&orgs)
        .fetch_optional(&state.db)
        .await?;
        let (name, org_id, org_name) = row.ok_or(AppError::NotFound)?;
        let devices: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, coalesce(display_name, hostname) FROM devices
              WHERE site_id = $1 AND retired_at IS NULL ORDER BY lower(coalesce(display_name, hostname)) LIMIT 500",
        )
        .bind(id)
        .fetch_all(&state.db)
        .await?;
        let fields = crate::fields::resolve(&state, &p, org_id, Some(id), None).await?;
        let (network_assets,): (i64,) = sqlx::query_as("SELECT count(*) FROM network_assets WHERE site_id=$1 AND organization_id=$2")
            .bind(id).bind(org_id).fetch_one(&state.db).await?;
        let (network_collectors,): (i64,) = sqlx::query_as("SELECT count(*) FROM network_collectors WHERE site_id=$1 AND organization_id=$2 AND revoked_at IS NULL")
            .bind(id).bind(org_id).fetch_one(&state.db).await?;
        html(flyw8t_web::site_page(
            &ctx(&p, flash(m.m.as_deref())),
            flyw8t_web::model::SitePage {
                id,
                name,
                organization: flyw8t_web::model::OrgRef {
                    id: org_id,
                    name: org_name,
                },
                devices: devices
                    .into_iter()
                    .map(|(id, name)| flyw8t_web::model::OrgRef { id, name })
                    .collect(),
                network_assets,
                network_collectors,
            },
            fields,
        ))
    })
    .await
}

pub async fn add_site(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageOrganizations)?;
        visible_org(&state, &p, id).await?;
        let name = clean_name(form.get("name"))?;
        sqlx::query("INSERT INTO sites (organization_id, name) VALUES ($1, $2)")
            .bind(id)
            .bind(&name)
            .execute(&state.db)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(d) if d.is_unique_violation() => {
                    AppError::Conflict("That site exists.".into())
                }
                _ => e.into(),
            })?;
        Audit::user(&p, "site.create")
            .org(id)
            .detail(json!({ "name": name }))
            .record(&state.db)
            .await?;
        to(format!("/organizations/{id}?m=site-added"))
    })
    .await
}

/// Rename an organization. Its id, and everything that points at it, stays.
pub async fn rename_org(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageOrganizations)?;
        visible_org(&state, &p, id).await?;
        let name = clean_name(form.get("name"))?;
        let mut tx = state.db.begin().await?;
        // Read under the lock that changes it, so the audit's "from" is the name this change replaced.
        let (old,): (String,) =
            sqlx::query_as("SELECT name FROM organizations WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        if name != old {
            sqlx::query("UPDATE organizations SET name = $2 WHERE id = $1")
                .bind(id)
                .bind(&name)
                .execute(&mut *tx)
                .await
                .map_err(|e| match &e {
                    sqlx::Error::Database(d) if d.is_unique_violation() => {
                        AppError::Conflict("An organization with that name exists.".into())
                    }
                    _ => e.into(),
                })?;
            Audit::user(&p, "organization.rename")
                .org(id)
                .target("organization", id)
                .detail(json!({ "from": old, "to": name }))
                .record(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        to(format!("/organizations/{id}?m=org-renamed"))
    })
    .await
}

/// Rename a site, within the caller's organizations.
pub async fn rename_site(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageOrganizations)?;
        let name = clean_name(form.get("name"))?;
        let (all, orgs) = p.scope();
        let mut tx = state.db.begin().await?;
        let row: Option<(String, Uuid)> = sqlx::query_as(
            "SELECT name, organization_id FROM sites
              WHERE id = $1 AND ($2 OR organization_id = ANY($3)) FOR UPDATE",
        )
        .bind(id)
        .bind(all)
        .bind(&orgs)
        .fetch_optional(&mut *tx)
        .await?;
        let (old, org) = row.ok_or(AppError::NotFound)?;
        if name != old {
            sqlx::query("UPDATE sites SET name = $2 WHERE id = $1")
                .bind(id)
                .bind(&name)
                .execute(&mut *tx)
                .await
                .map_err(|e| match &e {
                    sqlx::Error::Database(d) if d.is_unique_violation() => {
                        AppError::Conflict("That site exists.".into())
                    }
                    _ => e.into(),
                })?;
            Audit::user(&p, "site.rename")
                .org(org)
                .target("site", id)
                .detail(json!({ "from": old, "to": name }))
                .record(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        to(format!("/sites/{id}?m=site-renamed"))
    })
    .await
}

fn enrollment_setup(public_url: &str) -> String {
    include_str!("enroll-windows.ps1")
        .replace("__VERSION__", env!("CARGO_PKG_VERSION"))
        .replace("__SERVER_URL__", &powershell_literal(public_url))
}

pub async fn download_enrollment_setup(
    State(state): State<Shared>,
    WebUser(p): WebUser,
) -> Response {
    page(&p, async {
        p.require(Permission::ManageEnrollment)?;
        // Windows PowerShell 5.1 uses the BOM to recognize UTF-8, including the URL.
        let body = format!("\u{feff}{}", enrollment_setup(&state.config.public_url));
        Ok((
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"Install-Flyw8t.ps1\"",
                ),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response())
    })
    .await
}

pub async fn create_enrollment_token(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageEnrollment)?;
        let org = visible_org(&state, &p, id).await?;
        let ttl_minutes: i64 = form.get("ttl_minutes").and_then(|v| v.parse().ok()).unwrap_or(60);
        if !(5..=1440).contains(&ttl_minutes) {
            return Err(AppError::BadRequest("Validity must be between 5 minutes and 24 hours.".into()));
        }
        let max_uses: i32 = form.get("max_uses").and_then(|v| v.parse().ok()).unwrap_or(1);
        if !(1..=100).contains(&max_uses) {
            return Err(AppError::BadRequest("Devices must be between 1 and 100.".into()));
        }
        let site: Option<Uuid> = form.get("site").filter(|s| !s.is_empty()).map(|s| s.parse()).transpose().map_err(|_| AppError::BadRequest("Unknown site.".into()))?;
        let site_name = site.map(|id| {
            org.sites.iter().find(|view| view.id == id).map(|view| view.name.clone())
                .ok_or_else(|| AppError::BadRequest("Unknown site.".into()))
        }).transpose()?;
        let download = form.get("download") == Some("windows");
        let template = if download { Some(crate::windows_installer::template(&state).await?) } else { None };
        let secret = format!("{}{}", auth::ENROLL_PREFIX, auth::random_secret(32));
        let installer = template.map(|base| -> AppResult<Vec<u8>> {
            let mut exe = base.to_vec();
            flyw8t_protocol::enrollment_package::EnrollmentPackage {
                server_url: state.config.public_url.clone(),
                organization: org.name.clone(),
                site: site_name,
                token: secret.clone(),
            }.append(&mut exe).map_err(|error| AppError::Internal(error.into()))?;
            Ok(exe)
        }).transpose()?;
        let mut tx = state.db.begin().await?;
        auth::recheck_actor(&mut tx, &p, Some(id), false).await?;
        let (token_id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO enrollment_tokens (organization_id, site_id, token_hash, created_by, expires_at, max_uses)
             VALUES ($1, $2, $3, $4, now() + make_interval(mins => $5), $6) RETURNING id",
        )
        .bind(id)
        .bind(site)
        .bind(auth::digest(&secret))
        .bind(p.user_id)
        .bind(ttl_minutes as i32)
        .bind(max_uses)
        .fetch_one(&mut *tx)
        .await?;
        Audit::user(&p, "enrollment_token.create")
            .org(id)
            .target("enrollment_token", token_id)
            .detail(json!({ "ttl_minutes": ttl_minutes, "max_uses": max_uses, "site": site }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        if let Some(exe) = installer {
            return Ok(([
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CONTENT_DISPOSITION, "attachment; filename=Flyw8t-Setup-x64.exe"),
                (header::CACHE_CONTROL, "no-store"),
            ], exe).into_response());
        }
        let revealed = RevealedSecret {
            label: format!("Enrollment token for {}", org.name),
            hint: format!(
                "Valid for {ttl_minutes} minutes and {max_uses} device(s). Whoever holds it can enroll a device into {} until then; revoke it below if it goes astray.",
                org.name
            ),
            commands: Some(enrollment_setup(&state.config.public_url)),
            secret,
        };
        let tokens = queries::enrollment_tokens(&state, id).await?;
        let fields = crate::fields::resolve(&state, &p, id, None, None).await?;
        let mut resp =
            Html(flyw8t_web::organization_page(&ctx(&p, None), org, tokens, Some(revealed), fields)).into_response();
        resp.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        resp.headers_mut().insert(header::CONTENT_SECURITY_POLICY, enrollment_copy_policy());
        Ok(resp)
    })
    .await
}

pub async fn revoke_enrollment_token(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path((org, token)): Path<(Uuid, Uuid)>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require(Permission::ManageEnrollment)?;
        visible_org(&state, &p, org).await?;
        let n = sqlx::query("UPDATE enrollment_tokens SET revoked_at = now() WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL")
            .bind(token)
            .bind(org)
            .execute(&state.db)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound);
        }
        Audit::user(&p, "enrollment_token.revoke").org(org).target("enrollment_token", token).record(&state.db).await?;
        to(format!("/organizations/{org}?m=token-revoked"))
    })
    .await
}

// ---------------------------------------------------------------------------------------
// Audit and administration (admins only)

/// The audit page's query string. Everything is text: an empty box in the filter form is no filter.
#[derive(Deserialize, Default)]
pub struct AuditQs {
    actor: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    org: Option<String>,
    from: Option<String>,
    to: Option<String>,
    before: Option<String>,
}

/// `YYYY-MM-DD`, as a date input sends it.
fn parse_day(s: &str) -> Option<time::Date> {
    let mut parts = s.split('-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let month = time::Month::try_from(m.parse::<u8>().ok()?).ok()?;
    time::Date::from_calendar_date(y.parse().ok()?, month, d.parse().ok()?).ok()
}

fn audit_filter(qs: AuditQs) -> AppResult<AuditFilter> {
    fn given(v: Option<String>) -> Option<String> {
        v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }
    let bad =
        |what: &str| AppError::BadRequest(format!("That {what} is not one this page offers."));
    let text = |v: Option<String>, max: usize| -> String {
        given(v).unwrap_or_default().chars().take(max).collect()
    };
    let day = |v: Option<String>| -> AppResult<Option<time::Date>> {
        given(v)
            .map(|s| parse_day(&s).ok_or_else(|| bad("date")))
            .transpose()
    };
    Ok(AuditFilter {
        actor: text(qs.actor, 200),
        action: text(qs.action, 100),
        outcome: given(qs.outcome)
            .map(|o| {
                if matches!(o.as_str(), "success" | "denied" | "failed") {
                    Ok(o)
                } else {
                    Err(bad("result"))
                }
            })
            .transpose()?,
        organization: given(qs.org)
            .map(|o| o.parse().map_err(|_| bad("organization")))
            .transpose()?,
        from: day(qs.from)?,
        to: day(qs.to)?,
        before: given(qs.before)
            .map(|b| b.parse::<i64>().map_err(|_| bad("page")))
            .transpose()?,
    })
}

pub async fn audit(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(qs): Query<AuditQs>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewAudit)?;
        let filter = audit_filter(qs)?;
        let size = queries::AUDIT_PAGE_SIZE;
        // One more than a page, to know whether older events exist.
        let mut rows = queries::audit(&state, &p, &filter, size + 1).await?;
        let older = (rows.len() as i64 > size).then(|| {
            rows.truncate(size as usize);
            rows.last().map(|r| r.id)
        });
        html(flyw8t_web::audit_page(
            &ctx(&p, None),
            AuditPage {
                rows,
                filter,
                older: older.flatten(),
                organizations: queries::org_refs(&state, &p).await?,
            },
        ))
    })
    .await
}

/// One CSV cell: always quoted, quotes doubled. A cell a spreadsheet would read as a formula gets a leading
/// apostrophe, so text someone put into the audit log (a device name, an email) is never run when the file is opened.
fn csv_cell(s: &str) -> String {
    let guard = s.trim_start().starts_with([
        '=', '+', '-', '@', '\u{FF1D}', '\u{FF0B}', '\u{FF0D}', '\u{FF20}',
    ]) || s.starts_with(['\t', '\r', '\n']);
    format!(
        "\"{}{}\"",
        if guard { "'" } else { "" },
        s.replace('"', "\"\"")
    )
}

const AUDIT_CSV_HEADER: &str =
    "id,at,actor,channel,credential,client_ip,action,target_type,target_id,outcome,organization,detail\r\n";

/// The most an export may weigh. Events are short; this is a ceiling for a log someone has stuffed.
const AUDIT_EXPORT_BYTES: usize = 32 * 1024 * 1024;

fn audit_csv_line(r: &AuditRow) -> String {
    let mut out = String::new();
    {
        let cells = [
            r.id.to_string(),
            flyw8t_web::fmt::iso(r.at),
            r.actor_label.clone(),
            r.channel.clone(),
            r.credential.clone().unwrap_or_default(),
            r.client_ip.clone().unwrap_or_default(),
            r.action.clone(),
            r.target_type.clone().unwrap_or_default(),
            r.target_id.map(|t| t.to_string()).unwrap_or_default(),
            r.outcome.clone(),
            r.organization.clone().unwrap_or_default(),
            r.detail.to_string(),
        ];
        let line: Vec<String> = cells.iter().map(|c| csv_cell(c)).collect();
        out.push_str(&line.join(","));
        out.push_str("\r\n");
    }
    out
}

/// Add `line` to `text` unless that would take it past `max_bytes`; says whether it was added.
fn push_within(text: &mut String, line: &str, max_bytes: usize) -> bool {
    if text.len() + line.len() > max_bytes {
        return false;
    }
    text.push_str(line);
    true
}

/// The export's text, how many events it holds, and whether matching events were left out. Read a page at a time, so
/// the server never holds more than one page of events beside the file it is building.
async fn audit_csv_text(
    state: &Shared,
    p: &Principal,
    filter: &AuditFilter,
    max_events: i64,
    max_bytes: usize,
) -> AppResult<(String, i64, bool)> {
    const CHUNK: i64 = 500;
    let mut filter = filter.clone();
    filter.before = None;
    let mut text = String::from(AUDIT_CSV_HEADER);
    let mut events = 0;
    loop {
        let rows = queries::audit(state, p, &filter, CHUNK).await?;
        for r in &rows {
            if events == max_events || !push_within(&mut text, &audit_csv_line(r), max_bytes) {
                return Ok((text, events, true));
            }
            events += 1;
        }
        match rows.last() {
            Some(last) if rows.len() as i64 == CHUNK => filter.before = Some(last.id),
            _ => return Ok((text, events, false)),
        }
    }
}

/// The audit log as a file, with the page's filters: newest first, at most `AUDIT_EXPORT_LIMIT` events. Taking a
/// copy of the log is itself recorded.
pub async fn audit_csv(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(qs): Query<AuditQs>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewAudit)?;
        let filter = audit_filter(qs)?;
        let (text, events, truncated) = audit_csv_text(
            &state,
            &p,
            &filter,
            queries::AUDIT_EXPORT_LIMIT,
            AUDIT_EXPORT_BYTES,
        )
        .await?;
        Audit::user(&p, "audit.export")
            .detail(json!({
                "filters": flyw8t_web::audit_query(&filter),
                "events": events,
                "truncated": truncated,
            }))
            .record(&state.db)
            .await?;
        let now = OffsetDateTime::now_utc();
        let name = format!(
            "flyw8t-audit-{:04}{:02}{:02}-{:02}{:02}{:02}.csv",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        Ok((
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{name}\""),
                ),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            text,
        )
            .into_response())
    })
    .await
}

async fn admin_view(
    state: &Shared,
    p: &Principal,
    flash_code: Option<&str>,
    revealed: Option<RevealedSecret>,
) -> AppResult<Response> {
    p.require(Permission::ManageUsers)?;
    let users = queries::users(state).await?;
    let tokens = queries::api_tokens(state).await?;
    let orgs = queries::org_refs(state, p).await?;
    let reauth_for_mcp = if state.config.oidc.is_some() && !p.sudo {
        let mut db = state.db.acquire().await?;
        crate::directory::is_directory(&mut db, p.user_id).await?
            && !crate::passkeys::recent_provider(&mut *db, p).await?
    } else {
        false
    };
    let mut resp = Html(flyw8t_web::admin_page(
        &ctx(p, flash(flash_code)),
        users,
        tokens,
        orgs,
        revealed.clone(),
        state.config.oidc.is_some(),
        reauth_for_mcp,
    ))
    .into_response();
    if revealed.is_some() {
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    }
    Ok(resp)
}

pub async fn admin(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, admin_view(&state, &p, m.m.as_deref(), None)).await
}

pub async fn create_user(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageUsers)?;
        p.require_sudo("/admin")?;
        let email = form.get("email").unwrap_or("").trim().to_lowercase();
        if !email.contains('@') || email.len() > 254 {
            return Err(AppError::BadRequest("Enter a valid email address.".into()));
        }
        let name = clean_name(form.get("display_name"))?;
        let password = form.get("password").unwrap_or("");
        if password.chars().count() < auth::MIN_PASSWORD_LEN {
            return Err(AppError::BadRequest(format!("Passwords must be at least {} characters.", auth::MIN_PASSWORD_LEN)));
        }
        let role = form.get("role").and_then(Role::parse).ok_or_else(|| AppError::BadRequest("Unknown role.".into()))?;
        let orgs: Vec<Uuid> = form.all("org").into_iter().filter_map(|o| o.parse().ok()).collect();
        let hash = auth::hash_password(password)?;
        let mut tx = state.db.begin().await?;
        // Whoever creates an account must, as of now, still be an enabled administrator in sudo mode.
        auth::recheck_actor(&mut tx, &p, None, true).await?;
        let (uid,): (Uuid,) = sqlx::query_as("INSERT INTO users (email, display_name, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id")
            .bind(&email)
            .bind(&name)
            .bind(hash)
            .bind(role.as_str())
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict("A user with that email exists.".into()),
                _ => e.into(),
            })?;
        if role != Role::Admin {
            for org in &orgs {
                sqlx::query("INSERT INTO user_organizations (user_id, organization_id) VALUES ($1, $2)")
                    .bind(uid)
                    .bind(org)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        Audit::user(&p, "user.create")
            .target("user", uid)
            .detail(json!({ "email": email, "role": role.as_str(), "organizations": orgs }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        to("/admin?m=user-created")
    })
    .await
}

pub async fn create_api_token(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageUsers)?;
        let name = clean_name(form.get("name"))?;
        let mut scopes: Vec<String> = form.all("scope").into_iter().filter(|s| matches!(*s, "read" | "jobs:run" | "support:screenshot")).map(String::from).collect();
        scopes.sort();
        scopes.dedup();
        if scopes.is_empty() {
            return Err(AppError::BadRequest("Choose at least one scope.".into()));
        }
        let days: i32 = form.get("ttl_days").and_then(|d| d.parse().ok()).filter(|d| (1..=365).contains(d)).unwrap_or(90);
        let body = auth::random_secret(32);
        let secret = format!("{}{body}", auth::TOKEN_PREFIX);
        let prefix: String = body.chars().take(8).collect();
        let mut tx = state.db.begin().await?;
        let sso_screenshot = scopes == ["support:screenshot"] && !p.sudo
            && state.config.oidc.is_some() && crate::directory::is_directory(&mut tx, p.user_id).await?;
        if !sso_screenshot { p.require_sudo("/admin")?; }
        auth::recheck_actor(&mut tx, &p, None, !sso_screenshot).await?;
        if sso_screenshot && !crate::passkeys::recent_provider(&mut *tx, &p).await? {
            return to("/login/oidc?resume=mcp");
        }
        let days = if sso_screenshot { days.min(30) } else { days };
        let (tid,): (Uuid,) = sqlx::query_as(
            "INSERT INTO api_tokens (user_id, name, prefix, token_hash, scopes, expires_at)
             VALUES ($1, $2, $3, $4, $5, now() + make_interval(days => $6)) RETURNING id",
        )
        .bind(p.user_id)
        .bind(&name)
        .bind(&prefix)
        .bind(auth::digest(&secret))
        .bind(&scopes)
        .bind(days)
        .fetch_one(&mut *tx)
        .await?;
        Audit::user(&p, "api_token.create").target("api_token", tid).detail(json!({ "name": name, "scopes": scopes, "days": days })).record(&mut *tx).await?;
        tx.commit().await?;
        let revealed = RevealedSecret {
            label: format!("API token \"{name}\""),
            secret,
            hint: format!("Send as Authorization: Bearer <token> to {}/api/v1/. It acts as you, limited to: {}.", state.config.public_url, scopes.join(", ")),
            commands: None,
        };
        admin_view(&state, &p, None, Some(revealed)).await
    })
    .await
}

pub async fn revoke_api_token(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require(Permission::ManageUsers)?;
        let n = sqlx::query(
            "UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound);
        }
        Audit::user(&p, "api_token.revoke")
            .target("api_token", id)
            .record(&state.db)
            .await?;
        to("/admin?m=token-revoked")
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::{csv_cell, parse_day, powershell_literal, push_within};

    #[test]
    fn a_csv_cell_is_quoted_and_never_a_formula() {
        assert_eq!(csv_cell("plain"), "\"plain\"");
        assert_eq!(csv_cell("a,b\nc"), "\"a,b\nc\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        for formula in [
            "=1+1",
            "+1",
            "-1",
            "@SUM(A1)",
            "\t=1",
            "\r=1",
            "\n=1+1",
            "  =1+1",
            "\u{FF1D}1+1",
            "\u{FF0B}1",
            "\u{FF0D}1",
            "\u{FF20}SUM(A1)",
            "\tplain",
        ] {
            assert_eq!(csv_cell(formula), format!("\"'{formula}\""), "{formula:?}");
        }
        // Only the first character matters: these are text to a spreadsheet already.
        assert_eq!(csv_cell("a=b"), "\"a=b\"");
        assert_eq!(csv_cell(""), "\"\"");
    }

    #[test]
    fn an_export_never_passes_its_byte_budget() {
        let mut text = String::from("12345");
        assert!(push_within(&mut text, "678", 8), "exactly the budget fits");
        assert_eq!(text, "12345678");
        assert!(!push_within(&mut text, "9", 8), "one byte more does not");
        assert_eq!(text, "12345678", "a refused line leaves the text as it was");
        assert!(push_within(&mut text, "", 8));
    }

    #[test]
    fn a_day_is_four_two_two_digits_and_a_real_date() {
        assert_eq!(
            parse_day("2026-11-15"),
            Some(time::Date::from_calendar_date(2026, time::Month::November, 15).unwrap())
        );
        for bad in [
            "2026-02-30",
            "2026-13-01",
            "26-11-15",
            "2026-11-15-1",
            "2026/11/15",
            "",
            "2026-1-5",
        ] {
            assert_eq!(parse_day(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_powershell_literal_expands_nothing_and_cannot_be_closed_early() {
        assert_eq!(
            powershell_literal("https://rmm.example"),
            "'https://rmm.example'"
        );
        // Inside single quotes `$(...)` and backticks are plain text.
        assert_eq!(
            powershell_literal("https://x/$(Stop-Computer)`n"),
            "'https://x/$(Stop-Computer)`n'"
        );
        // Every character PowerShell reads as a single quote is doubled.
        assert_eq!(powershell_literal("a'; calc; '"), "'a''; calc; '''");
        assert_eq!(
            powershell_literal("a\u{2019}b\u{2018}c"),
            "'a\u{2019}\u{2019}b\u{2018}\u{2018}c'"
        );
    }
}
