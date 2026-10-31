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
use flyw8t_web::model::{DeviceFilter, Flash, PageCtx, RevealedSecret};
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

pub(crate) fn ctx(p: &Principal, flash: Option<Flash>) -> PageCtx {
    PageCtx {
        user_name: p.display_name.clone(),
        role: p.role.as_str(),
        csrf: p.csrf.clone(),
        now: OffsetDateTime::now_utc(),
        can_run: p.can(Permission::RunDiagnostics),
        is_admin: p.role == Role::Admin,
        can_enroll: p.can(Permission::ManageEnrollment),
        can_support: p.can(Permission::RunSupportSessions),
        can_control: p.can(Permission::RunControlSessions),
        flash,
    }
}

/// Fixed flash messages selected by code, so a URL cannot inject arbitrary text.
pub(crate) fn flash(code: Option<&str>) -> Option<Flash> {
    let (ok, message) = match code? {
        "job-cancelled" => (true, "Cancellation recorded."),
        "org-created" => (true, "Organization created."),
        "site-added" => (true, "Site added."),
        "token-revoked" => (true, "Token revoked."),
        "user-created" => (true, "User created."),
        "device-revoked" => (true, "Device credential revoked and its connection closed."),
        "mfa-reset" => (true, "Two-step verification reset. That user was signed out everywhere and sets it up again at next sign-in."),
        "mfa-disabled" => (true, "Two-step verification turned off."),
        "codes-regenerated" => (true, "New recovery codes issued; the old ones no longer work."),
        _ => return None,
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

pub async fn login_form(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if let Ok(Some(_)) = auth::session_principal(&state, &headers).await {
        return Redirect::to("/").into_response();
    }
    Html(flyw8t_web::login_page(None, no_users(&state).await, None)).into_response()
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
        (
            status,
            Html(flyw8t_web::login_page(Some(msg.into()), no_admin, None)),
        )
            .into_response()
    };
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
        "SELECT id, password_hash, disabled_at IS NOT NULL, totp_enabled_at IS NOT NULL FROM users WHERE email = $1",
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
    let Some((user_id, _, _, _)) = user.filter(|_| ok) else {
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
        let mut tx = state.db.begin().await?;
        let (has_totp,): (bool,) =
            sqlx::query_as("SELECT totp_secret IS NOT NULL FROM users WHERE id = $1 FOR SHARE")
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await?;
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
        };
        let rows = queries::devices(&state, &p, &filter).await?;
        let orgs = queries::org_refs(&state, &p).await?;
        html(flyw8t_web::devices_page(&ctx(&p, None), rows, filter, orgs))
    })
    .await
}

pub async fn device(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewDevices)?;
        let d = queries::device(&state, &p, id)
            .await?
            .ok_or(AppError::NotFound)?;
        html(flyw8t_web::device_page(&ctx(&p, flash(m.m.as_deref())), d))
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
        let job_id = jobs::create(
            &state,
            &p,
            NewJob {
                device_id: id,
                action,
                timeout_secs: None,
                idempotency_key: None,
            },
        )
        .await?;
        to(format!("/jobs/{job_id}"))
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
        p.require(Permission::ManageUsers)?;
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

#[derive(Deserialize, Default)]
pub struct JobsQs {
    state: Option<String>,
}

pub async fn jobs_list(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(qs): Query<JobsQs>,
) -> Response {
    page(&p, async {
        let st = qs.state.as_deref().and_then(ExecState::parse);
        let rows = queries::jobs(
            &state,
            &p,
            &JobQuery {
                state: st,
                limit: 200,
                ..Default::default()
            },
        )
        .await?;
        html(flyw8t_web::jobs_page(&ctx(&p, None), rows, st))
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

fn clean_name(raw: Option<&str>) -> AppResult<String> {
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
        html(flyw8t_web::organization_page(
            &ctx(&p, flash(m.m.as_deref())),
            org,
            tokens,
            None,
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
        if let Some(s) = site {
            if !org.sites.iter().any(|x| x.id == s) {
                return Err(AppError::BadRequest("Unknown site.".into()));
            }
        }
        let secret = format!("{}{}", auth::ENROLL_PREFIX, auth::random_secret(32));
        let mut tx = state.db.begin().await?;
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
        let revealed = RevealedSecret {
            label: format!("Enrollment token for {}", org.name),
            hint: format!(
                "On the Windows device, as Administrator: flyw8t-agent enroll --server {} --token <token>, then flyw8t-agent service install. Valid for {ttl_minutes} minutes and {max_uses} device(s).",
                state.config.public_url
            ),
            secret,
        };
        let tokens = queries::enrollment_tokens(&state, id).await?;
        let mut resp = Html(flyw8t_web::organization_page(&ctx(&p, None), org, tokens, Some(revealed))).into_response();
        resp.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
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

pub async fn audit(State(state): State<Shared>, WebUser(p): WebUser) -> Response {
    page(&p, async {
        p.require(Permission::ViewAudit)?;
        html(flyw8t_web::audit_page(
            &ctx(&p, None),
            queries::audit(&state).await?,
        ))
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
    let mut resp = Html(flyw8t_web::admin_page(
        &ctx(p, flash(flash_code)),
        users,
        tokens,
        orgs,
        revealed.clone(),
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
        let mut scopes: Vec<String> = form.all("scope").into_iter().filter(|s| matches!(*s, "read" | "jobs:run")).map(String::from).collect();
        scopes.sort();
        scopes.dedup();
        if scopes.is_empty() {
            return Err(AppError::BadRequest("Choose at least one scope.".into()));
        }
        let days: i32 = form.get("ttl_days").and_then(|d| d.parse().ok()).filter(|d| (1..=365).contains(d)).unwrap_or(90);
        let body = auth::random_secret(32);
        let secret = format!("{}{body}", auth::TOKEN_PREFIX);
        let prefix: String = body.chars().take(8).collect();
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
        .fetch_one(&state.db)
        .await?;
        Audit::user(&p, "api_token.create").target("api_token", tid).detail(json!({ "name": name, "scopes": scopes, "days": days })).record(&state.db).await?;
        let revealed = RevealedSecret {
            label: format!("API token \"{name}\""),
            secret,
            hint: format!("Send as Authorization: Bearer <token> to {}/api/v1/. It acts as you, limited to: {}.", state.config.public_url, scopes.join(", ")),
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
