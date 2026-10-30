//! Second factor for the web console: TOTP set-up, the sign-in challenge, recovery codes,
//! and an administrator's reset.
//!
//! A correct password yields a partial session (`auth::Stage::Mfa` or `Enroll`) that reaches
//! only these pages. Finishing the second factor promotes it under a new secret. Every code
//! check is counted against the session and rate-limited per user; every accepted TOTP step
//! is recorded so the same code cannot be used twice.

use crate::audit::Audit;
use crate::auth::{self, SessionInfo, Stage, WebUser};
use crate::error::{AppError, AppResult};
use crate::totp;
use crate::web::{self, check_csrf, constant_time_eq, ctx, page, to, Form, MsgQuery};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use flyw8t_domain::Permission;
use flyw8t_web::model::{AccountView, Flash, MfaSetupView};
use serde_json::json;
use sqlx::PgConnection;
use std::net::SocketAddr;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

/// Wrong codes a partial session may submit before it is revoked.
pub const MAX_ATTEMPTS: i32 = 5;
const ISSUER: &str = "flyw8t";

fn csrf_ok(s: &SessionInfo, form: &Form) -> bool {
    form.get("csrf")
        .is_some_and(|t| constant_time_eq(t.as_bytes(), s.csrf.as_bytes()))
}

fn rate_limited(state: &Shared, user: Uuid) -> bool {
    !state
        .limiter
        .allow(&format!("mfa-user:{user}"), 10, Duration::from_secs(300))
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    r
}

/// Count one attempt against a partial session. `false` once the limit is spent, in which
/// case the session has been revoked.
async fn spend_attempt(db: &mut PgConnection, session: Uuid) -> AppResult<bool> {
    let (n,): (i32,) = sqlx::query_as(
        "UPDATE sessions SET mfa_attempts = mfa_attempts + 1 WHERE id = $1 RETURNING mfa_attempts",
    )
    .bind(session)
    .fetch_one(&mut *db)
    .await?;
    if n > MAX_ATTEMPTS {
        sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1")
            .bind(session)
            .execute(&mut *db)
            .await?;
        return Ok(false);
    }
    Ok(true)
}

/// Which factor a submitted code satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Spent {
    Totp,
    Recovery,
}

/// Check `input` against the user's enrolled factor and spend it: a TOTP step only if it is
/// later than the last one accepted (atomic in the database), a recovery code only once.
async fn spend_factor(
    db: &mut PgConnection,
    user: Uuid,
    secret: &[u8],
    input: &str,
    allow_recovery: bool,
) -> AppResult<Option<Spent>> {
    if let Some(step) = totp::matching_step(secret, input, totp::now_step()) {
        let step = i64::try_from(step).map_err(|_| anyhow::anyhow!("TOTP step out of range"))?;
        let r = sqlx::query(
            "UPDATE users SET totp_last_step = $2
              WHERE id = $1 AND totp_secret IS NOT NULL AND (totp_last_step IS NULL OR totp_last_step < $2)",
        )
        .bind(user)
        .bind(step)
        .execute(&mut *db)
        .await?;
        return Ok((r.rows_affected() == 1).then_some(Spent::Totp));
    }
    if !allow_recovery {
        return Ok(None);
    }
    let Some(code) = totp::normalize_recovery(input) else {
        return Ok(None);
    };
    let r = sqlx::query(
        "UPDATE recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
    )
    .bind(user)
    .bind(auth::digest(&code))
    .execute(&mut *db)
    .await?;
    Ok((r.rows_affected() == 1).then_some(Spent::Recovery))
}

/// Replace a user's recovery codes; returns the new ones for display, once.
async fn issue_recovery_codes(db: &mut PgConnection, user: Uuid) -> AppResult<Vec<String>> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user)
        .execute(&mut *db)
        .await?;
    let codes: Vec<String> = (0..totp::RECOVERY_CODES)
        .map(|_| totp::new_recovery_code())
        .collect();
    for c in &codes {
        let canonical = totp::normalize_recovery(c).expect("generated codes are canonical");
        sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(user)
            .bind(auth::digest(&canonical))
            .execute(&mut *db)
            .await?;
    }
    Ok(codes)
}

fn group(secret_b32: &str) -> String {
    secret_b32
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------------------
// Sign-in challenge

pub async fn challenge_form(State(state): State<Shared>, headers: HeaderMap) -> Response {
    match auth::any_session(&state, &headers).await {
        Ok(Some(s)) if s.stage == Stage::Mfa => {
            Html(flyw8t_web::mfa_challenge_page(s.csrf, None)).into_response()
        }
        Ok(Some(s)) if s.stage == Stage::Full => Redirect::to("/").into_response(),
        Ok(_) => Redirect::to("/login").into_response(),
        Err(e) => web::error_response(None, e),
    }
}

pub async fn challenge(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let s = match auth::any_session(&state, &headers).await {
        Ok(Some(s)) if s.stage == Stage::Mfa => s,
        Ok(_) => return Redirect::to("/login").into_response(),
        Err(e) => return web::error_response(None, e),
    };
    let form = Form::parse(&body);
    if !csrf_ok(&s, &form) {
        return web::error_response(None, AppError::Forbidden);
    }
    let ip = peer.ip().to_string();
    let retry = |status: StatusCode, msg: &str| {
        (
            status,
            Html(flyw8t_web::mfa_challenge_page(
                s.csrf.clone(),
                Some(msg.into()),
            )),
        )
            .into_response()
    };
    if rate_limited(&state, s.user_id) {
        return retry(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Wait a few minutes.",
        );
    }
    let result: AppResult<Response> = async {
        let mut tx = state.db.begin().await?;
        // The factor as it is now (it may have been replaced since this request began), and
        // the session as it is now (it may have been revoked or promoted).
        let secret = auth::lock_user_factor(&mut tx, s.user_id).await?;
        let session_ok =
            auth::lock_session(&mut tx, s.session_id, Some(&s.token_hash), &[Stage::Mfa])
                .await
                .is_ok();
        let (Some(secret), true) = (secret, session_ok) else {
            return Ok(Redirect::to("/login").into_response());
        };
        let audit = Audit::anonymous("web", s.email.clone(), "user.login")
            .ip(&ip)
            .target("user", s.user_id);
        if !spend_attempt(&mut tx, s.session_id).await? {
            audit
                .denied()
                .detail(json!({ "reason": "too many codes" }))
                .record(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok((
                StatusCode::UNAUTHORIZED,
                Html(flyw8t_web::login_page(
                    Some("Too many incorrect codes. Sign in again.".into()),
                    false,
                    None,
                )),
            )
                .into_response());
        }
        let code = form.get("code").unwrap_or("");
        let Some(spent) = spend_factor(&mut tx, s.user_id, &secret, code, true).await? else {
            audit
                .denied()
                .detail(json!({ "reason": "wrong or reused code" }))
                .record(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(retry(
                StatusCode::UNAUTHORIZED,
                "That code is not valid, or was already used. Wait for the next one.",
            ));
        };
        let cookie = auth::promote_session(&state, &mut tx, s.session_id).await?;
        let method = match spent {
            Spent::Totp => "totp",
            Spent::Recovery => "recovery_code",
        };
        audit
            .detail(json!({ "second_factor": method }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response())
    }
    .await;
    result.unwrap_or_else(|e| web::error_response(None, e))
}

// ---------------------------------------------------------------------------------------
// Set-up

/// Set-up is open to an `Enroll` session (MFA required, not yet set up) and to a full
/// session without MFA. The pending secret belongs to this session alone.
async fn setup_session(state: &Shared, headers: &HeaderMap) -> AppResult<Option<SessionInfo>> {
    Ok(auth::any_session(state, headers)
        .await?
        .filter(|s| matches!(s.stage, Stage::Enroll | Stage::Full) && s.totp_secret.is_none()))
}

fn setup_view(s: &SessionInfo, secret: &[u8], error: Option<String>) -> MfaSetupView {
    MfaSetupView {
        csrf: s.csrf.clone(),
        email: s.email.clone(),
        secret: group(&totp::base32(secret)),
        otpauth_uri: totp::otpauth_uri(ISSUER, &s.email, secret),
        forced: s.stage == Stage::Enroll,
        error,
    }
}

pub async fn setup_form(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let result: AppResult<Response> = async {
        let Some(s) = setup_session(&state, &headers).await? else {
            return Ok(match auth::any_session(&state, &headers).await? {
                Some(s) if s.stage == Stage::Full => Redirect::to("/account").into_response(),
                _ => Redirect::to("/login").into_response(),
            });
        };
        let secret = match &s.pending_secret {
            Some(p) => p.clone(),
            None => {
                let fresh = totp::new_secret();
                sqlx::query("UPDATE sessions SET pending_totp_secret = $2 WHERE id = $1")
                    .bind(s.session_id)
                    .bind(&fresh)
                    .execute(&state.db)
                    .await?;
                fresh
            }
        };
        Ok(no_store(
            Html(flyw8t_web::mfa_setup_page(setup_view(&s, &secret, None))).into_response(),
        ))
    }
    .await;
    result.unwrap_or_else(|e| web::error_response(None, e))
}

pub async fn setup(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result: AppResult<Response> = async {
        let Some(s) = setup_session(&state, &headers).await? else {
            return Ok(Redirect::to("/login").into_response());
        };
        let form = Form::parse(&body);
        if !csrf_ok(&s, &form) {
            return Err(AppError::Forbidden);
        }
        let Some(secret) = s.pending_secret.clone() else {
            return Ok(Redirect::to("/account/mfa").into_response());
        };
        let again = |msg: &str| {
            no_store(
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Html(flyw8t_web::mfa_setup_page(setup_view(
                        &s,
                        &secret,
                        Some(msg.into()),
                    ))),
                )
                    .into_response(),
            )
        };
        if rate_limited(&state, s.user_id) {
            return Ok(again("Too many attempts. Wait a few minutes."));
        }
        let mut tx = state.db.begin().await?;
        if auth::lock_user_factor(&mut tx, s.user_id).await?.is_some() {
            return Err(AppError::Conflict(
                "Two-step verification is already on for this account.".into(),
            ));
        }
        // Still this session, still live, still holding the key this page showed.
        let locked = auth::lock_session(
            &mut tx,
            s.session_id,
            Some(&s.token_hash),
            &[Stage::Enroll, Stage::Full],
        )
        .await;
        if !matches!(&locked, Ok(Some(p)) if *p == secret) {
            return Ok(Redirect::to("/login").into_response());
        }
        if s.stage != Stage::Full && !spend_attempt(&mut tx, s.session_id).await? {
            tx.commit().await?;
            return Ok(Redirect::to("/login").into_response());
        }
        let Some(step) =
            totp::matching_step(&secret, form.get("code").unwrap_or(""), totp::now_step())
        else {
            tx.commit().await?;
            return Ok(again(
                "That code does not match. Check the app's clock and try the next code.",
            ));
        };
        let step = i64::try_from(step).map_err(|_| anyhow::anyhow!("TOTP step out of range"))?;
        let enabled = sqlx::query(
            "UPDATE users SET totp_secret = $2, totp_enabled_at = now(), totp_last_step = $3
              WHERE id = $1 AND totp_secret IS NULL",
        )
        .bind(s.user_id)
        .bind(&secret)
        .bind(step)
        .execute(&mut *tx)
        .await?;
        if enabled.rows_affected() != 1 {
            return Err(AppError::Conflict(
                "Two-step verification is already on for this account.".into(),
            ));
        }
        let codes = issue_recovery_codes(&mut tx, s.user_id).await?;
        // This session continues under a new secret; every other session was established
        // with the password alone and ends now.
        let cookie = auth::promote_session(&state, &mut tx, s.session_id).await?;
        auth::revoke_other_sessions(&mut tx, s.user_id, Some(s.session_id)).await?;
        if s.stage == Stage::Enroll {
            Audit::anonymous("web", s.email.clone(), "user.login")
                .ip(peer.ip().to_string())
                .target("user", s.user_id)
                .detail(json!({ "second_factor": "totp_enrolled" }))
                .record(&mut *tx)
                .await?;
        }
        Audit::anonymous("web", s.email.clone(), "user.mfa.enable")
            .ip(peer.ip().to_string())
            .target("user", s.user_id)
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        // Support sockets authenticated with a now-revoked session close as well.
        state.support.recheck_user(s.user_id);
        let next = if s.stage == Stage::Enroll {
            "/"
        } else {
            "/account"
        };
        let mut resp = no_store(Html(flyw8t_web::recovery_codes_page(codes, next)).into_response());
        resp.headers_mut().insert(
            header::SET_COOKIE,
            cookie
                .parse()
                .map_err(|_| anyhow::anyhow!("cookie header"))?,
        );
        Ok(resp)
    }
    .await;
    result.unwrap_or_else(|e| web::error_response(None, e))
}

// ---------------------------------------------------------------------------------------
// Account page (full sessions)

async fn account_view(state: &Shared, user: Uuid) -> AppResult<AccountView> {
    let (email, display_name, enabled_at, remaining): (String, String, Option<OffsetDateTime>, i64) =
        sqlx::query_as(
            "SELECT u.email, u.display_name, u.totp_enabled_at,
                    (SELECT count(*) FROM recovery_codes r WHERE r.user_id = u.id AND r.used_at IS NULL)
               FROM users u WHERE u.id = $1",
        )
        .bind(user)
        .fetch_one(&state.db)
        .await?;
    Ok(AccountView {
        email,
        display_name,
        mfa_enabled_at: enabled_at,
        recovery_remaining: remaining,
        require_mfa: state.config.require_mfa,
    })
}

pub async fn account(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, async {
        let v = account_view(&state, p.user_id).await?;
        web::html(flyw8t_web::account_page(
            &ctx(&p, web::flash(m.m.as_deref())),
            v,
        ))
    })
    .await
}

/// Re-render the account page with an error, for a wrong code on a full session.
async fn account_error(state: &Shared, p: &auth::Principal, msg: &str) -> AppResult<Response> {
    let v = account_view(state, p.user_id).await?;
    let flash = Flash {
        ok: false,
        message: msg.into(),
    };
    Ok((
        StatusCode::UNPROCESSABLE_ENTITY,
        Html(flyw8t_web::account_page(&ctx(p, Some(flash)), v)),
    )
        .into_response())
}

/// The current TOTP code, required before replacing recovery codes or turning MFA off.
async fn confirm_current(
    state: &Shared,
    tx: &mut PgConnection,
    p: &auth::Principal,
    form: &Form,
) -> AppResult<bool> {
    if rate_limited(state, p.user_id) {
        return Ok(false);
    }
    let secret = auth::lock_user_factor(tx, p.user_id).await?;
    // The session that made this request must still be live now that the user is locked.
    let session = p.session_id.ok_or(AppError::Unauthorized)?;
    auth::lock_session(tx, session, p.session_token.as_deref(), &[Stage::Full]).await?;
    let Some(secret) = secret else {
        return Err(AppError::Conflict(
            "Two-step verification is not on.".into(),
        ));
    };
    Ok(spend_factor(
        tx,
        p.user_id,
        &secret,
        form.get("code").unwrap_or(""),
        false,
    )
    .await?
    .is_some())
}

pub async fn regenerate_codes(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        let mut tx = state.db.begin().await?;
        if !confirm_current(&state, &mut tx, &p, &form).await? {
            tx.commit().await?;
            Audit::user(&p, "user.mfa.recovery_codes")
                .denied()
                .record(&state.db)
                .await?;
            return account_error(&state, &p, "That code is not valid, or was already used.").await;
        }
        let codes = issue_recovery_codes(&mut tx, p.user_id).await?;
        Audit::user(&p, "user.mfa.recovery_codes")
            .target("user", p.user_id)
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(no_store(
            Html(flyw8t_web::recovery_codes_page(
                codes,
                "/account?m=codes-regenerated",
            ))
            .into_response(),
        ))
    })
    .await
}

pub async fn disable(State(state): State<Shared>, WebUser(p): WebUser, body: Bytes) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        if state.config.require_mfa {
            return Err(AppError::Forbidden);
        }
        let mut tx = state.db.begin().await?;
        if !confirm_current(&state, &mut tx, &p, &form).await? {
            tx.commit().await?;
            Audit::user(&p, "user.mfa.disable")
                .denied()
                .record(&state.db)
                .await?;
            return account_error(&state, &p, "That code is not valid, or was already used.").await;
        }
        clear_mfa(&mut tx, p.user_id).await?;
        // As with set-up: this session continues under a new secret, every other one ends.
        let session = p.session_id.ok_or(AppError::Unauthorized)?;
        let cookie = auth::promote_session(&state, &mut tx, session).await?;
        auth::revoke_other_sessions(&mut tx, p.user_id, Some(session)).await?;
        Audit::user(&p, "user.mfa.disable")
            .target("user", p.user_id)
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        state.support.recheck_user(p.user_id);
        Ok((
            [(header::SET_COOKIE, cookie)],
            Redirect::to("/account?m=mfa-disabled"),
        )
            .into_response())
    })
    .await
}

async fn clear_mfa(db: &mut PgConnection, user: Uuid) -> AppResult<()> {
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL WHERE id = $1")
        .bind(user)
        .execute(&mut *db)
        .await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user)
        .execute(&mut *db)
        .await?;
    Ok(())
}

/// An administrator removes a user's second factor (lost device and codes). The user is
/// signed out everywhere and, when MFA is required, sets it up again at next sign-in.
pub async fn admin_reset(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require(Permission::ManageUsers)?;
        let mut tx = state.db.begin().await?;
        let email: Option<(String,)> =
            sqlx::query_as("SELECT email FROM users WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((email,)) = email else {
            return Err(AppError::NotFound);
        };
        clear_mfa(&mut tx, id).await?;
        auth::revoke_other_sessions(&mut tx, id, None).await?;
        Audit::user(&p, "user.mfa.reset")
            .target("user", id)
            .detail(json!({ "email": email }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        state.support.recheck_user(id);
        // "Signed out everywhere" includes live attended-support sockets, which authenticated
        // once at their handshake.
        crate::support::end_all_created_by(
            &state,
            id,
            &crate::support::Who::User(Box::new(p.clone())),
            "technician signed out by an administrator",
        )
        .await?;
        if id == p.user_id {
            return Ok(Redirect::to("/login").into_response());
        }
        to("/admin?m=mfa-reset")
    })
    .await
}
