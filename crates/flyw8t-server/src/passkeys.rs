//! Passkeys and security keys (WebAuthn), and sudo mode (ADR-0014 section 3).
//!
//! A user registers a credential from the account page. The first one needs the account password (and the current
//! code, when two-step verification is on), so a stolen session cookie cannot add a key; later ones, and removing one,
//! need sudo mode. Sudo mode is a fresh assertion with one of the user's credentials, and lasts [`SUDO`]. It guards
//! the changes that widen what can run or who can sign in: custom field definitions, users, API tokens and second-factor
//! resets. A signed-in session, a password or a TOTP code never stands in for it.
//!
//! Each ceremony uses a challenge held on the session, spent by the first answer whether or not it verifies.

use crate::audit::Audit;
use crate::auth::{self, Principal, Stage, WebUser};
use crate::error::{AppError, AppResult};
use crate::mfa;
use crate::web::{self, check_csrf, ctx, page, Form};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use flyw8t_protocol::webauthn::{self, b64url, from_b64url, Ceremony, Expected};
use flyw8t_web::model::{PasskeyNewView, SudoView, WebAuthnCeremony};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgConnection;
use std::time::Duration;
use uuid::Uuid;

/// How long sudo mode lasts after a passkey is confirmed.
pub const SUDO: Duration = Duration::from_secs(5 * 60);
/// How long a browser has to answer a challenge.
const CEREMONY: Duration = Duration::from_secs(5 * 60);
/// Credentials one user may register.
const MAX_PER_USER: i64 = 10;
/// CSP for the ceremony pages: the console's policy plus same-origin script (the WebAuthn calls).
const CEREMONY_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; manifest-src 'self'; \
     form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

fn rp(state: &Shared) -> AppResult<(String, String)> {
    let (origin, rp_id) = webauthn::origin_and_rp_id(&state.config.public_url)
        .ok_or_else(|| anyhow::anyhow!("FLYW8T_PUBLIC_URL has no usable origin"))?;
    if !webauthn::rp_id_usable(&rp_id) {
        return Err(AppError::Conflict(format!(
            "Passkeys need this console to be reached by a host name, and FLYW8T_PUBLIC_URL uses the address {rp_id}. \
             Ask the administrator to give it a name (localhost works on this machine)."
        )));
    }
    Ok((origin, rp_id))
}

/// A path on this site to return to: never another site, whatever was asked for.
pub fn local_path(next: Option<&str>) -> String {
    match next {
        Some(n)
            if n.starts_with('/')
                && !n.starts_with("//")
                && n.len() <= 512
                && !n.chars().any(|c| c == '\\' || c.is_control()) =>
        {
            n.to_string()
        }
        _ => "/".to_string(),
    }
}

fn ceremony_page(html: String) -> Response {
    let mut r = Html(html).into_response();
    r.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CEREMONY_CSP),
    );
    r
}

/// Start a ceremony: a fresh challenge on this session, replacing any other in flight.
async fn new_challenge(state: &Shared, p: &Principal, purpose: &str) -> AppResult<Vec<u8>> {
    let mut challenge = vec![0u8; 32];
    SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| anyhow::anyhow!("no randomness"))?;
    let session = p.session_id.ok_or(AppError::Unauthorized)?;
    let r = sqlx::query(
        "UPDATE sessions SET webauthn_challenge = $2, webauthn_purpose = $3,
                webauthn_expires_at = now() + make_interval(secs => $4)
          WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(session)
    .bind(&challenge)
    .bind(purpose)
    .bind(CEREMONY.as_secs_f64())
    .execute(&state.db)
    .await?;
    if r.rows_affected() != 1 {
        return Err(AppError::Unauthorized);
    }
    Ok(challenge)
}

/// Spend this session's challenge, under the session's lock. `None` if there was none for `purpose`, or it expired.
async fn take_challenge(
    tx: &mut PgConnection,
    p: &Principal,
    purpose: &str,
) -> AppResult<Option<Vec<u8>>> {
    let session = p.session_id.ok_or(AppError::Unauthorized)?;
    auth::lock_session(tx, session, p.session_token.as_deref(), &[Stage::Full]).await?;
    let row: (Option<Vec<u8>>, Option<String>, bool) = sqlx::query_as(
        "SELECT webauthn_challenge, webauthn_purpose, coalesce(webauthn_expires_at > now(), false)
           FROM sessions WHERE id = $1",
    )
    .bind(session)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE sessions SET webauthn_challenge = NULL, webauthn_purpose = NULL, webauthn_expires_at = NULL
          WHERE id = $1",
    )
    .bind(session)
    .execute(&mut *tx)
    .await?;
    Ok(match row {
        (Some(c), Some(p), true) if p == purpose => Some(c),
        _ => None,
    })
}

async fn credential_ids(state: &Shared, user: Uuid) -> AppResult<Vec<Vec<u8>>> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT credential_id FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

fn descriptors(ids: &[Vec<u8>]) -> serde_json::Value {
    ids.iter()
        .map(|id| json!({ "type": "public-key", "id": b64url(id) }))
        .collect()
}

// ---------------------------------------------------------------------------------------
// Registration

pub async fn new_form(State(state): State<Shared>, WebUser(p): WebUser) -> Response {
    page(&p, async { new_page(&state, &p, None).await }).await
}

async fn new_page(state: &Shared, p: &Principal, error: Option<String>) -> AppResult<Response> {
    let existing = credential_ids(state, p.user_id).await?;
    if !existing.is_empty() {
        p.require_sudo("/account/passkeys/new")?;
    }
    let (_, rp_id) = rp(state)?;
    let challenge = new_challenge(state, p, "register").await?;
    let totp: (bool,) = sqlx::query_as("SELECT totp_secret IS NOT NULL FROM users WHERE id = $1")
        .bind(p.user_id)
        .fetch_one(&state.db)
        .await?;
    let options = json!({
        "mode": "create",
        "publicKey": {
            "challenge": b64url(&challenge),
            "rp": { "id": rp_id, "name": "flyw8t" },
            "user": { "id": b64url(p.user_id.as_bytes()), "name": p.email, "displayName": p.display_name },
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "authenticatorSelection": { "residentKey": "preferred", "userVerification": "required" },
            "attestation": "none",
            "excludeCredentials": descriptors(&existing),
            "timeout": CEREMONY.as_millis() as u64,
        }
    });
    let status = if error.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    let html = flyw8t_web::passkey_new_page(
        &ctx(p, None),
        PasskeyNewView {
            ceremony: WebAuthnCeremony {
                action: "/account/passkeys".into(),
                options: options.to_string(),
                error,
            },
            needs_password: existing.is_empty(),
            needs_code: existing.is_empty() && totp.0,
        },
    );
    let mut r = ceremony_page(html);
    *r.status_mut() = status;
    Ok(r)
}

pub async fn register(State(state): State<Shared>, WebUser(p): WebUser, body: Bytes) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        let name = form.get("name").unwrap_or("").trim().to_string();
        let mut tx = state.db.begin().await?;
        // The user's lock first, as for every change to how they sign in (auth::lock_user_factor).
        let totp_secret = auth::lock_user_factor(&mut tx, p.user_id).await?;
        let (count,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1")
                .bind(p.user_id)
                .fetch_one(&mut *tx)
                .await?;
        if count > 0 {
            p.require_sudo("/account/passkeys/new")?;
        }
        let challenge = take_challenge(&mut tx, &p, "register").await?;
        // Ok(Err(..)): refused, with a message for the person; Err(..): something broke.
        let outcome: AppResult<Result<NewCredential, String>> = async {
            if count >= MAX_PER_USER {
                return Ok(Err("You already have as many passkeys as an account may hold. Remove one first.".into()));
            }
            if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
                return Ok(Err("Give the passkey a name of up to 100 characters, such as \"YubiKey on my keyring\".".into()));
            }
            if count == 0 {
                // The first key: the password, and the current code when two-step verification is on.
                if mfa::rate_limited(&state, p.user_id) {
                    return Err(AppError::RateLimited);
                }
                let (hash,): (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
                    .bind(p.user_id)
                    .fetch_one(&mut *tx)
                    .await?;
                if !auth::verify_password(&hash, form.get("password").unwrap_or("")) {
                    return Ok(Err("That password is not right.".into()));
                }
                if let Some(secret) = &totp_secret {
                    let code = form.get("code").unwrap_or("");
                    if mfa::spend_factor(&mut tx, p.user_id, secret, code, false).await?.is_none() {
                        return Ok(Err("That code is not valid, or was already used.".into()));
                    }
                }
            }
            let Some(challenge) = challenge else {
                return Ok(Err("That request expired. Try again.".into()));
            };
            let (origin, rp_id) = rp(&state)?;
            let field = |k: &str| form.get(k).and_then(from_b64url).unwrap_or_default();
            Ok(verify_registration(
                &field("attestation_object"),
                &field("client_data_json"),
                &Expected { ceremony: Ceremony::Create, challenge: &challenge, origin: &origin, rp_id: &rp_id },
            ))
        }
        .await;
        let cred = match outcome? {
            Ok(c) => c,
            Err(msg) => {
                tx.commit().await?;
                Audit::user(&p, "user.passkey.add").denied().record(&state.db).await?;
                return new_page(&state, &p, Some(msg)).await;
            }
        };
        let inserted: Option<(Uuid,)> = sqlx::query_as(
            "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, name, sign_count)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (credential_id) DO NOTHING RETURNING id",
        )
        .bind(p.user_id)
        .bind(&cred.id)
        .bind(&cred.public_key[..])
        .bind(&name)
        .bind(i64::from(cred.sign_count))
        .fetch_optional(&mut *tx)
        .await?;
        let Some((id,)) = inserted else {
            tx.commit().await?;
            return new_page(&state, &p, Some("That passkey is already registered.".into())).await;
        };
        Audit::user(&p, "user.passkey.add")
            .target("user", p.user_id)
            .detail(json!({ "passkey": id, "name": name }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        web::to("/account?m=passkey-added")
    })
    .await
}

pub async fn remove(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require_sudo("/account")?;
        let mut tx = state.db.begin().await?;
        auth::lock_user_factor(&mut tx, p.user_id).await?;
        let gone: Option<(String,)> = sqlx::query_as(
            "DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2 RETURNING name",
        )
        .bind(id)
        .bind(p.user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((name,)) = gone else {
            return Err(AppError::NotFound);
        };
        Audit::user(&p, "user.passkey.remove")
            .target("user", p.user_id)
            .detail(json!({ "passkey": id, "name": name }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        web::to("/account?m=passkey-removed")
    })
    .await
}

/// Every credential of a user, when an administrator resets their second factors.
pub async fn remove_all(db: &mut PgConnection, user: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM webauthn_credentials WHERE user_id = $1")
        .bind(user)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Sudo mode

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
}

pub async fn sudo_form(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(q): Query<NextQuery>,
) -> Response {
    page(&p, async {
        sudo_page(&state, &p, local_path(q.next.as_deref()), None).await
    })
    .await
}

async fn sudo_page(
    state: &Shared,
    p: &Principal,
    next: String,
    error: Option<String>,
) -> AppResult<Response> {
    let ids = credential_ids(state, p.user_id).await?;
    let ceremony = if ids.is_empty() {
        None
    } else {
        let (_, rp_id) = rp(state)?;
        let challenge = new_challenge(state, p, "sudo").await?;
        let options = json!({
            "mode": "get",
            "publicKey": {
                "challenge": b64url(&challenge),
                "rpId": rp_id,
                "allowCredentials": descriptors(&ids),
                "userVerification": "required",
                "timeout": CEREMONY.as_millis() as u64,
            }
        });
        Some(WebAuthnCeremony {
            action: "/sudo".into(),
            options: options.to_string(),
            error,
        })
    };
    let html = flyw8t_web::sudo_page(
        &ctx(p, None),
        SudoView {
            ceremony,
            next,
            minutes: SUDO.as_secs() / 60,
        },
    );
    Ok(ceremony_page(html))
}

pub async fn sudo(State(state): State<Shared>, WebUser(p): WebUser, body: Bytes) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        let next = local_path(form.get("next"));
        let field = |k: &str| form.get(k).and_then(from_b64url).unwrap_or_default();
        let credential = field("credential_id");
        let mut tx = state.db.begin().await?;
        auth::lock_user_factor(&mut tx, p.user_id).await?;
        let challenge = take_challenge(&mut tx, &p, "sudo").await?;
        let key: Option<(Uuid, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT id, public_key, sign_count FROM webauthn_credentials WHERE user_id = $1 AND credential_id = $2",
        )
        .bind(p.user_id)
        .bind(&credential)
        .fetch_optional(&mut *tx)
        .await?;
        let (origin, rp_id) = rp(&state)?;
        let outcome = match (&challenge, &key) {
            (None, _) => Err("That request expired. Try again.".to_string()),
            (_, None) => Err("That passkey is not one of yours here.".to_string()),
            (Some(challenge), Some((id, public_key, last))) => webauthn::verify_assertion(
                public_key,
                &Expected { ceremony: Ceremony::Get, challenge, origin: &origin, rp_id: &rp_id },
                &field("authenticator_data"),
                &field("client_data_json"),
                &field("signature"),
            )
            .map_err(|e| format!("Not confirmed: {e}."))
            .and_then(|a| counter_moved(*last, a.sign_count))
            .map(|count| (*id, count)),
        };
        let (id, count) = match outcome {
            Ok(v) => v,
            Err(msg) => {
                tx.commit().await?;
                Audit::user(&p, "user.sudo").denied().record(&state.db).await?;
                return sudo_page(&state, &p, next, Some(msg)).await;
            }
        };
        sqlx::query("UPDATE webauthn_credentials SET sign_count = $2, last_used_at = now() WHERE id = $1")
            .bind(id)
            .bind(i64::from(count))
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE sessions SET sudo_until = now() + make_interval(secs => $2) WHERE id = $1")
            .bind(p.session_id)
            .bind(SUDO.as_secs_f64())
            .execute(&mut *tx)
            .await?;
        Audit::user(&p, "user.sudo")
            .target("user", p.user_id)
            .detail(json!({ "passkey": id }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Redirect::to(&next).into_response())
    })
    .await
}

// ---------------------------------------------------------------------------------------
// Sign-in
//
// Usernameless: the browser offers the passkeys it holds for this console, and the credential it answers with names the
// person. A passkey that verifies its user (a PIN, a fingerprint or a device unlock) is two factors in one, so it signs
// straight in to a full session, past the TOTP code. It does not start sudo mode: that stays a separate, deliberate
// confirmation. The challenge is held against the browser's sign-in cookie, since there is no session yet.

/// Sign-in pages one address may open in five minutes (each stores a challenge).
const SIGN_IN_PAGES_PER_IP: u32 = 30;

pub async fn sign_in_form(
    State(state): State<Shared>,
    crate::client_ip::ClientIp(ip): crate::client_ip::ClientIp,
    headers: HeaderMap,
) -> Response {
    if let Ok(Some(_)) = auth::session_principal(&state, &headers).await {
        return Redirect::to("/").into_response();
    }
    let token = auth::login_cookie_value(&state, &headers).map(String::from);
    sign_in_page(&state, &ip, token, None, StatusCode::OK)
        .await
        .unwrap_or_else(|e| web::error_response(None, e))
}

/// The sign-in ceremony, under the browser's sign-in token (a new one when it has none, with its cookie).
async fn sign_in_page(
    state: &Shared,
    ip: &str,
    token: Option<String>,
    error: Option<String>,
    status: StatusCode,
) -> AppResult<Response> {
    let (_, rp_id) = rp(state)?;
    if !state.limiter.allow(
        &format!("passkey-sign-in:{ip}"),
        SIGN_IN_PAGES_PER_IP,
        Duration::from_secs(300),
    ) {
        return Err(AppError::RateLimited);
    }
    let (token, cookie) = match token {
        Some(t) => (t, None),
        None => {
            let t = auth::random_secret(24);
            let c = auth::set_login_cookie(state, &t);
            (t, Some(c))
        }
    };
    let mut challenge = vec![0u8; 32];
    SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| anyhow::anyhow!("no randomness"))?;
    sqlx::query("DELETE FROM webauthn_sign_in_challenges WHERE expires_at < now()")
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO webauthn_sign_in_challenges (login_hash, challenge, expires_at)
         VALUES ($1, $2, now() + make_interval(secs => $3))
         ON CONFLICT (login_hash) DO UPDATE SET challenge = excluded.challenge, expires_at = excluded.expires_at",
    )
    .bind(auth::digest(&token))
    .bind(&challenge)
    .bind(CEREMONY.as_secs_f64())
    .execute(&state.db)
    .await?;
    let options = json!({
        "mode": "get",
        "publicKey": {
            "challenge": b64url(&challenge),
            "rpId": rp_id,
            // Empty: the browser offers whichever of its passkeys belong to this console.
            "allowCredentials": [],
            "userVerification": "required",
            "timeout": CEREMONY.as_millis() as u64,
        }
    });
    let html = flyw8t_web::passkey_sign_in_page(
        WebAuthnCeremony {
            action: "/login/passkey".into(),
            options: options.to_string(),
            error,
        },
        &token,
    );
    let mut r = ceremony_page(html);
    *r.status_mut() = status;
    if let Some(c) = cookie {
        r.headers_mut().insert(
            header::SET_COOKIE,
            c.parse().map_err(|_| anyhow::anyhow!("cookie header"))?,
        );
    }
    Ok(r)
}

pub async fn sign_in(
    State(state): State<Shared>,
    crate::client_ip::ClientIp(ip): crate::client_ip::ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = Form::parse(&body);
    let result: AppResult<Response> = async {
        // Login CSRF, as for the password form: the ceremony form carries the sign-in token as its `csrf`.
        let token = auth::login_cookie_value(&state, &headers).map(String::from);
        let presented = form.get("csrf").unwrap_or("");
        let Some(token) = token.filter(|t| web::constant_time_eq(t.as_bytes(), presented.as_bytes())) else {
            return sign_in_page(
                &state,
                &ip,
                None,
                Some("This sign-in page had expired, or did not come from this console. Try again.".into()),
                StatusCode::FORBIDDEN,
            )
            .await;
        };
        if !state.limiter.allow(&format!("login-ip:{ip}"), 20, Duration::from_secs(300)) {
            return Err(AppError::RateLimited);
        }
        let (origin, rp_id) = rp(&state)?;
        let field = |k: &str| form.get(k).and_then(from_b64url).unwrap_or_default();
        let credential = field("credential_id");
        let mut tx = state.db.begin().await?;
        // Spent by this answer, right or wrong.
        let challenge: Option<(Vec<u8>, bool)> = sqlx::query_as(
            "DELETE FROM webauthn_sign_in_challenges WHERE login_hash = $1 RETURNING challenge, expires_at > now()",
        )
        .bind(auth::digest(&token))
        .fetch_optional(&mut *tx)
        .await?;
        let owner: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT c.user_id, u.email FROM webauthn_credentials c JOIN users u ON u.id = c.user_id WHERE c.credential_id = $1",
        )
        .bind(&credential)
        .fetch_optional(&mut *tx)
        .await?;
        // The user's lock, as for every check of how they sign in, so a reset that removes this key either happens
        // first (and the key is gone) or waits for this sign-in and then signs it out. A disabled account is refused.
        let key: Option<(Uuid, Uuid, String, Vec<u8>, i64)> = match &owner {
            Some((user, email)) if auth::lock_user_factor(&mut tx, *user).await.is_ok() => sqlx::query_as::<_, (Uuid, Vec<u8>, i64)>(
                "SELECT id, public_key, sign_count FROM webauthn_credentials WHERE credential_id = $1 AND user_id = $2",
            )
            .bind(&credential)
            .bind(user)
            .fetch_optional(&mut *tx)
            .await?
            .map(|(id, pk, n)| (id, *user, email.clone(), pk, n)),
            _ => None,
        };
        let outcome = match (&challenge, &key) {
            (None, _) | (Some((_, false)), _) => Err("That request expired. Try again.".to_string()),
            (_, None) => Err("That passkey cannot sign in here.".to_string()),
            (Some((challenge, true)), Some((_, _, _, public_key, last))) => webauthn::verify_assertion(
                public_key,
                &Expected { ceremony: Ceremony::Get, challenge, origin: &origin, rp_id: &rp_id },
                &field("authenticator_data"),
                &field("client_data_json"),
                &field("signature"),
            )
            .map_err(|e| format!("Not signed in: {e}."))
            .and_then(|a| counter_moved(*last, a.sign_count)),
        };
        let email = owner.as_ref().map(|o| o.1.clone()).unwrap_or_default();
        let audit = Audit::anonymous("web", email, "user.login").ip(&ip);
        let (count, id, user) = match (outcome, &key) {
            (Ok(count), Some((id, user, ..))) => (count, *id, *user),
            (outcome, _) => {
                let msg = outcome.err().unwrap_or_else(|| "That passkey cannot sign in here.".into());
                audit
                    .denied()
                    .detail(json!({ "method": "passkey", "reason": msg }))
                    .record(&mut *tx)
                    .await?;
                tx.commit().await?;
                return sign_in_page(&state, &ip, Some(token), Some(msg), StatusCode::UNAUTHORIZED).await;
            }
        };
        sqlx::query("UPDATE webauthn_credentials SET sign_count = $2, last_used_at = now() WHERE id = $1")
            .bind(id)
            .bind(i64::from(count))
            .execute(&mut *tx)
            .await?;
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let cookie = auth::create_session(&state, &mut tx, user, &ip, ua, Stage::Full).await?;
        audit
            .target("user", user)
            .detail(json!({ "method": "passkey", "passkey": id }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response())
    }
    .await;
    result.unwrap_or_else(|e| web::error_response(None, e))
}

/// An authenticator that keeps a counter must have moved it forward; one that went back may have been cloned. Synced
/// passkeys report 0 throughout, which says nothing either way.
fn counter_moved(last: i64, now: u32) -> Result<u32, String> {
    if (last > 0 || now > 0) && i64::from(now) <= last {
        Err("This passkey's signature counter went backwards, which can mean it was copied. Use another, or remove it.".into())
    } else {
        Ok(now)
    }
}

// ---------------------------------------------------------------------------------------
// Registration data: attestation object (CBOR) and the credential's COSE key

#[derive(Debug, PartialEq, Eq)]
pub struct NewCredential {
    pub id: Vec<u8>,
    pub public_key: [u8; webauthn::P256_KEY_LEN],
    pub sign_count: u32,
}

/// Check a registration and extract the credential. Attestation is not checked (the browser was asked for none): who
/// made the key does not matter here, only that this user holds it.
pub fn verify_registration(
    attestation_object: &[u8],
    client_data_json: &[u8],
    exp: &Expected,
) -> Result<NewCredential, String> {
    let bad = |what: &str| format!("Not added: {what}.");
    webauthn::check_client_data(client_data_json, exp).map_err(|e| bad(&e.to_string()))?;
    if attestation_object.len() > 64 * 1024 {
        return Err(bad("the browser's answer is too large"));
    }
    let mut r = Cbor::new(attestation_object);
    let map = r
        .map()
        .ok_or_else(|| bad("the browser's answer is not valid"))?;
    let auth_data = map
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Item::Text(k), Item::Bytes(v)) if k == "authData" => Some(v.clone()),
            _ => None,
        })
        .ok_or_else(|| bad("the browser's answer has no authenticator data"))?;
    if !r.done() {
        return Err(bad("the browser's answer is not valid"));
    }
    let head = webauthn::check_authenticator_data(&auth_data, exp.rp_id)
        .map_err(|e| bad(&e.to_string()))?;
    if head.flags & webauthn::FLAG_AT == 0 || auth_data.len() < 55 {
        return Err(bad("the key sent no credential"));
    }
    let id_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    if id_len == 0 || id_len > 1023 || auth_data.len() < 55 + id_len {
        return Err(bad("the credential is not valid"));
    }
    let id = auth_data[55..55 + id_len].to_vec();
    let mut k = Cbor::new(&auth_data[55 + id_len..]);
    let cose = k
        .map()
        .ok_or_else(|| bad("the credential's key is not valid"))?;
    // Extensions may follow the key; nothing else may.
    if head.flags & webauthn::FLAG_ED == 0 && !k.done() {
        return Err(bad("the credential is not valid"));
    }
    let int = |label: i64| {
        cose.iter().find_map(|(k, v)| match k {
            Item::Int(l) if *l == label => Some(v),
            _ => None,
        })
    };
    // kty 2 (EC2), alg -7 (ES256), crv 1 (P-256), x and y 32 bytes each.
    let es256 = matches!(int(1), Some(Item::Int(2)))
        && matches!(int(3), Some(Item::Int(-7)))
        && matches!(int(-1), Some(Item::Int(1)));
    let (Some(Item::Bytes(x)), Some(Item::Bytes(y))) = (int(-2), int(-3)) else {
        return Err(bad("only ES256 (P-256) keys are supported"));
    };
    if !es256 || x.len() != 32 || y.len() != 32 {
        return Err(bad("only ES256 (P-256) keys are supported"));
    }
    let mut public_key = [0u8; webauthn::P256_KEY_LEN];
    public_key[0] = 0x04;
    public_key[1..33].copy_from_slice(x);
    public_key[33..].copy_from_slice(y);
    Ok(NewCredential {
        id,
        public_key,
        sign_count: head.sign_count,
    })
}

/// The CBOR this needs: definite-length items only, as authenticators send them.
#[derive(Debug, Clone, PartialEq)]
enum Item {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Item>),
    Map(Vec<(Item, Item)>),
    Simple(u8),
}

struct Cbor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cbor<'a> {
    const MAX_DEPTH: usize = 8;

    fn new(data: &'a [u8]) -> Self {
        Cbor { data, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos == self.data.len()
    }

    fn map(&mut self) -> Option<Vec<(Item, Item)>> {
        match self.item(0)? {
            Item::Map(m) => Some(m),
            _ => None,
        }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn arg(&mut self, info: u8) -> Option<u64> {
        Some(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().ok()?)),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().ok()?)),
            27 => u64::from_be_bytes(self.take(8)?.try_into().ok()?),
            _ => return None, // indefinite lengths and reserved values
        })
    }

    fn item(&mut self, depth: usize) -> Option<Item> {
        if depth > Self::MAX_DEPTH {
            return None;
        }
        let b = self.take(1)?[0];
        let (major, info) = (b >> 5, b & 0x1f);
        let arg = self.arg(info)?;
        // No count can exceed the bytes left, so a hostile length cannot make us allocate.
        let left = (self.data.len() - self.pos) as u64;
        Some(match major {
            0 => Item::Int(i64::try_from(arg).ok()?),
            1 => Item::Int(-1 - i64::try_from(arg).ok()?),
            2 if arg <= left => Item::Bytes(self.take(arg as usize)?.to_vec()),
            3 if arg <= left => {
                Item::Text(String::from_utf8(self.take(arg as usize)?.to_vec()).ok()?)
            }
            4 if arg <= left => Item::Array(
                (0..arg)
                    .map(|_| self.item(depth + 1))
                    .collect::<Option<_>>()?,
            ),
            5 if arg <= left => Item::Map(
                (0..arg)
                    .map(|_| Some((self.item(depth + 1)?, self.item(depth + 1)?)))
                    .collect::<Option<_>>()?,
            ),
            7 if info < 24 => Item::Simple(info),
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_paths_are_returned_to() {
        assert_eq!(local_path(Some("/admin/fields")), "/admin/fields");
        assert_eq!(local_path(Some("/scripts/x?tab=1")), "/scripts/x?tab=1");
        for bad in [
            "//evil.example",
            "https://evil.example",
            "/\\evil.example",
            "admin",
            "",
            "/a\nb",
        ] {
            assert_eq!(local_path(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(local_path(None), "/");
    }

    #[test]
    fn counters_must_move_forward_unless_never_kept() {
        assert_eq!(counter_moved(0, 0), Ok(0));
        assert_eq!(counter_moved(5, 6), Ok(6));
        assert_eq!(counter_moved(0, 1), Ok(1));
        assert!(counter_moved(5, 5).is_err());
        assert!(counter_moved(5, 4).is_err());
        assert!(counter_moved(5, 0).is_err());
    }

    #[test]
    fn cbor_reads_what_authenticators_send_and_nothing_hostile() {
        // {"fmt": "none", "authData": h'0102'}
        let ok = [
            0xa2, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x68, b'a', b'u', b't',
            b'h', b'D', b'a', b't', b'a', 0x42, 1, 2,
        ];
        let mut r = Cbor::new(&ok);
        let m = r.map().unwrap();
        assert!(r.done());
        assert_eq!(
            m[1],
            (Item::Text("authData".into()), Item::Bytes(vec![1, 2]))
        );
        // Negative integers, as COSE labels use them.
        assert_eq!(Cbor::new(&[0x26]).item(0), Some(Item::Int(-7)));
        assert_eq!(Cbor::new(&[0x38, 0x18]).item(0), Some(Item::Int(-25)));
        // Lengths beyond the input, indefinite lengths, deep nesting, bad UTF-8, truncation.
        for bad in [
            &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
            &[0x9a, 0xff, 0xff, 0xff, 0xff],
            &[0x5f, 0x41, 0x00, 0xff],
            &[0x81; 20],
            &[0x62, 0xff, 0xfe],
            &[0xa1, 0x01],
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[],
        ] {
            assert_eq!(Cbor::new(bad).item(0), None, "{bad:x?}");
        }
    }
}
