//! Authentication for people and integrations.
//!
//! Two planes (STD-004): browser sessions (HttpOnly, SameSite=Strict cookie + per-session CSRF
//! token on every form) for the web console, and prefixed bearer tokens (`fw8_…`) for the JSON
//! API. The API accepts only bearer tokens, so it has no cookie-borne CSRF surface. Every
//! secret is random, shown once, and stored only as a SHA-256 digest.

use crate::error::{AppError, AppResult};
use crate::Shared;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use flyw8t_domain::{Permission, Role};
use ring::rand::SecureRandom;
use std::sync::OnceLock;
use uuid::Uuid;

pub const TOKEN_PREFIX: &str = "fw8_";
pub const ENROLL_PREFIX: &str = "fw8e_";
pub const MIN_PASSWORD_LEN: usize = 12;

/// URL-safe random secret with `bytes` of entropy.
pub fn random_secret(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .expect("system RNG");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

pub fn digest(secret: &str) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, secret.as_bytes())
        .as_ref()
        .to_vec()
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let mut salt = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| anyhow::anyhow!("RNG"))?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_string())
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}

/// Spend the same time on unknown users as on wrong passwords.
pub fn burn_password_check(password: &str) {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let h = DUMMY.get_or_init(|| hash_password("flyw8t-timing-equalizer").unwrap_or_default());
    let _ = verify_password(h, password);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Web,
    Api,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Web => "web",
            Channel::Api => "api",
        }
    }
}

/// An authenticated person (or a token acting for one).
#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: Role,
    /// Organizations assigned to a non-admin user. Ignored for admins.
    pub orgs: Vec<Uuid>,
    pub channel: Channel,
    /// Credential identifier for audit: `session:<id>` or `token:<prefix>`. Never the secret.
    pub credential: String,
    /// API token scopes; `None` for browser sessions.
    pub scopes: Option<Vec<String>>,
    pub csrf: String,
    pub session_id: Option<Uuid>,
    /// Digest of the presented session cookie, so a check made under lock can tell that this
    /// exact credential is still the session's (it changes on rotation). `None` for tokens.
    pub session_token: Option<Vec<u8>>,
}

impl Principal {
    /// Role permits it, and (for tokens) a scope permits it. Scopes only ever narrow.
    pub fn can(&self, p: Permission) -> bool {
        if !self.role.allows(p) {
            return false;
        }
        match &self.scopes {
            None => true,
            Some(scopes) => {
                let has = |s: &str| scopes.iter().any(|x| x == s);
                match p {
                    Permission::ViewDevices => has("read"),
                    Permission::RunDiagnostics | Permission::CancelJobs => has("jobs:run"),
                    // Administration is browser-only.
                    _ => false,
                }
            }
        }
    }

    pub fn require(&self, p: Permission) -> AppResult<()> {
        if self.can(p) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    pub fn sees_all(&self) -> bool {
        self.role.is_global()
    }

    pub fn can_see_org(&self, org: Uuid) -> bool {
        self.sees_all() || self.orgs.contains(&org)
    }

    /// Bind parameters for `($1 OR organization_id = ANY($2))` scoping.
    pub fn scope(&self) -> (bool, Vec<Uuid>) {
        (self.sees_all(), self.orgs.clone())
    }
}

type UserRow = (Uuid, String, String, String, Vec<Uuid>);

const USER_COLUMNS: &str = "u.id, u.email, u.display_name, u.role, \
     coalesce(array_agg(uo.organization_id) FILTER (WHERE uo.organization_id IS NOT NULL), '{}')";

fn principal(
    row: UserRow,
    channel: Channel,
    credential: String,
    scopes: Option<Vec<String>>,
    csrf: String,
    session_id: Option<Uuid>,
) -> AppResult<Principal> {
    let (user_id, email, display_name, role, orgs) = row;
    Ok(Principal {
        user_id,
        email,
        display_name,
        role: Role::parse(&role).ok_or_else(|| anyhow::anyhow!("bad role {role:?} in database"))?,
        orgs,
        channel,
        credential,
        scopes,
        csrf,
        session_id,
        session_token: None,
    })
}

pub fn cookie_name(state: &Shared) -> &'static str {
    if state.config.secure_cookies() {
        "__Host-flyw8t"
    } else {
        "flyw8t_session"
    }
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

pub async fn session_principal(
    state: &Shared,
    headers: &HeaderMap,
) -> AppResult<Option<Principal>> {
    let Some(raw) = cookie_value(headers, cookie_name(state)) else {
        return Ok(None);
    };
    let row: Option<(Uuid, String, Uuid, String, String, String, Vec<Uuid>)> = sqlx::query_as(&format!(
        "SELECT s.id, s.csrf_token, {USER_COLUMNS}
           FROM sessions s
           JOIN users u ON u.id = s.user_id
           LEFT JOIN user_organizations uo ON uo.user_id = u.id
          WHERE s.token_hash = $1 AND s.stage = 'full' AND s.revoked_at IS NULL AND s.expires_at > now()
            AND u.disabled_at IS NULL
          GROUP BY s.id, u.id"
    ))
    .bind(digest(raw))
    .fetch_optional(&state.db)
    .await?;
    let Some((sid, csrf, uid, email, name, role, orgs)) = row else {
        return Ok(None);
    };
    principal(
        (uid, email, name, role, orgs),
        Channel::Web,
        format!("session:{}", &sid.to_string()[..8]),
        None,
        csrf,
        Some(sid),
    )
    .map(|mut p| {
        p.session_token = Some(digest(raw));
        Some(p)
    })
}

/// Whether a browser session is still live and full, with this exact secret. Long-lived
/// connections (support sockets) call this to notice sign-out, revocation and rotation.
pub async fn session_still_valid(state: &Shared, session_id: Uuid, token: &[u8]) -> bool {
    sqlx::query_as::<_, (bool,)>(
        // The same conditions as `session_principal`, including an account that is still
        // enabled: anything that would refuse the next page load refuses the socket too.
        "SELECT EXISTS (SELECT 1 FROM sessions s JOIN users u ON u.id = s.user_id
                         WHERE s.id = $1 AND s.token_hash = $2 AND s.stage = 'full'
                           AND s.revoked_at IS NULL AND s.expires_at > now() AND u.disabled_at IS NULL)",
    )
    .bind(session_id)
    .bind(token)
    .fetch_one(&state.db)
    .await
    .is_ok_and(|r| r.0)
}

pub async fn token_principal(state: &Shared, headers: &HeaderMap) -> AppResult<Option<Principal>> {
    let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Ok(None);
    };
    let token = auth
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| t.starts_with(TOKEN_PREFIX))
        .ok_or(AppError::Unauthorized)?;
    let row: Option<(
        Uuid,
        String,
        Vec<String>,
        Uuid,
        String,
        String,
        String,
        Vec<Uuid>,
    )> = sqlx::query_as(&format!(
        "SELECT t.id, t.prefix, t.scopes, {USER_COLUMNS}
           FROM api_tokens t
           JOIN users u ON u.id = t.user_id
           LEFT JOIN user_organizations uo ON uo.user_id = u.id
          WHERE t.token_hash = $1 AND t.revoked_at IS NULL
            AND (t.expires_at IS NULL OR t.expires_at > now()) AND u.disabled_at IS NULL
          GROUP BY t.id, u.id"
    ))
    .bind(digest(token))
    .fetch_optional(&state.db)
    .await?;
    let Some((tid, prefix, scopes, uid, email, name, role, orgs)) = row else {
        return Err(AppError::Unauthorized);
    };
    sqlx::query("UPDATE api_tokens SET last_used_at = now() WHERE id = $1")
        .bind(tid)
        .execute(&state.db)
        .await?;
    principal(
        (uid, email, name, role, orgs),
        Channel::Api,
        format!("token:{prefix}"),
        Some(scopes),
        String::new(),
        None,
    )
    .map(Some)
}

/// How far a browser session has got through sign-in. Only `Full` reaches the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Password accepted; a second-factor code is owed.
    Mfa,
    /// Password accepted; MFA is required and this user must set it up first.
    Enroll,
    Full,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Mfa => "mfa",
            Stage::Enroll => "enroll",
            Stage::Full => "full",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "mfa" => Some(Stage::Mfa),
            "enroll" => Some(Stage::Enroll),
            "full" => Some(Stage::Full),
            _ => None,
        }
    }
}

/// A password-only session lives this long before the second factor must be finished.
pub const PARTIAL_SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Create a browser session; returns the `Set-Cookie` header value. The caller decides the
/// stage while holding the user row (see `web::login`), so the decision cannot interleave
/// with a second factor being set up.
pub async fn create_session(
    state: &Shared,
    exec: &mut sqlx::PgConnection,
    user_id: Uuid,
    ip: &str,
    user_agent: &str,
    stage: Stage,
) -> AppResult<String> {
    let secret = random_secret(32);
    let ttl = match stage {
        Stage::Full => state.config.session_ttl,
        Stage::Mfa | Stage::Enroll => PARTIAL_SESSION_TTL,
    };
    sqlx::query(
        "INSERT INTO sessions (user_id, token_hash, csrf_token, expires_at, client_ip, user_agent, stage)
         VALUES ($1, $2, $3, now() + make_interval(secs => $4), $5, $6, $7)",
    )
    .bind(user_id)
    .bind(digest(&secret))
    .bind(random_secret(24))
    .bind(ttl.as_secs_f64())
    .bind(ip)
    .bind(user_agent.chars().take(300).collect::<String>())
    .bind(stage.as_str())
    .execute(exec)
    .await?;
    Ok(set_cookie(state, &secret, ttl.as_secs()))
}

/// Promote a session to a full one under a new secret and CSRF token, so a token seen
/// before the second factor is worthless after it. Returns the `Set-Cookie` value. Fails
/// if the session was revoked meanwhile; callers hold its row lock (`lock_session`).
pub async fn promote_session(
    state: &Shared,
    exec: &mut sqlx::PgConnection,
    session_id: Uuid,
) -> AppResult<String> {
    let secret = random_secret(32);
    let ttl = state.config.session_ttl;
    let r = sqlx::query(
        "UPDATE sessions SET token_hash = $2, csrf_token = $3, stage = 'full', pending_totp_secret = NULL,
                mfa_attempts = 0, expires_at = now() + make_interval(secs => $4)
          WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .bind(digest(&secret))
    .bind(random_secret(24))
    .bind(ttl.as_secs_f64())
    .execute(exec)
    .await?;
    if r.rows_affected() != 1 {
        return Err(AppError::Unauthorized);
    }
    Ok(set_cookie(state, &secret, ttl.as_secs()))
}

/// Lock a user's row and read their current TOTP secret. Every change to a user's second
/// factor, and every check of one, takes this lock first (then any session lock), so a check
/// always sees the factor as it is now, never one replaced while the request was in flight.
pub async fn lock_user_factor(
    exec: &mut sqlx::PgConnection,
    user_id: Uuid,
) -> AppResult<Option<Vec<u8>>> {
    let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
        "SELECT totp_secret FROM users WHERE id = $1 AND disabled_at IS NULL FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(exec)
    .await?;
    row.map(|r| r.0).ok_or(AppError::Unauthorized)
}

/// Re-check, under its row lock, that the session this request presented is still live, at
/// one of `stages`, and still holds the same secret. Returns its pending TOTP secret.
pub async fn lock_session(
    exec: &mut sqlx::PgConnection,
    session_id: Uuid,
    token_hash: Option<&[u8]>,
    stages: &[Stage],
) -> AppResult<Option<Vec<u8>>> {
    let row: Option<(String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT stage, pending_totp_secret FROM sessions
          WHERE id = $1 AND ($2::bytea IS NULL OR token_hash = $2)
            AND revoked_at IS NULL AND expires_at > now()
          FOR UPDATE",
    )
    .bind(session_id)
    .bind(token_hash)
    .fetch_optional(exec)
    .await?;
    match row {
        Some((stage, pending)) if Stage::parse(&stage).is_some_and(|s| stages.contains(&s)) => {
            Ok(pending)
        }
        _ => Err(AppError::Unauthorized),
    }
}

/// Sign a user out everywhere except `keep`: after their second factor changes, no session
/// established under the old arrangement survives.
pub async fn revoke_other_sessions(
    exec: &mut sqlx::PgConnection,
    user_id: Uuid,
    keep: Option<Uuid>,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE sessions SET revoked_at = now()
          WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2)",
    )
    .bind(user_id)
    .bind(keep)
    .execute(exec)
    .await?;
    Ok(())
}

/// Any live session, at any stage, with what the second-factor pages need.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: Uuid,
    /// Digest of the presented cookie, to re-check the session under lock.
    pub token_hash: Vec<u8>,
    pub stage: Stage,
    pub csrf: String,
    pub user_id: Uuid,
    pub email: String,
    pub pending_secret: Option<Vec<u8>>,
    pub totp_secret: Option<Vec<u8>>,
}

pub async fn any_session(state: &Shared, headers: &HeaderMap) -> AppResult<Option<SessionInfo>> {
    let Some(raw) = cookie_value(headers, cookie_name(state)) else {
        return Ok(None);
    };
    type Row = (
        Uuid,
        String,
        String,
        Uuid,
        String,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT s.id, s.stage, s.csrf_token, u.id, u.email, s.pending_totp_secret, u.totp_secret
           FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
            AND u.disabled_at IS NULL",
    )
    .bind(digest(raw))
    .fetch_optional(&state.db)
    .await?;
    let Some((session_id, stage, csrf, user_id, email, pending_secret, totp_secret)) = row else {
        return Ok(None);
    };
    Ok(Some(SessionInfo {
        session_id,
        token_hash: digest(raw),
        stage: Stage::parse(&stage)
            .ok_or_else(|| anyhow::anyhow!("bad session stage {stage:?}"))?,
        csrf,
        user_id,
        email,
        pending_secret,
        totp_secret,
    }))
}

pub fn set_cookie(state: &Shared, value: &str, max_age: u64) -> String {
    let secure = if state.config.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
        cookie_name(state)
    )
}

/// The browser-session extractor. Redirects to the sign-in page when absent.
pub struct WebUser(pub Principal);

impl FromRequestParts<Shared> for WebUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> Result<Self, Self::Rejection> {
        match session_principal(state, &parts.headers).await {
            Ok(Some(p)) => Ok(WebUser(p)),
            Ok(None) => Err(Redirect::to("/login").into_response()),
            Err(e) => Err(crate::web::error_response(None, e)),
        }
    }
}

/// The API extractor: bearer tokens only.
pub struct ApiUser(pub Principal);

impl FromRequestParts<Shared> for ApiUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> Result<Self, Self::Rejection> {
        match token_principal(state, &parts.headers).await? {
            Some(p) => Ok(ApiUser(p)),
            None => Err(AppError::Unauthorized),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_hash_and_verify() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(verify_password(&h, "correct horse battery"));
        assert!(!verify_password(&h, "wrong"));
        assert!(!verify_password("not a hash", "x"));
    }

    #[test]
    fn secrets_are_unique_and_urlsafe() {
        let a = random_secret(32);
        assert_ne!(a, random_secret(32));
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_eq!(a.len(), 43);
    }

    fn p(role: Role, scopes: Option<Vec<&str>>) -> Principal {
        Principal {
            user_id: Uuid::nil(),
            email: String::new(),
            display_name: String::new(),
            role,
            orgs: vec![],
            channel: Channel::Api,
            credential: String::new(),
            scopes: scopes.map(|s| s.into_iter().map(String::from).collect()),
            csrf: String::new(),
            session_id: None,
            session_token: None,
        }
    }

    #[test]
    fn token_scopes_only_narrow() {
        // An admin's read-only token cannot run jobs or administer.
        let t = p(Role::Admin, Some(vec!["read"]));
        assert!(t.can(Permission::ViewDevices));
        assert!(!t.can(Permission::RunDiagnostics));
        assert!(!t.can(Permission::ManageUsers));
        // A jobs:run scope cannot lift a read-only user above their role.
        let t = p(Role::ReadOnly, Some(vec!["read", "jobs:run"]));
        assert!(!t.can(Permission::RunDiagnostics));
        // No token can administer, whatever the role.
        let t = p(Role::Admin, Some(vec!["read", "jobs:run"]));
        assert!(!t.can(Permission::ManageEnrollment));
        assert!(!t.can(Permission::ViewAudit));
    }
}
