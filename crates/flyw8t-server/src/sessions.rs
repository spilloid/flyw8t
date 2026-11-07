//! Where a person is signed in: their own session list with sign-out per session, and an
//! administrator's "sign out everywhere" for anyone. Signing out only ever takes access away,
//! so none of it needs sudo mode: someone who finds an account in use where it should not be
//! must be able to end that at once.

use crate::audit::Audit;
use crate::auth::{self, Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::web::{check_csrf, page, to, Form};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use flyw8t_domain::Permission;
use flyw8t_web::model::SessionRow;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

/// The person's live sessions, most recently used first. Partial ones (password accepted,
/// second factor owed) are listed too: one the person did not start means their password is known.
pub async fn list(state: &Shared, user: Uuid, current: Option<Uuid>) -> AppResult<Vec<SessionRow>> {
    let rows: Vec<(
        Uuid,
        String,
        OffsetDateTime,
        OffsetDateTime,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, stage, created_at, last_seen_at, client_ip, user_agent FROM sessions
              WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
              ORDER BY last_seen_at DESC LIMIT 50",
    )
    .bind(user)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, stage, created_at, last_seen_at, ip, ua)| SessionRow {
            id,
            current: Some(id) == current,
            partial: stage != "full",
            created_at,
            last_seen_at,
            client_ip: ip.unwrap_or_default(),
            user_agent: ua.unwrap_or_default(),
        })
        .collect())
}

/// Signed out: clear the cookie and go to sign in.
fn signed_out(state: &Shared) -> Response {
    (
        [(header::SET_COOKIE, auth::set_cookie(state, "", 0))],
        Redirect::to("/login"),
    )
        .into_response()
}

/// Sign out one of your own sessions (this one included).
pub async fn revoke(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        let mut tx = state.db.begin().await?;
        let n = sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(id)
        .bind(p.user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        // Someone else's session is as unknown here as one that does not exist.
        if n == 0 {
            return Err(AppError::NotFound);
        }
        Audit::user(&p, "user.session.revoke")
            .target("session", id)
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        // Support sockets opened from that session notice it is gone.
        state.support.recheck_user(p.user_id);
        if Some(id) == p.session_id {
            return Ok(signed_out(&state));
        }
        to("/account?m=session-revoked")
    })
    .await
}

/// Sign out every session of yours except this one.
pub async fn revoke_others(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        let mut tx = state.db.begin().await?;
        let n = revoke_all(&mut tx, p.user_id, p.session_id).await?;
        Audit::user(&p, "user.session.revoke_others")
            .detail(json!({ "sessions": n }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        state.support.recheck_user(p.user_id);
        to("/account?m=sessions-revoked")
    })
    .await
}

/// An administrator signs a user out of every session, partial ones included, and ends the
/// attended-support sessions they started (those sockets authenticated once, at their handshake).
pub async fn admin_sign_out(
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
        let (email,) = email.ok_or(AppError::NotFound)?;
        let n = revoke_all(&mut tx, id, None).await?;
        Audit::user(&p, "user.sessions.revoke")
            .target("user", id)
            .detail(json!({ "email": email, "sessions": n }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        end_support(&state, &p, id).await?;
        if id == p.user_id {
            return Ok(signed_out(&state));
        }
        to("/admin?m=user-signed-out")
    })
    .await
}

async fn revoke_all(tx: &mut sqlx::PgConnection, user: Uuid, keep: Option<Uuid>) -> AppResult<u64> {
    Ok(sqlx::query(
        "UPDATE sessions SET revoked_at = now()
          WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2)",
    )
    .bind(user)
    .bind(keep)
    .execute(tx)
    .await?
    .rows_affected())
}

async fn end_support(state: &Shared, by: &Principal, user: Uuid) -> AppResult<()> {
    state.support.recheck_user(user);
    crate::support::end_all_created_by(
        state,
        user,
        &crate::support::Who::User(Box::new(by.clone())),
        "technician signed out by an administrator",
    )
    .await?;
    Ok(())
}
