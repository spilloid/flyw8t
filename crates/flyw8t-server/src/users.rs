//! Managing a user after the account exists: name, role, organizations, disabling and enabling, a temporary
//! password; and a person changing their own password. Creating users is in `web.rs`; second factors are in `mfa.rs`.
//!
//! Every change here that an administrator makes needs sudo mode, locks the user's row and the administrator's
//! own, and is audited in the same transaction. Under those locks the administrator must still be one: enabled, an
//! administrator, signed in with the session that made the request, and in sudo mode. So a request already under
//! way when its caller is disabled, demoted or signed out does nothing, and the console never ends with no
//! administrator who can sign in: nobody changes their own role or disables themselves, and whoever changes
//! someone else is, under the lock, an enabled administrator who stays one.

use crate::audit::Audit;
use crate::auth::{self, Principal, Stage, WebUser};
use crate::error::{AppError, AppResult};
use crate::queries;
use crate::web::{check_csrf, clean_name, ctx, flash, page, to, Form, MsgQuery};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use flyw8t_domain::{Permission, Role};
use flyw8t_web::model::{RevealedSecret, UserDetail};
use serde_json::json;
use sqlx::PgConnection;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

/// Longer than any passphrase, short enough that hashing one costs nothing unusual.
const MAX_PASSWORD_LEN: usize = 1024;

/// The user being changed, read under lock.
struct Locked {
    email: String,
    role: Role,
    disabled: bool,
}

/// Lock the user's row and the caller's, in one fixed order, and check the caller as of now. Whoever asks second
/// waits, and then sees what the first one did: to the user, and to themselves.
async fn lock_user(tx: &mut PgConnection, p: &Principal, id: Uuid) -> AppResult<Locked> {
    let rows: Vec<(Uuid, String, String, bool)> = sqlx::query_as(
        "SELECT id, email, role, disabled_at IS NOT NULL FROM users
          WHERE id = $1 OR id = $2
          ORDER BY id FOR UPDATE",
    )
    .bind(id)
    .bind(p.user_id)
    .fetch_all(&mut *tx)
    .await?;
    let still_admin = rows
        .iter()
        .any(|(uid, _, role, disabled)| *uid == p.user_id && role == "admin" && !disabled);
    if !still_admin {
        return Err(AppError::Unauthorized);
    }
    auth::recheck_session(tx, p, true).await?;
    let (_, email, role, disabled) = rows
        .into_iter()
        .find(|(uid, ..)| *uid == id)
        .ok_or(AppError::NotFound)?;
    Ok(Locked {
        email,
        role: Role::parse(&role).ok_or_else(|| anyhow::anyhow!("unknown role {role:?}"))?,
        disabled,
    })
}

fn rank(role: Role) -> u8 {
    match role {
        Role::Admin => 2,
        Role::Technician => 1,
        Role::ReadOnly => 0,
    }
}

fn back(id: Uuid) -> String {
    format!("/admin/users/{id}")
}

/// Live attended-support sockets authenticated once, at their handshake: end the sessions this user started.
async fn end_support(state: &Shared, by: &Principal, user: Uuid, reason: &str) -> AppResult<()> {
    state.support.recheck_user(user);
    crate::support::end_all_created_by(
        state,
        user,
        &crate::support::Who::User(Box::new(by.clone())),
        reason,
    )
    .await?;
    Ok(())
}

async fn detail(state: &Shared, p: &Principal, id: Uuid) -> AppResult<UserDetail> {
    type Row = (
        String,
        String,
        String,
        Option<OffsetDateTime>,
        OffsetDateTime,
        Vec<Uuid>,
        bool,
        i64,
        i64,
        i64,
        Option<OffsetDateTime>,
        bool,
        i64,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT u.email, u.display_name, u.role, u.disabled_at, u.created_at,
                coalesce((SELECT array_agg(uo.organization_id) FROM user_organizations uo WHERE uo.user_id = u.id), '{}'),
                u.totp_enabled_at IS NOT NULL,
                (SELECT count(*) FROM webauthn_credentials w WHERE w.user_id = u.id),
                (SELECT count(*) FROM sessions s WHERE s.user_id = u.id AND s.revoked_at IS NULL AND s.expires_at > now()),
                (SELECT count(*) FROM api_tokens t WHERE t.user_id = u.id AND t.revoked_at IS NULL
                                                    AND (t.expires_at IS NULL OR t.expires_at > now())),
                u.password_changed_at, u.password_temporary,
                (SELECT count(*) FROM users a WHERE a.role = 'admin' AND a.disabled_at IS NULL AND a.id <> u.id)
           FROM users u WHERE u.id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let (
        email,
        display_name,
        role,
        disabled_at,
        created_at,
        organization_ids,
        mfa,
        passkeys,
        sessions,
        api_tokens,
        password_changed_at,
        password_temporary,
        other_admins,
    ) = row.ok_or(AppError::NotFound)?;
    Ok(UserDetail {
        id,
        only_admin: role == "admin" && disabled_at.is_none() && other_admins == 0,
        is_self: id == p.user_id,
        email,
        display_name,
        role,
        disabled_at,
        created_at,
        organization_ids,
        mfa,
        passkeys,
        sessions,
        api_tokens,
        password_changed_at,
        password_temporary,
        directory: sqlx::query_as::<_, (bool,)>(
            "SELECT EXISTS(SELECT 1 FROM directory_users WHERE user_id=$1)",
        )
        .bind(id)
        .fetch_one(&state.db)
        .await?
        .0,
    })
}

async fn view(
    state: &Shared,
    p: &Principal,
    id: Uuid,
    flash_code: Option<&str>,
    revealed: Option<RevealedSecret>,
) -> AppResult<Response> {
    p.require(Permission::ManageUsers)?;
    let user = detail(state, p, id).await?;
    let orgs = queries::org_refs(state, p).await?;
    let secret = revealed.is_some();
    let mut resp = Html(flyw8t_web::user_page(
        &ctx(p, flash(flash_code)),
        user,
        orgs,
        revealed,
    ))
    .into_response();
    if secret {
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    }
    Ok(resp)
}

pub async fn user_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    Query(m): Query<MsgQuery>,
) -> Response {
    page(&p, view(&state, &p, id, m.m.as_deref(), None)).await
}

/// Name, role and organizations. Lowering a role or taking an organization away also ends the support sessions the
/// user started: those were opened under the access they had.
pub async fn edit(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageUsers)?;
        p.require_sudo(&back(id))?;
        let name = clean_name(form.get("display_name"))?;
        let role = form
            .get("role")
            .and_then(Role::parse)
            .ok_or_else(|| AppError::BadRequest("Unknown role.".into()))?;
        let mut wanted: Vec<Uuid> = Vec::new();
        for o in form.all("org") {
            wanted.push(
                o.parse()
                    .map_err(|_| AppError::BadRequest("Unknown organization.".into()))?,
            );
        }
        wanted.sort();
        wanted.dedup();
        if role == Role::Admin {
            // Administrators span every organization; they hold no assignments.
            wanted.clear();
        }
        let mut tx = state.db.begin().await?;
        let u = lock_user(&mut tx, &p, id).await?;
        if crate::directory::is_directory(&mut tx,id).await? { return Err(AppError::Conflict("This account is managed by the directory. Change its group mapping or directory profile.".into())); }
        if id == p.user_id && role != u.role {
            return Err(AppError::BadRequest(
                "You cannot change your own role. Another administrator can.".into(),
            ));
        }
        let (known,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM organizations WHERE id = ANY($1)")
                .bind(&wanted)
                .fetch_one(&mut *tx)
                .await?;
        if known != wanted.len() as i64 {
            return Err(AppError::BadRequest("Unknown organization.".into()));
        }
        let before: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT organization_id FROM user_organizations WHERE user_id = $1 ORDER BY 1",
        )
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
        let before: Vec<Uuid> = before.into_iter().map(|r| r.0).collect();
        sqlx::query("UPDATE users SET display_name = $2, role = $3 WHERE id = $1")
            .bind(id)
            .bind(&name)
            .bind(role.as_str())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM user_organizations WHERE user_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO user_organizations (user_id, organization_id) SELECT $1, unnest($2::uuid[])",
        )
        .bind(id)
        .bind(&wanted)
        .execute(&mut *tx)
        .await?;
        let added: Vec<Uuid> = wanted
            .iter()
            .filter(|o| !before.contains(o))
            .copied()
            .collect();
        let removed: Vec<Uuid> = before
            .iter()
            .filter(|o| !wanted.contains(o))
            .copied()
            .collect();
        let narrowed = rank(role) < rank(u.role) || (role != Role::Admin && !removed.is_empty());
        // Enrollment tokens are authority handed out in advance. Judged by what the person may do now, not by
        // what was taken away (an administrator had no assignments to take): all of them stop if the new role may
        // not enroll, and otherwise those for organizations outside the new assignments.
        if role != Role::Admin {
            sqlx::query("UPDATE scim_credentials SET revoked_at=now() WHERE created_by=$1 AND revoked_at IS NULL").bind(id).execute(&mut *tx).await?;
        }
        let keeps_all = role == Role::Admin;
        let lost_all = !role.allows(Permission::ManageEnrollment);
        let enrollment_tokens = sqlx::query(
            "UPDATE enrollment_tokens SET revoked_at = now()
              WHERE created_by = $1 AND revoked_at IS NULL AND expires_at > now()
                AND NOT $4 AND ($2 OR NOT (organization_id = ANY($3)))",
        )
        .bind(id)
        .bind(lost_all)
        .bind(&wanted)
        .bind(keeps_all)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        Audit::user(&p, "user.update")
            .target("user", id)
            .detail(json!({
                "email": u.email,
                "role": { "from": u.role.as_str(), "to": role.as_str() },
                "organizations_added": added,
                "organizations_removed": removed,
                "enrollment_tokens_revoked": enrollment_tokens,
            }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        if narrowed {
            end_support(
                &state,
                &p,
                id,
                "technician's access changed by an administrator",
            )
            .await?;
        }
        to(format!("{}?m=user-updated", back(id)))
    })
    .await
}

/// Stop a person signing in or acting: every session ends, their API tokens and unspent enrollment tokens are
/// revoked, and the support sessions they started end. Jobs they already queued are not touched. Their history stays.
pub async fn disable(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require(Permission::ManageUsers)?;
        p.require_sudo(&back(id))?;
        if id == p.user_id {
            return Err(AppError::BadRequest(
                "You cannot disable your own account. Another administrator can.".into(),
            ));
        }
        let mut tx = state.db.begin().await?;
        let u = lock_user(&mut tx, &p, id).await?;
        let manual=sqlx::query("UPDATE directory_users SET directory_disabled=false WHERE user_id=$1 AND directory_disabled").bind(id).execute(&mut *tx).await?.rows_affected();
        if u.disabled {
            if manual>0 {Audit::user(&p,"user.disable").target("user",id).detail(json!({"manual_directory_disable":true})).record(&mut *tx).await?;}
            tx.commit().await?;
            return to(format!("{}?m=user-disabled", back(id)));
        }
        sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        auth::revoke_other_sessions(&mut tx, id, None).await?;
        sqlx::query("UPDATE scim_credentials SET revoked_at=now() WHERE created_by=$1 AND revoked_at IS NULL").bind(id).execute(&mut *tx).await?;
        let api_tokens = sqlx::query(
            "UPDATE api_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let enrollment_tokens = sqlx::query(
            "UPDATE enrollment_tokens SET revoked_at = now()
              WHERE created_by = $1 AND revoked_at IS NULL AND expires_at > now()",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        Audit::user(&p, "user.disable")
            .target("user", id)
            .detail(json!({
                "email": u.email,
                "api_tokens_revoked": api_tokens,
                "enrollment_tokens_revoked": enrollment_tokens,
            }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        end_support(
            &state,
            &p,
            id,
            "technician's account disabled by an administrator",
        )
        .await?;
        to(format!("{}?m=user-disabled", back(id)))
    })
    .await
}

/// Let a disabled person sign in again. Nothing that disabling revoked comes back.
pub async fn enable(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require(Permission::ManageUsers)?;
        p.require_sudo(&back(id))?;
        let mut tx = state.db.begin().await?;
        let u = lock_user(&mut tx, &p, id).await?;
        if crate::directory::is_directory(&mut tx,id).await? {
            let (allowed,):(bool,)=sqlx::query_as("SELECT d.active AND EXISTS(SELECT 1 FROM directory_mappings m WHERE m.issuer=d.issuer AND m.group_key=ANY(d.groups)) FROM directory_users d WHERE d.user_id=$1").bind(id).fetch_one(&mut *tx).await?;
            if !allowed {return Err(AppError::Conflict("Restore directory active status and a group mapping before enabling this account.".into()));}
        }
        if u.disabled {
            sqlx::query("UPDATE directory_users SET directory_disabled=false WHERE user_id=$1").bind(id).execute(&mut *tx).await?;
            sqlx::query("UPDATE users SET disabled_at = NULL WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            Audit::user(&p, "user.enable")
                .target("user", id)
                .detail(json!({ "email": u.email }))
                .record(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        to(format!("{}?m=user-enabled", back(id)))
    })
    .await
}

/// Replace a person's password with a temporary one the server makes up, shown once to the administrator. The person
/// is signed out everywhere; their second factor is untouched and still asked for.
pub async fn temporary_password(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require(Permission::ManageUsers)?;
        p.require_sudo(&back(id))?;
        if id == p.user_id {
            return Err(AppError::BadRequest(
                "Change your own password on your account page.".into(),
            ));
        }
        let secret = auth::random_secret(15);
        let hash = auth::hash_password(&secret)?;
        let mut tx = state.db.begin().await?;
        let u = lock_user(&mut tx, &p, id).await?;
        if crate::directory::is_directory(&mut tx,id).await? {return Err(AppError::Conflict("Directory accounts have no local password. Reset sign-in at the provider.".into()));}
        sqlx::query(
            "UPDATE users SET password_hash = $2, password_changed_at = now(), password_temporary = true WHERE id = $1",
        )
        .bind(id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
        auth::revoke_other_sessions(&mut tx, id, None).await?;
        Audit::user(&p, "user.password.reset")
            .target("user", id)
            .detail(json!({ "email": u.email }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        end_support(
            &state,
            &p,
            id,
            "technician signed out by an administrator",
        )
        .await?;
        let revealed = RevealedSecret {
            label: format!("Temporary password for {}", u.email),
            secret,
            hint: "Give it to them by a channel you trust. Their old password no longer works and they are signed out \
                   everywhere. Their account page asks them to choose their own; two-step verification is unchanged."
                .into(),
            commands: None,
        };
        view(&state, &p, id, None, Some(revealed)).await
    })
    .await
}

/// A person changes their own password: the current one is required, and every other session of theirs ends.
pub async fn change_password(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        let current = form.get("current").unwrap_or("");
        let new = form.get("new").unwrap_or("");
        let refuse = |msg: &'static str| crate::mfa::account_error(&state, &p, msg);
        let len = new.chars().count();
        if len < auth::MIN_PASSWORD_LEN {
            return refuse("Passwords must be at least 12 characters.").await;
        }
        if len > MAX_PASSWORD_LEN {
            return refuse("Passwords may be at most 1024 characters.").await;
        }
        if form.get("repeat") != Some(new) {
            return refuse("The two new passwords are not the same.").await;
        }
        if new == current {
            return refuse("The new password must differ from the current one.").await;
        }
        // A signed-in browser someone else is holding must not get to guess the password at leisure.
        if !state.limiter.allow(
            &format!("password-change:{}", p.user_id),
            5,
            Duration::from_secs(300),
        ) {
            return Err(AppError::RateLimited);
        }
        let hash = auth::hash_password(new)?;
        let mut tx = state.db.begin().await?;
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT password_hash FROM users WHERE id = $1 AND disabled_at IS NULL FOR UPDATE",
        )
        .bind(p.user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (stored,) = row.ok_or(AppError::Unauthorized)?;
        // The session that made this request must still be live now that the user is locked.
        if crate::directory::is_directory(&mut tx,p.user_id).await? {return Err(AppError::Conflict("Directory accounts have no local password. Change it at the provider.".into()));}
        let session = p.session_id.ok_or(AppError::Unauthorized)?;
        auth::lock_session(&mut tx, session, p.session_token.as_deref(), &[Stage::Full]).await?;
        if !auth::verify_password(&stored, current) {
            tx.rollback().await?;
            Audit::user(&p, "user.password.change")
                .denied()
                .record(&state.db)
                .await?;
            return refuse("That is not your current password.").await;
        }
        sqlx::query(
            "UPDATE users SET password_hash = $2, password_changed_at = now(), password_temporary = false WHERE id = $1",
        )
        .bind(p.user_id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
        auth::revoke_other_sessions(&mut tx, p.user_id, p.session_id).await?;
        Audit::user(&p, "user.password.change")
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        state.support.recheck_user(p.user_id);
        to("/account?m=password-changed")
    })
    .await
}
