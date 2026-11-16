//! Directory identity and the single reconciliation path for sign-in, SCIM and mappings.
use crate::audit::Audit;
use crate::auth::{self, Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::web::{check_csrf, clean_name, ctx, page, to, Form};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Response};
use flyw8t_domain::{Permission, Role};
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

pub fn issuer(state: &Shared) -> AppResult<&str> {
    state
        .config
        .oidc
        .as_ref()
        .map(|o| o.issuer.as_str())
        .ok_or(AppError::NotFound)
}

/// Directory mutations share this lock, then the existing global user-row order. Read state
/// in a subsequent statement: SELECT FOR UPDATE may have waited on an older snapshot.
pub async fn lock_all(tx: &mut PgConnection) -> AppResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(7146291730017)")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM users ORDER BY id FOR UPDATE")
        .fetch_all(&mut *tx)
        .await?;
    Ok(())
}

pub async fn is_directory(tx: &mut PgConnection, user: Uuid) -> AppResult<bool> {
    Ok(sqlx::query_as::<_, (bool,)>(
        "SELECT EXISTS(SELECT 1 FROM directory_users WHERE user_id = $1)",
    )
    .bind(user)
    .fetch_one(tx)
    .await?
    .0)
}

pub async fn ensure_identity(
    tx: &mut PgConnection,
    issuer: &str,
    subject: &str,
    email: &str,
    name: &str,
    managed: bool,
) -> AppResult<Uuid> {
    if subject.is_empty() || subject.len() > 255 || subject.chars().any(char::is_control) {
        return Err(AppError::BadRequest(
            "Directory subject must be 1 to 255 bytes.".into(),
        ));
    }
    let email = email.trim().to_lowercase();
    if email.len() > 254
        || !email.contains('@')
        || email.starts_with('@')
        || email.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(AppError::BadRequest(
            "A usable directory email is required.".into(),
        ));
    }
    let name = clean_name(Some(name))?;
    let existing: Option<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM directory_users WHERE issuer = $1 AND subject = $2")
            .bind(issuer)
            .bind(subject)
            .fetch_optional(&mut *tx)
            .await?;
    let collision: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await?;
    if collision.is_some() && collision != existing {
        return Err(AppError::Conflict("This email belongs to another identity. Use a separate local break-glass address; accounts are never linked by email.".into()));
    }
    let id = if let Some((id,)) = existing {
        sqlx::query("UPDATE users SET email = $2, display_name = $3 WHERE id = $1")
            .bind(id)
            .bind(email)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        if managed {
            sqlx::query("UPDATE directory_users SET managed = true WHERE user_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        id
    } else {
        let (admin,): (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM users WHERE role='admin' AND disabled_at IS NULL)",
        )
        .fetch_one(&mut *tx)
        .await?;
        if !admin {
            return Err(AppError::Conflict("Configure an enabled bootstrap administrator before provisioning directory accounts.".into()));
        }
        let (id,): (Uuid,) = sqlx::query_as("INSERT INTO users(email,display_name,password_hash,role,disabled_at) VALUES ($1,$2,'!directory-only','readonly',now()) RETURNING id")
            .bind(email).bind(name).fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO directory_users(user_id,issuer,subject,managed,directory_disabled) VALUES ($1,$2,$3,$4,true)")
            .bind(id).bind(issuer).bind(subject).bind(managed).execute(&mut *tx).await?;
        Audit::system("directory.user.create")
            .target("user", id)
            .record(&mut *tx)
            .await?;
        id
    };
    Ok(id)
}

fn rank(role: Role) -> u8 {
    match role {
        Role::Admin => 2,
        Role::Technician => 1,
        Role::ReadOnly => 0,
    }
}

/// Caller holds lock_all. Returns whether long-lived support must be ended after commit.
pub async fn reconcile(tx: &mut PgConnection, user: Uuid) -> AppResult<bool> {
    let (issuer, active, groups, directory_disabled, old_role, disabled): (String,bool,Vec<String>,bool,String,bool) = sqlx::query_as(
        "SELECT d.issuer,d.active,d.groups,d.directory_disabled,u.role,u.disabled_at IS NOT NULL FROM directory_users d JOIN users u ON u.id=d.user_id WHERE d.user_id=$1")
        .bind(user).fetch_one(&mut *tx).await?;
    let mappings: Vec<(String,Vec<Uuid>)> = sqlx::query_as("SELECT role,organization_ids FROM directory_mappings WHERE issuer=$1 AND group_key=ANY($2)")
        .bind(issuer).bind(groups).fetch_all(&mut *tx).await?;
    let mapped = !mappings.is_empty();
    let role = mappings
        .iter()
        .filter_map(|(r, _)| Role::parse(r))
        .max_by_key(|r| rank(*r))
        .unwrap_or(Role::ReadOnly);
    let mut organizations: Vec<Uuid> = mappings.into_iter().flat_map(|(_, o)| o).collect();
    organizations.sort();
    organizations.dedup();
    if role == Role::Admin {
        organizations.clear();
    }
    // A separate administrator disable stays disabled when directory access returns.
    let manually_disabled = disabled && !directory_disabled;
    let enabled = active && mapped && !manually_disabled;
    let old_organizations: Vec<(Uuid,)> =
        sqlx::query_as("SELECT organization_id FROM user_organizations WHERE user_id=$1")
            .bind(user)
            .fetch_all(&mut *tx)
            .await?;
    let old_role = Role::parse(&old_role).ok_or_else(|| anyhow::anyhow!("invalid stored role"))?;
    if old_role == Role::Admin && !disabled && (!enabled || role != Role::Admin) {
        let (others,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM users WHERE role='admin' AND disabled_at IS NULL AND id<>$1",
        )
        .bind(user)
        .fetch_one(&mut *tx)
        .await?;
        if others == 0 {
            return Err(AppError::Conflict("Directory change would remove the last enabled administrator. Restore a local break-glass administrator first.".into()));
        }
    }
    let narrowed = (!disabled && !enabled)
        || rank(role) < rank(old_role)
        || (role != Role::Admin
            && old_organizations
                .iter()
                .any(|(o,)| !organizations.contains(o)));
    sqlx::query("UPDATE users SET role=$2, disabled_at=CASE WHEN $3 THEN NULL ELSE coalesce(disabled_at,now()) END WHERE id=$1")
        .bind(user).bind(role.as_str()).bind(enabled).execute(&mut *tx).await?;
    sqlx::query("UPDATE directory_users SET directory_disabled=$2 WHERE user_id=$1")
        .bind(user)
        .bind(!enabled && !manually_disabled)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM user_organizations WHERE user_id=$1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO user_organizations(user_id,organization_id) SELECT $1,unnest($2::uuid[])",
    )
    .bind(user)
    .bind(&organizations)
    .execute(&mut *tx)
    .await?;
    if narrowed {
        revoke_authority(tx, user).await?;
    }
    if narrowed || role != old_role || enabled == disabled {
        Audit::system("directory.user.reconcile").target("user",user)
            .detail(json!({"role":role.as_str(),"enabled":enabled,"organizations":organizations,"credentials_revoked":narrowed}))
            .record(&mut *tx).await?;
    }
    Ok(narrowed)
}

pub async fn revoke_authority(tx: &mut PgConnection, user: Uuid) -> AppResult<()> {
    auth::revoke_other_sessions(tx, user, None).await?;
    sqlx::query(
        "UPDATE scim_credentials SET revoked_at=now() WHERE created_by=$1 AND revoked_at IS NULL",
    )
    .bind(user)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE api_tokens SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE enrollment_tokens SET revoked_at=now() WHERE created_by=$1 AND revoked_at IS NULL",
    )
    .bind(user)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

pub async fn reconcile_all(tx: &mut PgConnection, issuer: &str) -> AppResult<Vec<Uuid>> {
    let users: Vec<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM directory_users WHERE issuer=$1 ORDER BY user_id")
            .bind(issuer)
            .fetch_all(&mut *tx)
            .await?;
    let mut revoked = Vec::new();
    for (user,) in users {
        if reconcile(tx, user).await? {
            revoked.push(user);
        }
    }
    Ok(revoked)
}

pub async fn refresh_scim_groups(tx: &mut PgConnection, users: &[Uuid]) -> AppResult<()> {
    sqlx::query("UPDATE directory_users d SET managed=true, groups=ARRAY(SELECT g.external_id FROM directory_members m JOIN directory_groups g ON g.id=m.group_id WHERE m.user_id=d.user_id AND g.issuer=d.issuer ORDER BY g.external_id) WHERE d.user_id=ANY($1)")
        .bind(users).execute(tx).await?;
    Ok(())
}

pub async fn finish_revocations(state: &Shared, users: Vec<Uuid>) -> AppResult<()> {
    // Wake every socket before awaiting any fallible database operation.
    for user in &users {
        state.support.recheck_user(*user);
    }
    let mut failure = None;
    for user in users {
        if let Err(error) = crate::support::end_all_created_by(
            state,
            user,
            &crate::support::Who::System,
            "directory access revoked",
        )
        .await
        {
            if failure.is_none() {
                failure = Some(error);
            }
        }
    }
    if let Some(error) = failure {
        return Err(error.into());
    }
    Ok(())
}

pub async fn admin_page(State(state): State<Shared>, WebUser(p): WebUser) -> Response {
    page(&p, view(&state, &p, None)).await
}

async fn view(state: &Shared, p: &Principal, secret: Option<String>) -> AppResult<Response> {
    p.require(Permission::ManageUsers)?;
    let issuer = issuer(state)?;
    let mappings:Vec<(Uuid,String,String,Vec<Uuid>)>=sqlx::query_as("SELECT id,group_key,role,organization_ids FROM directory_mappings WHERE issuer=$1 ORDER BY group_key")
        .bind(issuer).fetch_all(&state.db).await?;
    let credentials:Vec<(Uuid,String)>=sqlx::query_as("SELECT id,prefix FROM scim_credentials WHERE issuer=$1 AND revoked_at IS NULL ORDER BY created_at DESC")
        .bind(issuer).fetch_all(&state.db).await?;
    Ok(Html(flyw8t_web::directory_page(
        &ctx(p, None),
        issuer.to_string(),
        mappings,
        credentials,
        crate::queries::org_refs(state, p).await?,
        secret,
    ))
    .into_response())
}

pub async fn map_group(State(state): State<Shared>, WebUser(p): WebUser, body: Bytes) -> Response {
    page(&p,async {
        let form=Form::parse(&body); check_csrf(&p,&form)?;
        p.require(Permission::ManageUsers)?; p.require_sudo("/admin/directory")?;
        let issuer=issuer(&state)?;
        let key=clean_name(form.get("group_key"))?;
        let role=form.get("role").and_then(Role::parse).ok_or_else(||AppError::BadRequest("Unknown role.".into()))?;
        let mut orgs=Vec::new();
        for o in form.all("org") { orgs.push(o.parse::<Uuid>().map_err(|_|AppError::BadRequest("Unknown organization.".into()))?); }
        orgs.sort();orgs.dedup(); if role==Role::Admin {orgs.clear();}
        let mut tx=state.db.begin().await?; lock_all(&mut tx).await?;
        auth::recheck_actor(&mut tx,&p,None,true).await?;
        let (known,):(i64,)=sqlx::query_as("SELECT count(*) FROM organizations WHERE id=ANY($1)").bind(&orgs).fetch_one(&mut *tx).await?;
        if known!=orgs.len() as i64 {return Err(AppError::BadRequest("Unknown organization.".into()));}
        sqlx::query("INSERT INTO directory_mappings(issuer,group_key,role,organization_ids) VALUES($1,$2,$3,$4) ON CONFLICT(issuer,group_key) DO UPDATE SET role=excluded.role,organization_ids=excluded.organization_ids")
            .bind(issuer).bind(&key).bind(role.as_str()).bind(&orgs).execute(&mut *tx).await?;
        let revoked=reconcile_all(&mut tx,issuer).await?;
        Audit::user(&p,"directory.mapping.save").detail(json!({"group":key,"role":role.as_str(),"organizations":orgs})).record(&mut *tx).await?;
        tx.commit().await?;finish_revocations(&state,revoked).await?;to("/admin/directory")
    }).await
}

pub async fn remove_mapping(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        check_csrf(&p, &Form::parse(&body))?;
        p.require(Permission::ManageUsers)?;
        p.require_sudo("/admin/directory")?;
        let issuer = issuer(&state)?;
        let mut tx = state.db.begin().await?;
        lock_all(&mut tx).await?;
        auth::recheck_actor(&mut tx, &p, None, true).await?;
        if sqlx::query("DELETE FROM directory_mappings WHERE id=$1 AND issuer=$2")
            .bind(id)
            .bind(issuer)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            != 1
        {
            return Err(AppError::NotFound);
        }
        let revoked = reconcile_all(&mut tx, issuer).await?;
        Audit::user(&p, "directory.mapping.remove")
            .target("directory_mapping", id)
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        finish_revocations(&state, revoked).await?;
        to("/admin/directory")
    })
    .await
}

pub async fn create_credential(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    body: Bytes,
) -> Response {
    page(&p,async {
        check_csrf(&p,&Form::parse(&body))?;p.require(Permission::ManageUsers)?;p.require_sudo("/admin/directory")?;
        let issuer=issuer(&state)?;let secret=format!("fw8s_{}",auth::random_secret(32));let prefix=&secret[..13];
        let mut tx=state.db.begin().await?;lock_all(&mut tx).await?;auth::recheck_actor(&mut tx,&p,None,true).await?;
        sqlx::query("UPDATE scim_credentials SET revoked_at=now() WHERE issuer=$1 AND revoked_at IS NULL").bind(issuer).execute(&mut *tx).await?;
        let (id,):(Uuid,)=sqlx::query_as("INSERT INTO scim_credentials(issuer,prefix,token_hash,created_by) VALUES($1,$2,$3,$4) RETURNING id")
            .bind(issuer).bind(prefix).bind(auth::digest(&secret)).bind(p.user_id).fetch_one(&mut *tx).await?;
        Audit::user(&p,"directory.credential.rotate").target("scim_credential",id).detail(json!({"prefix":prefix})).record(&mut *tx).await?;
        tx.commit().await?;view(&state,&p,Some(secret)).await
    }).await
}

pub async fn revoke_credential(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p,async {
        check_csrf(&p,&Form::parse(&body))?;p.require(Permission::ManageUsers)?;p.require_sudo("/admin/directory")?;
        let issuer=issuer(&state)?;let mut tx=state.db.begin().await?;lock_all(&mut tx).await?;auth::recheck_actor(&mut tx,&p,None,true).await?;
        if sqlx::query("UPDATE scim_credentials SET revoked_at=now() WHERE id=$1 AND issuer=$2 AND revoked_at IS NULL")
            .bind(id).bind(issuer).execute(&mut *tx).await?.rows_affected()!=1 {return Err(AppError::NotFound);}
        Audit::user(&p,"directory.credential.revoke").target("scim_credential",id).record(&mut *tx).await?;
        tx.commit().await?;to("/admin/directory")
    }).await
}
