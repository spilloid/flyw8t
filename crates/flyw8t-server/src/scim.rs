//! SCIM 2.0 directory provisioning. This is a separate credential plane: a SCIM key can
//! administer only directory identities for the configured issuer, never local accounts.
//! Writes serialize with mapping changes and re-check the key after acquiring those locks.

use crate::audit::Audit;
use crate::auth;
use crate::directory;
use crate::error::AppError;
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use sqlx::PgConnection;
use uuid::Uuid;

const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const MEDIA: &str = "application/scim+json";
const MAX_MEMBERS: usize = 1000;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/scim/v2/Users", get(users).post(create_user))
        .route(
            "/scim/v2/Users/{id}",
            get(user)
                .put(replace_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route("/scim/v2/Groups", get(groups).post(create_group))
        .route(
            "/scim/v2/Groups/{id}",
            get(group)
                .put(replace_group)
                .patch(patch_group)
                .delete(delete_group),
        )
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(resource_types))
        .route("/scim/v2/ResourceTypes/{id}", get(resource_type))
        .route("/scim/v2/Schemas", get(schemas))
        .route("/scim/v2/Schemas/{id}", get(schema_resource))
}

#[derive(Debug)]
struct Error {
    status: StatusCode,
    kind: &'static str,
    detail: String,
}

type Result<T> = std::result::Result<T, Error>;

impl Error {
    fn bad(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            kind,
            detail: detail.into(),
        }
    }
    fn missing() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            kind: "",
            detail: "Resource not found.".into(),
        }
    }
}

impl From<AppError> for Error {
    fn from(e: AppError) -> Self {
        e.log();
        Self {
            status: match e {
                AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
                _ => e.status(),
            },
            kind: match e {
                AppError::Conflict(_) => "",
                AppError::BadRequest(_) => "invalidValue",
                _ => "",
            },
            detail: e.to_string(),
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        if e.as_database_error()
            .is_some_and(|d| d.is_unique_violation())
        {
            Self {
                status: StatusCode::CONFLICT,
                kind: "uniqueness",
                detail: "That directory identity, group key or email already exists.".into(),
            }
        } else {
            AppError::from(e).into()
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut body = json!({ "schemas": [ERROR], "status": self.status.as_u16().to_string(), "detail": self.detail });
        if !self.kind.is_empty() {
            body["scimType"] = json!(self.kind);
        }
        let mut response = reply(self.status, body);
        if self.status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
        }
        response
    }
}

fn reply(status: StatusCode, value: Value) -> Response {
    (status, [(header::CONTENT_TYPE, MEDIA)], axum::Json(value)).into_response()
}

fn resource_reply(status: StatusCode, value: Value) -> Response {
    let location = value["meta"]["location"].as_str().map(str::to_owned);
    let mut response = reply(status, value);
    if let Some(location) = location.and_then(|v| v.parse().ok()) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

fn id(raw: &str) -> Result<Uuid> {
    raw.parse().map_err(|_| Error::missing())
}

struct Credential {
    issuer: String,
    id: Uuid,
    prefix: String,
}

async fn authenticate(
    state: &Shared,
    tx: &mut PgConnection,
    headers: &HeaderMap,
) -> Result<Credential> {
    let issuer = directory::issuer(state)?;
    let mut authorization = headers.get_all(header::AUTHORIZATION).iter();
    let raw = authorization
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .and_then(|(scheme, token)| scheme.eq_ignore_ascii_case("Bearer").then_some(token));
    let raw = raw.filter(|v| {
        v.starts_with("fw8s_")
            && (25..=128).contains(&v.len())
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    });
    if authorization.next().is_some() || raw.is_none() {
        return Err(AppError::Unauthorized.into());
    }
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, prefix FROM scim_credentials WHERE issuer = $1 AND token_hash = $2 AND revoked_at IS NULL",
    ).bind(issuer).bind(auth::digest(raw.unwrap())).fetch_optional(&mut *tx).await?;
    let (id, prefix) = row.ok_or(AppError::Unauthorized)?;
    Ok(Credential {
        issuer: issuer.into(),
        id,
        prefix,
    })
}

fn audit(credential: &Credential, action: &'static str, kind: &'static str, id: Uuid) -> Audit {
    Audit::system(action).target(kind, id).detail(json!({ "credential_id": credential.id, "credential_prefix": credential.prefix, "issuer": credential.issuer }))
}

fn body(headers: &HeaderMap, bytes: &[u8]) -> Result<Value> {
    let media = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if !media.eq_ignore_ascii_case(MEDIA) && !media.eq_ignore_ascii_case("application/json") {
        return Err(Error {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            kind: "invalidSyntax",
            detail: "Use application/scim+json.".into(),
        });
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| Error::bad("invalidSyntax", "A JSON object is required."))?;
    if !value.is_object() {
        return Err(Error::bad("invalidSyntax", "A JSON object is required."));
    }
    Ok(value)
}

fn check_fields(value: &Value, allowed: &[&str]) -> Result<()> {
    for key in value
        .as_object()
        .ok_or_else(|| Error::bad("invalidSyntax", "A JSON object is required."))?
        .keys()
    {
        if !allowed.contains(&key.as_str()) {
            return Err(Error::bad(
                "invalidPath",
                format!("Unsupported attribute: {key}."),
            ));
        }
    }
    Ok(())
}

fn schema(value: &Value, required: &str) -> Result<()> {
    if !value
        .get("schemas")
        .and_then(Value::as_array)
        .is_some_and(|s| s.len() == 1 && s[0].as_str() == Some(required))
    {
        return Err(Error::bad(
            "invalidSyntax",
            format!("schemas must contain only {required}."),
        ));
    }
    Ok(())
}

fn text(value: &Value, field: &str, max: usize) -> Result<String> {
    let raw = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::bad("invalidValue", format!("{field} is required.")))?;
    if raw.is_empty() || raw.chars().count() > max || raw.chars().any(char::is_control) {
        return Err(Error::bad(
            "invalidValue",
            format!("{field} must be 1 to {max} characters without control characters."),
        ));
    }
    Ok(raw.to_string())
}

fn email(raw: &str) -> Result<String> {
    let email = raw.trim().to_lowercase();
    if email.len() > 254
        || !email
            .split_once('@')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && !b.contains('@'))
        || email.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(Error::bad(
            "invalidValue",
            "userName must be an email address.",
        ));
    }
    Ok(email)
}

#[derive(Default)]
struct Page {
    start: i64,
    count: i64,
    filter: Option<(String, String)>,
}

fn pagination(raw: Option<String>, user: bool) -> Result<Page> {
    let mut page = Page {
        start: 1,
        count: 100,
        filter: None,
    };
    let mut seen = std::collections::HashSet::new();
    for (key, value) in form_urlencoded::parse(raw.as_deref().unwrap_or("").as_bytes()) {
        if !seen.insert(key.to_string()) {
            return Err(Error::bad("invalidSyntax", "Duplicate query parameter."));
        }
        match key.as_ref() {
            "startIndex" => {
                page.start = value
                    .parse::<i64>()
                    .ok()
                    .filter(|n| (1..=10_000_000).contains(n))
                    .ok_or_else(|| {
                        Error::bad("invalidValue", "startIndex must be between 1 and 10000000.")
                    })?
            }
            "count" => {
                page.count = value
                    .parse::<i64>()
                    .ok()
                    .filter(|n| (0..=200).contains(n))
                    .ok_or_else(|| Error::bad("invalidValue", "count must be between 0 and 200."))?
            }
            "filter" => page.filter = Some(filter(&value, user)?),
            _ => {
                return Err(Error::bad(
                    "invalidSyntax",
                    "Only filter, startIndex and count query parameters are supported.",
                ))
            }
        }
    }
    Ok(page)
}

fn filter(raw: &str, user: bool) -> Result<(String, String)> {
    let (attribute, rest) = raw.trim().split_once(char::is_whitespace).ok_or_else(|| {
        Error::bad(
            "invalidFilter",
            "Use an equality filter with a quoted string.",
        )
    })?;
    let (operator, rest) = rest
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or_else(|| {
            Error::bad(
                "invalidFilter",
                "Use an equality filter with a quoted string.",
            )
        })?;
    let attribute = attribute.to_ascii_lowercase();
    let allowed = if user {
        &["id", "username", "externalid"][..]
    } else {
        &["id", "displayname", "externalid"][..]
    };
    let value: String = serde_json::from_str(rest.trim()).map_err(|_| {
        Error::bad(
            "invalidFilter",
            "Filter values must be quoted JSON strings.",
        )
    })?;
    if !operator.eq_ignore_ascii_case("eq")
        || !allowed.contains(&attribute.as_str())
        || value.len() > 512
    {
        return Err(Error::bad(
            "invalidFilter",
            "Unsupported filter; only id, externalId and userName/displayName eq are supported.",
        ));
    }
    Ok((attribute, value))
}

fn list(resources: Vec<Value>, total: i64, start: i64) -> Value {
    json!({ "schemas": [LIST], "totalResults": total, "startIndex": start, "itemsPerPage": resources.len(), "Resources": resources })
}

async fn user_value(
    state: &Shared,
    tx: &mut PgConnection,
    issuer: &str,
    id: Uuid,
) -> Result<Value> {
    let row: Option<(String, String, String, bool, Value)> = sqlx::query_as(
        "SELECT d.subject, u.email, u.display_name, d.active,
                coalesce((SELECT jsonb_agg(jsonb_build_object('value', g.id::text, 'display', g.display_name, 'type', 'direct') ORDER BY g.id)
                  FROM directory_members m JOIN directory_groups g ON g.id = m.group_id WHERE m.user_id = d.user_id AND g.issuer = d.issuer), '[]'::jsonb)
           FROM directory_users d JOIN users u ON u.id = d.user_id WHERE d.issuer = $1 AND d.user_id = $2",
    ).bind(issuer).bind(id).fetch_optional(&mut *tx).await?;
    let (subject, email, name, active, groups) = row.ok_or_else(Error::missing)?;
    Ok(
        json!({ "schemas": [USER], "id": id, "externalId": subject, "userName": email, "displayName": name,
        "active": active, "emails": [{ "value": email, "primary": true }], "groups": groups,
        "meta": { "resourceType": "User", "location": format!("{}/scim/v2/Users/{id}", state.config.public_url) } }),
    )
}

async fn group_value(
    state: &Shared,
    tx: &mut PgConnection,
    issuer: &str,
    id: Uuid,
) -> Result<Value> {
    let row: Option<(String, String, Value)> = sqlx::query_as(
        "SELECT g.external_id, g.display_name,
                coalesce((SELECT jsonb_agg(jsonb_build_object('value', m.user_id::text, 'display', u.display_name) ORDER BY m.user_id)
                  FROM directory_members m JOIN users u ON u.id = m.user_id WHERE m.group_id = g.id AND EXISTS (SELECT 1 FROM directory_users du WHERE du.user_id = m.user_id AND du.issuer = g.issuer)), '[]'::jsonb)
           FROM directory_groups g WHERE g.issuer = $1 AND g.id = $2",
    ).bind(issuer).bind(id).fetch_optional(&mut *tx).await?;
    let (external, name, members) = row.ok_or_else(Error::missing)?;
    Ok(
        json!({ "schemas": [GROUP], "id": id, "externalId": external, "displayName": name, "members": members,
        "meta": { "resourceType": "Group", "location": format!("{}/scim/v2/Groups/{id}", state.config.public_url) } }),
    )
}

async fn users(
    State(state): State<Shared>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    let credential = authenticate(&state, &mut tx, &headers).await?;
    let page = pagination(raw, true)?;
    let (attribute, value) = page
        .filter
        .as_ref()
        .map(|(a, v)| (Some(a.as_str()), Some(v.as_str())))
        .unwrap_or_default();
    let ids: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT d.user_id FROM directory_users d JOIN users u ON u.id = d.user_id
          WHERE d.issuer = $1 AND ($2::text IS NULL OR CASE $2 WHEN 'id' THEN d.user_id::text = $3
            WHEN 'externalid' THEN d.subject = $3 WHEN 'username' THEN lower(u.email) = lower($3) ELSE false END)
          ORDER BY d.user_id LIMIT $4 OFFSET $5",
    ).bind(&credential.issuer).bind(attribute).bind(value).bind(page.count).bind(page.start - 1).fetch_all(&mut *tx).await?;
    let (total,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM directory_users d JOIN users u ON u.id = d.user_id
          WHERE d.issuer = $1 AND ($2::text IS NULL OR CASE $2 WHEN 'id' THEN d.user_id::text = $3
            WHEN 'externalid' THEN d.subject = $3 WHEN 'username' THEN lower(u.email) = lower($3) ELSE false END)",
    ).bind(&credential.issuer).bind(attribute).bind(value).fetch_one(&mut *tx).await?;
    let mut resources = Vec::new();
    for (id,) in ids {
        resources.push(user_value(&state, &mut tx, &credential.issuer, id).await?);
    }
    tx.commit().await?;
    Ok(reply(StatusCode::OK, list(resources, total, page.start)))
}

async fn groups(
    State(state): State<Shared>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    let credential = authenticate(&state, &mut tx, &headers).await?;
    let page = pagination(raw, false)?;
    let (attribute, value) = page
        .filter
        .as_ref()
        .map(|(a, v)| (Some(a.as_str()), Some(v.as_str())))
        .unwrap_or_default();
    let ids: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM directory_groups WHERE issuer = $1 AND ($2::text IS NULL OR CASE $2
          WHEN 'id' THEN id::text = $3 WHEN 'externalid' THEN external_id = $3 WHEN 'displayname' THEN lower(display_name) = lower($3) ELSE false END)
          ORDER BY id LIMIT $4 OFFSET $5",
    ).bind(&credential.issuer).bind(attribute).bind(value).bind(page.count).bind(page.start - 1).fetch_all(&mut *tx).await?;
    let (total,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM directory_groups WHERE issuer = $1 AND ($2::text IS NULL OR CASE $2
          WHEN 'id' THEN id::text = $3 WHEN 'externalid' THEN external_id = $3 WHEN 'displayname' THEN lower(display_name) = lower($3) ELSE false END)",
    ).bind(&credential.issuer).bind(attribute).bind(value).fetch_one(&mut *tx).await?;
    let mut resources = Vec::new();
    for (id,) in ids {
        resources.push(group_value(&state, &mut tx, &credential.issuer, id).await?);
    }
    tx.commit().await?;
    Ok(reply(StatusCode::OK, list(resources, total, page.start)))
}

async fn user(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    let c = authenticate(&state, &mut tx, &headers).await?;
    let value = user_value(&state, &mut tx, &c.issuer, id(&raw)?).await?;
    tx.commit().await?;
    Ok(resource_reply(StatusCode::OK, value))
}

async fn group(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    let c = authenticate(&state, &mut tx, &headers).await?;
    let value = group_value(&state, &mut tx, &c.issuer, id(&raw)?).await?;
    tx.commit().await?;
    Ok(resource_reply(StatusCode::OK, value))
}

struct UserInput {
    subject: String,
    email: String,
    name: String,
    active: bool,
}

fn user_input(value: &Value) -> Result<UserInput> {
    schema(value, USER)?;
    check_fields(
        value,
        &[
            "schemas",
            "id",
            "externalId",
            "userName",
            "displayName",
            "active",
            "emails",
            "name",
            "meta",
        ],
    )?;
    let subject = text(value, "externalId", 255)?;
    let email = email(&text(value, "userName", 254)?)?;
    let name = match value.get("displayName") {
        Some(_) => text(value, "displayName", 200)?,
        None => value
            .get("name")
            .map(name_value)
            .transpose()?
            .unwrap_or_else(|| email.clone()),
    };
    if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
        return Err(Error::bad(
            "invalidValue",
            "displayName must be 1 to 200 characters.",
        ));
    }
    if let Some(emails) = value.get("emails") {
        let values = emails
            .as_array()
            .ok_or_else(|| Error::bad("invalidValue", "emails must be an array."))?;
        if values.len() > 10 {
            return Err(Error::bad(
                "invalidValue",
                "At most ten emails are accepted.",
            ));
        }
        for item in values {
            let raw = item
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::bad("invalidValue", "An email value is required."))?;
            if email != self::email(raw)? {
                return Err(Error::bad(
                    "invalidValue",
                    "emails must match the email used as userName.",
                ));
            }
        }
    }
    if let Some(name) = value.get("name") {
        name_value(name)?;
    }
    let active = match value.get("active") {
        None => true,
        Some(v) => v
            .as_bool()
            .ok_or_else(|| Error::bad("invalidValue", "active must be a boolean."))?,
    };
    Ok(UserInput {
        subject,
        email,
        name,
        active,
    })
}

async fn update_user(
    tx: &mut PgConnection,
    issuer: &str,
    id: Uuid,
    input: &UserInput,
) -> Result<bool> {
    let current: Option<(String,)> =
        sqlx::query_as("SELECT subject FROM directory_users WHERE user_id = $1 AND issuer = $2")
            .bind(id)
            .bind(issuer)
            .fetch_optional(&mut *tx)
            .await?;
    if current.ok_or_else(Error::missing)?.0 != input.subject {
        return Err(Error::bad("mutability", "externalId is immutable."));
    }
    sqlx::query("UPDATE users SET email = $2, display_name = $3 WHERE id = $1")
        .bind(id)
        .bind(&input.email)
        .bind(&input.name)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE directory_users SET active = $2, managed = true WHERE user_id = $1")
        .bind(id)
        .bind(input.active)
        .execute(&mut *tx)
        .await?;
    directory::refresh_scim_groups(tx, &[id]).await?;
    Ok(directory::reconcile(tx, id).await?)
}

/// Authentik 2026.5.3 interprets409 as permission to discover by mutable email/name.
/// Refuse every create conflict without409; safe duplicate identities return 200 directly.
fn create_failure(error: Error) -> Error {
    if error.status == StatusCode::CONFLICT {
        Error::bad("invalidValue","Provisioning conflict. No identity was adopted; verify the immutable externalId and resolve the profile through an existing resource before retrying.")
    } else {
        error
    }
}

async fn create_user(state: State<Shared>, headers: HeaderMap, bytes: Bytes) -> Result<Response> {
    create_user_inner(state, headers, bytes)
        .await
        .map_err(create_failure)
}

async fn create_user_inner(
    State(state): State<Shared>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    directory::lock_all(&mut tx).await?;
    let c = authenticate(&state, &mut tx, &headers).await?;
    let input = user_input(&body(&headers, &bytes)?)?;
    let existing:Option<(Uuid,String,String,bool)>=sqlx::query_as("SELECT d.user_id,u.email,u.display_name,d.active FROM directory_users d JOIN users u ON u.id=d.user_id WHERE d.issuer=$1 AND d.subject=$2")
        .bind(&c.issuer).bind(&input.subject).fetch_optional(&mut *tx).await?;
    if let Some((id, email, name, active)) = existing {
        if email != input.email || name != input.name || active != input.active {
            return Err(Error::bad("invalidValue","Existing subject has a different profile. Resolve it by immutable externalId and PUT/PATCH; create never adopts an email match."));
        }
        let value = user_value(&state, &mut tx, &c.issuer, id).await?;
        audit(&c, "directory.scim.user.reuse", "user", id)
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(resource_reply(StatusCode::OK, value));
    }
    let (email_used,): (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)")
            .bind(&input.email)
            .fetch_one(&mut *tx)
            .await?;
    if email_used {
        return Err(Error::bad("invalidValue","This email belongs to another identity. Resolve the address explicitly; create never adopts a local or directory email match."));
    }
    let id = directory::ensure_identity(
        &mut tx,
        &c.issuer,
        &input.subject,
        &input.email,
        &input.name,
        true,
    )
    .await?;
    let revoked = update_user(&mut tx, &c.issuer, id, &input).await?;
    audit(&c, "directory.scim.user.create", "user", id)
        .record(&mut *tx)
        .await?;
    let value = user_value(&state, &mut tx, &c.issuer, id).await?;
    tx.commit().await?;
    if revoked {
        directory::finish_revocations(&state, vec![id]).await?;
    }
    Ok(resource_reply(StatusCode::CREATED, value))
}

async fn replace_user(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    bytes: Bytes,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    directory::lock_all(&mut tx).await?;
    let c = authenticate(&state, &mut tx, &headers).await?;
    let id = id(&raw)?;
    let input = user_input(&body(&headers, &bytes)?)?;
    let revoked = update_user(&mut tx, &c.issuer, id, &input).await?;
    audit(&c, "directory.scim.user.replace", "user", id)
        .record(&mut *tx)
        .await?;
    let value = user_value(&state, &mut tx, &c.issuer, id).await?;
    tx.commit().await?;
    if revoked {
        directory::finish_revocations(&state, vec![id]).await?;
    }
    Ok(resource_reply(StatusCode::OK, value))
}

fn operations(value: &Value) -> Result<&Vec<Value>> {
    schema(value, PATCH)?;
    operation_values(value)
}

fn operation_values(value: &Value) -> Result<&Vec<Value>> {
    check_fields(value, &["schemas", "Operations"])?;
    value
        .get("Operations")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty() && v.len() <= 100)
        .ok_or_else(|| {
            Error::bad(
                "invalidSyntax",
                "Operations must contain 1 to 100 operations.",
            )
        })
}

/// Authentik 2026.5.3's group metadata client omits the outer default schemas when
/// serializing exclude_unset=True. Accommodate only its one full metadata replace;
/// every explicitly supplied outer schema, and every inner identity, remains checked.
fn group_operations(value: &Value) -> Result<&Vec<Value>> {
    if value.get("schemas").is_some() {
        return operations(value);
    }
    let operations = operation_values(value)?;
    if operations.len() != 1 {
        return Err(Error::bad(
            "invalidSyntax",
            "Omitted PATCH schemas requires one Group metadata replacement.",
        ));
    }
    let (op, path, fields) = operation(&operations[0])?;
    let fields =
        fields.ok_or_else(|| Error::bad("invalidValue", "A metadata replacement is required."))?;
    check_fields(fields, &["id", "schemas", "externalId", "displayName"])?;
    if op != "replace"
        || path.is_some()
        || !["id", "schemas", "externalId", "displayName"]
            .iter()
            .all(|k| fields.get(*k).is_some())
    {
        return Err(Error::bad(
            "invalidSyntax",
            "Omitted PATCH schemas only supports the full Group metadata replace shape.",
        ));
    }
    schema(fields, GROUP)?;
    Ok(operations)
}

fn operation(value: &Value) -> Result<(String, Option<String>, Option<&Value>)> {
    check_fields(value, &["op", "path", "value"])?;
    let op = text(value, "op", 20)?.to_ascii_lowercase();
    if !["add", "replace", "remove"].contains(&op.as_str()) {
        return Err(Error::bad("invalidSyntax", "Unsupported PATCH operation."));
    }
    let path = match value.get("path") {
        None => None,
        Some(v) => Some(
            v.as_str()
                .filter(|s| s.len() <= 512)
                .ok_or_else(|| {
                    Error::bad("invalidPath", "path must be a string of at most 512 bytes.")
                })?
                .to_ascii_lowercase(),
        ),
    };
    Ok((op, path, value.get("value")))
}

fn name_value(value: &Value) -> Result<String> {
    check_fields(value, &["formatted", "givenName", "familyName"])?;
    let name =
        if let Some(formatted) = value.get("formatted") {
            formatted
                .as_str()
                .ok_or_else(|| Error::bad("invalidValue", "name.formatted must be a string."))?
                .to_string()
        } else {
            let mut parts = Vec::new();
            for field in ["givenName", "familyName"] {
                if let Some(value) = value.get(field) {
                    parts.push(value.as_str().ok_or_else(|| {
                        Error::bad("invalidValue", "Name parts must be strings.")
                    })?);
                }
            }
            parts.join(" ")
        };
    if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
        return Err(Error::bad(
            "invalidValue",
            "name must describe a person in at most 200 characters.",
        ));
    }
    Ok(name)
}

fn patch_user_fields(current: &mut Value, fields: &Value) -> Result<()> {
    check_fields(
        fields,
        &[
            "externalId",
            "userName",
            "displayName",
            "active",
            "emails",
            "name",
        ],
    )?;
    if let Some(value) = fields.get("externalId") {
        if value != &current["externalId"] {
            return Err(Error::bad("mutability", "externalId is immutable."));
        }
    }
    if let Some(value) = fields.get("userName") {
        current["userName"] = value.clone();
        current.as_object_mut().unwrap().remove("emails");
    }
    if let Some(value) = fields.get("emails") {
        let values = value
            .as_array()
            .ok_or_else(|| Error::bad("invalidValue", "emails must be an array."))?;
        let primary = values
            .iter()
            .find(|v| v.get("primary").and_then(Value::as_bool) == Some(true))
            .or_else(|| values.first());
        let raw = primary
            .and_then(|v| v.get("value"))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::bad("invalidValue", "An email value is required."))?;
        if fields.get("userName").is_none() {
            current["userName"] = json!(email(raw)?);
        }
        current["emails"] = value.clone();
    }
    if let Some(value) = fields.get("name") {
        if fields.get("displayName").is_none() {
            current["displayName"] = json!(name_value(value)?);
        }
    }
    for (key, value) in fields.as_object().unwrap() {
        if key != "userName" && key != "emails" {
            current[key] = value.clone();
        }
    }
    Ok(())
}

async fn patch_user(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    bytes: Bytes,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    directory::lock_all(&mut tx).await?;
    let c = authenticate(&state, &mut tx, &headers).await?;
    let id = id(&raw)?;
    let mut current = user_value(&state, &mut tx, &c.issuer, id).await?;
    // groups is a read-only response attribute; authorization is changed through Groups.
    current.as_object_mut().unwrap().remove("groups");
    let patch = body(&headers, &bytes)?;
    for op in operations(&patch)? {
        let (op, path, value) = operation(op)?;
        if op == "remove" {
            return Err(Error::bad("mutability", "Removing required User attributes is unsupported; replace active with false to deprovision."));
        }
        let value = value.ok_or_else(|| Error::bad("invalidValue", "A value is required."))?;
        if let Some(path) = path {
            let key = match path.as_str() {
                "active" => "active",
                "username" => "userName",
                "displayname" => "displayName",
                "emails" => "emails",
                "externalid" => "externalId",
                "name" => "name",
                _ => return Err(Error::bad("invalidPath", "Unsupported User PATCH path.")),
            };
            patch_user_fields(&mut current, &json!({ (key): value }))?;
        } else {
            patch_user_fields(&mut current, value)?;
        }
    }
    let input = user_input(&current)?;
    let revoked = update_user(&mut tx, &c.issuer, id, &input).await?;
    audit(&c, "directory.scim.user.patch", "user", id)
        .record(&mut *tx)
        .await?;
    let value = user_value(&state, &mut tx, &c.issuer, id).await?;
    tx.commit().await?;
    if revoked {
        directory::finish_revocations(&state, vec![id]).await?;
    }
    Ok(resource_reply(StatusCode::OK, value))
}

async fn delete_user(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    directory::lock_all(&mut tx).await?;
    let c = authenticate(&state, &mut tx, &headers).await?;
    let id = id(&raw)?;
    let changed = sqlx::query("UPDATE directory_users SET active = false, managed = true WHERE user_id = $1 AND issuer = $2")
        .bind(id).bind(&c.issuer).execute(&mut *tx).await?.rows_affected();
    if changed == 0 {
        return Err(Error::missing());
    }
    let revoked = directory::reconcile(&mut tx, id).await?;
    audit(&c, "directory.scim.user.delete", "user", id)
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    if revoked {
        directory::finish_revocations(&state, vec![id]).await?;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

struct GroupInput {
    external: String,
    name: String,
    members: Vec<Uuid>,
}

fn member_ids(value: &Value) -> Result<Vec<Uuid>> {
    let values = value
        .as_array()
        .filter(|v| v.len() <= MAX_MEMBERS)
        .ok_or_else(|| {
            Error::bad(
                "invalidValue",
                "members must be an array of at most 1000 users.",
            )
        })?;
    let mut members = Vec::new();
    for member in values {
        check_fields(member, &["value", "display", "$ref", "type"])?;
        if member
            .get("type")
            .is_some_and(|v| v.as_str() != Some("User"))
        {
            return Err(Error::bad(
                "invalidValue",
                "Only direct User members are supported.",
            ));
        }
        let raw = member
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::bad("invalidValue", "Each member needs a User id as value."))?;
        members.push(
            raw.parse()
                .map_err(|_| Error::bad("invalidValue", "A member value must be a User id."))?,
        );
    }
    members.sort();
    members.dedup();
    Ok(members)
}

fn group_input(value: &Value) -> Result<GroupInput> {
    schema(value, GROUP)?;
    check_fields(
        value,
        &[
            "schemas",
            "id",
            "externalId",
            "displayName",
            "members",
            "meta",
        ],
    )?;
    Ok(GroupInput {
        external: text(value, "externalId", 200)?,
        name: text(value, "displayName", 200)?,
        members: value
            .get("members")
            .map(member_ids)
            .transpose()?
            .unwrap_or_default(),
    })
}

async fn replace_members(
    tx: &mut PgConnection,
    issuer: &str,
    id: Uuid,
    members: &[Uuid],
) -> Result<Vec<Uuid>> {
    let (known,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM directory_users WHERE issuer = $1 AND user_id = ANY($2)",
    )
    .bind(issuer)
    .bind(members)
    .fetch_one(&mut *tx)
    .await?;
    if known != members.len() as i64 {
        return Err(Error::bad("invalidValue", "Every member must be a directory User of this issuer; local users and nested groups are not supported."));
    }
    let (too_many,): (bool,) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM directory_members WHERE user_id = ANY($1) AND group_id <> $2 GROUP BY user_id HAVING count(*) >= $3)")
        .bind(members).bind(id).bind(MAX_MEMBERS as i64).fetch_one(&mut *tx).await?;
    if too_many {
        return Err(Error::bad(
            "invalidValue",
            "A user may belong to at most 1000 groups.",
        ));
    }
    let previous: Vec<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM directory_members WHERE group_id = $1")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
    let mut affected: Vec<Uuid> = previous
        .into_iter()
        .map(|r| r.0)
        .chain(members.iter().copied())
        .collect();
    affected.sort();
    affected.dedup();
    sqlx::query("DELETE FROM directory_members WHERE group_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO directory_members (group_id, user_id) SELECT $1, unnest($2::uuid[])")
        .bind(id)
        .bind(members)
        .execute(&mut *tx)
        .await?;
    directory::refresh_scim_groups(tx, &affected).await?;
    let mut revoked = Vec::new();
    for user in affected {
        if directory::reconcile(tx, user).await? {
            revoked.push(user);
        }
    }
    Ok(revoked)
}

async fn update_group(
    tx: &mut PgConnection,
    issuer: &str,
    id: Uuid,
    input: &GroupInput,
) -> Result<Vec<Uuid>> {
    let current: Option<(String,)> =
        sqlx::query_as("SELECT external_id FROM directory_groups WHERE issuer = $1 AND id = $2")
            .bind(issuer)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if current.ok_or_else(Error::missing)?.0 != input.external {
        return Err(Error::bad(
            "mutability",
            "externalId is immutable; create a new group and explicitly map its new key.",
        ));
    }
    sqlx::query("UPDATE directory_groups SET display_name = $2 WHERE id = $1")
        .bind(id)
        .bind(&input.name)
        .execute(&mut *tx)
        .await?;
    replace_members(tx, issuer, id, &input.members).await
}

async fn create_group(state: State<Shared>, headers: HeaderMap, bytes: Bytes) -> Result<Response> {
    create_group_inner(state, headers, bytes)
        .await
        .map_err(create_failure)
}

async fn create_group_inner(
    State(state): State<Shared>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    directory::lock_all(&mut tx).await?;
    let c = authenticate(&state, &mut tx, &headers).await?;
    let request = body(&headers, &bytes)?;
    let input = group_input(&request)?;
    let existing: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM directory_groups WHERE issuer=$1 AND external_id=$2")
            .bind(&c.issuer)
            .bind(&input.external)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((id,)) = existing {
        let named: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM directory_groups WHERE issuer=$1 AND lower(display_name)=lower($2)",
        )
        .bind(&c.issuer)
        .bind(&input.name)
        .fetch_all(&mut *tx)
        .await?;
        let value = group_value(&state, &mut tx, &c.issuer, id).await?;
        if named != vec![(id,)]
            || (request.get("members").is_some() && input.members != member_ids(&value["members"])?)
        {
            return Err(Error::bad("invalidValue","Existing group has a changed or ambiguous profile/membership. Resolve it by immutable externalId and PUT/PATCH; create never adopts a display-name match."));
        }
        audit(&c, "directory.scim.group.reuse", "directory_group", id)
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(resource_reply(StatusCode::OK, value));
    }
    let (id,): (Uuid,) = sqlx::query_as("INSERT INTO directory_groups (issuer, external_id, display_name) VALUES ($1, $2, $3) RETURNING id")
        .bind(&c.issuer).bind(&input.external).bind(&input.name).fetch_one(&mut *tx).await?;
    let revoked = replace_members(&mut tx, &c.issuer, id, &input.members).await?;
    audit(&c, "directory.scim.group.create", "directory_group", id)
        .record(&mut *tx)
        .await?;
    let value = group_value(&state, &mut tx, &c.issuer, id).await?;
    tx.commit().await?;
    directory::finish_revocations(&state, revoked).await?;
    Ok(resource_reply(StatusCode::CREATED, value))
}

async fn replace_group(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    bytes: Bytes,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    directory::lock_all(&mut tx).await?;
    let c = authenticate(&state, &mut tx, &headers).await?;
    let id = id(&raw)?;
    let input = group_input(&body(&headers, &bytes)?)?;
    let revoked = update_group(&mut tx, &c.issuer, id, &input).await?;
    audit(&c, "directory.scim.group.replace", "directory_group", id)
        .record(&mut *tx)
        .await?;
    let value = group_value(&state, &mut tx, &c.issuer, id).await?;
    tx.commit().await?;
    directory::finish_revocations(&state, revoked).await?;
    Ok(resource_reply(StatusCode::OK, value))
}

fn patch_group_fields(current: &mut Value, fields: &Value, op: &str) -> Result<()> {
    check_fields(
        fields,
        &["id", "schemas", "externalId", "displayName", "members"],
    )?;
    if fields.get("id").is_some() || fields.get("schemas").is_some() {
        if op != "replace" {
            return Err(Error::bad(
                "invalidSyntax",
                "Group identity metadata is accepted only in a replacement.",
            ));
        }
        if let Some(id) = fields.get("id") {
            if id != &current["id"] {
                return Err(Error::bad("mutability", "Group id is immutable."));
            }
        }
        if fields.get("schemas").is_some() {
            schema(fields, GROUP)?;
        }
    }
    for (key, value) in fields.as_object().unwrap() {
        match key.as_str() {
            "externalId" if value != &current["externalId"] => {
                return Err(Error::bad("mutability", "externalId is immutable."))
            }
            "members" => {
                let mut wanted = member_ids(value)?;
                if op == "add" {
                    wanted.extend(member_ids(&current["members"])?);
                    wanted.sort();
                    wanted.dedup();
                }
                if wanted.len() > MAX_MEMBERS {
                    return Err(Error::bad(
                        "invalidValue",
                        "A group may contain at most 1000 members.",
                    ));
                }
                current["members"] = json!(wanted
                    .into_iter()
                    .map(|id| json!({ "value": id }))
                    .collect::<Vec<_>>());
            }
            _ => current[key] = value.clone(),
        }
    }
    Ok(())
}

fn remove_member(path: &str) -> Result<Option<Uuid>> {
    if path == "members" {
        return Ok(None);
    }
    let raw = path
        .strip_prefix("members[")
        .and_then(|p| p.strip_suffix(']'))
        .ok_or_else(|| {
            Error::bad(
                "invalidPath",
                "Use members or members[value eq \"User-id\"].",
            )
        })?;
    let (attribute, raw) = raw
        .trim()
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::bad("invalidFilter", "Unsupported member filter."))?;
    let (operator, raw) = raw
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::bad("invalidFilter", "Unsupported member filter."))?;
    if attribute != "value" || operator != "eq" {
        return Err(Error::bad(
            "invalidFilter",
            "Only members[value eq \"User-id\"] is supported.",
        ));
    }
    let value: String = serde_json::from_str(raw.trim())
        .map_err(|_| Error::bad("invalidFilter", "A quoted User id is required."))?;
    Ok(Some(value.parse().map_err(|_| {
        Error::bad("invalidFilter", "A User id is required.")
    })?))
}

async fn patch_group(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    bytes: Bytes,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    directory::lock_all(&mut tx).await?;
    let c = authenticate(&state, &mut tx, &headers).await?;
    let id = id(&raw)?;
    let mut current = group_value(&state, &mut tx, &c.issuer, id).await?;
    let patch = body(&headers, &bytes)?;
    for value in group_operations(&patch)? {
        let (op, path, value) = operation(value)?;
        if op == "remove" {
            let path =
                path.ok_or_else(|| Error::bad("invalidPath", "remove needs a members path."))?;
            let wanted = remove_member(&path)?;
            let mut members = member_ids(&current["members"])?;
            if let Some(value) = value {
                if path != "members" {
                    return Err(Error::bad(
                        "invalidSyntax",
                        "A filtered member removal cannot also supply a value.",
                    ));
                }
                // Authentik uses a value array for targeted removals. An absent member is
                // an idempotent no-op; it must never mean remove all other members.
                let removed = member_ids(value)?;
                members.retain(|id| !removed.contains(id));
            } else if let Some(user) = wanted {
                members.retain(|id| *id != user);
            } else {
                members.clear();
            }
            current["members"] = json!(members
                .into_iter()
                .map(|id| json!({ "value": id }))
                .collect::<Vec<_>>());
        } else {
            let value = value.ok_or_else(|| Error::bad("invalidValue", "A value is required."))?;
            if let Some(path) = path {
                let key = match path.as_str() {
                    "members" => "members",
                    "displayname" => "displayName",
                    "externalid" => "externalId",
                    _ => return Err(Error::bad("invalidPath", "Unsupported Group PATCH path.")),
                };
                patch_group_fields(&mut current, &json!({ (key): value }), &op)?;
            } else {
                patch_group_fields(&mut current, value, &op)?;
            }
        }
    }
    let input = group_input(&current)?;
    let revoked = update_group(&mut tx, &c.issuer, id, &input).await?;
    audit(&c, "directory.scim.group.patch", "directory_group", id)
        .record(&mut *tx)
        .await?;
    let value = group_value(&state, &mut tx, &c.issuer, id).await?;
    tx.commit().await?;
    directory::finish_revocations(&state, revoked).await?;
    Ok(resource_reply(StatusCode::OK, value))
}

async fn delete_group(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    directory::lock_all(&mut tx).await?;
    let c = authenticate(&state, &mut tx, &headers).await?;
    let id = id(&raw)?;
    group_value(&state, &mut tx, &c.issuer, id).await?;
    let revoked = replace_members(&mut tx, &c.issuer, id, &[]).await?;
    sqlx::query("DELETE FROM directory_groups WHERE id = $1 AND issuer = $2")
        .bind(id)
        .bind(&c.issuer)
        .execute(&mut *tx)
        .await?;
    audit(&c, "directory.scim.group.delete", "directory_group", id)
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    directory::finish_revocations(&state, revoked).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn service_provider_config(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    Ok(reply(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": true }, "bulk": { "supported": false, "maxOperations": 100, "maxPayloadSize": 262144 },
            "filter": { "supported": true, "maxResults": 200 }, "changePassword": { "supported": false },
            "sort": { "supported": false }, "etag": { "supported": false },
            "authenticationSchemes": [{ "type": "oauthbearertoken", "name": "SCIM bearer credential", "description": "A dedicated revocable fw8s_ key issued by a flyw8t administrator.", "primary": true }]
        }),
    ))
}

async fn resource_types(State(state): State<Shared>, headers: HeaderMap) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    let resources = [("User", "/Users", USER), ("Group", "/Groups", GROUP)].into_iter().map(|(name, endpoint, schema)| json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": name, "name": name, "endpoint": endpoint, "schema": schema,
        "meta": { "resourceType": "ResourceType", "location": format!("{}/scim/v2/ResourceTypes/{name}", state.config.public_url) }
    })).collect();
    Ok(reply(StatusCode::OK, list(resources, 2, 1)))
}

fn schema_resources() -> Vec<Value> {
    let attribute = |name, kind, multi, required, mutable| json!({ "name": name, "type": kind, "multiValued": multi, "required": required, "mutability": mutable, "returned": "default", "caseExact": name == "externalId" || name == "value", "uniqueness": "none" });
    let resources = vec![
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"], "id": USER, "name": "User", "attributes": [
            attribute("externalId", "string", false, true, "immutable"), attribute("userName", "string", false, true, "readWrite"),
            attribute("displayName", "string", false, false, "readWrite"), attribute("active", "boolean", false, false, "readWrite"),
            { "name": "emails", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite", "returned": "default", "subAttributes": [attribute("value", "string", false, true, "readWrite"), attribute("primary", "boolean", false, false, "readWrite")] },
            { "name": "groups", "type": "complex", "multiValued": true, "required": false, "mutability": "readOnly", "returned": "default", "subAttributes": [attribute("value", "string", false, true, "readOnly"), attribute("display", "string", false, false, "readOnly")] }
        ] }),
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"], "id": GROUP, "name": "Group", "attributes": [
            attribute("externalId", "string", false, true, "immutable"), attribute("displayName", "string", false, true, "readWrite"),
            { "name": "members", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite", "returned": "default", "subAttributes": [attribute("value", "string", false, true, "readWrite"), attribute("display", "string", false, false, "readOnly")] }
        ] }),
    ];
    resources
}

async fn schemas(State(state): State<Shared>, headers: HeaderMap) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    Ok(reply(StatusCode::OK, list(schema_resources(), 2, 1)))
}

async fn schema_resource(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    let value = schema_resources()
        .into_iter()
        .find(|v| v["id"].as_str() == Some(raw.as_str()))
        .ok_or_else(Error::missing)?;
    Ok(reply(StatusCode::OK, value))
}

async fn resource_type(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Response> {
    let mut tx = state.db.begin().await?;
    authenticate(&state, &mut tx, &headers).await?;
    let (name, endpoint, schema) = match raw.as_str() {
        "User" => ("User", "/Users", USER),
        "Group" => ("Group", "/Groups", GROUP),
        _ => return Err(Error::missing()),
    };
    Ok(reply(
        StatusCode::OK,
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": name, "name": name, "endpoint": endpoint, "schema": schema,
            "meta": { "resourceType": "ResourceType", "location": format!("{}/scim/v2/ResourceTypes/{name}", state.config.public_url) }
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filters_and_paging_refuse_unsupported_or_unbounded_requests() {
        assert_eq!(
            filter("userName eq \"A@example.test\"", true).unwrap().0,
            "username"
        );
        assert_eq!(
            filter("externalId EQ \"subject\"", true).unwrap().1,
            "subject"
        );
        for raw in [
            "userName co \"x\"",
            "password eq \"x\"",
            "userName eq \"x\" or id pr",
            "userName eq x",
        ] {
            assert!(filter(raw, true).is_err(), "accepted {raw}");
        }
        for raw in [
            "count=201",
            "count=-1",
            "startIndex=0",
            "count=1&count=2",
            "sortBy=userName",
        ] {
            assert!(
                pagination(Some(raw.into()), true).is_err(),
                "accepted {raw}"
            );
        }
        assert_eq!(pagination(Some("count=0".into()), true).unwrap().count, 0);
    }
    #[test]
    fn member_removal_has_one_narrow_uuid_filter() {
        let id = Uuid::new_v4();
        assert_eq!(
            remove_member(&format!("members[value eq \"{id}\"]")).unwrap(),
            Some(id)
        );
        assert!(remove_member("members[value co \"x\"]").is_err());
        assert!(remove_member("members[display eq \"x\"]").is_err());
        assert!(remove_member("members[value eq \"x\"]").is_err());
        assert_eq!(remove_member("members").unwrap(), None);
    }
}
