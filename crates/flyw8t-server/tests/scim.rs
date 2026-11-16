//! SCIM's independent credential plane, directory-only identity, atomic membership sync,
//! revocation and synchronization against credential rotation.
mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::*;
use flyw8t_server::{auth, directory};
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

const ISSUER: &str = "https://identity.example.test/application/o/flyw8t/";
const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

async fn setup() -> (TestServer, String, Uuid) {
    let mut config = test_config(&fresh_database().await);
    config.oidc = Some(flyw8t_server::oidc::OidcConfig {
        issuer: ISSUER.into(),
        client_id: "test-client".into(),
        client_secret: "test-client-secret".into(),
    });
    let server = start(config).await;
    let (admin,): (Uuid,) = sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(ADMIN_EMAIL)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    let token = format!("fw8s_{}", auth::random_secret(32));
    let (credential,): (Uuid,) = sqlx::query_as("INSERT INTO scim_credentials(issuer,prefix,token_hash,created_by) VALUES($1,$2,$3,$4) RETURNING id")
        .bind(ISSUER).bind(&token[..13]).bind(auth::digest(&token)).bind(admin).fetch_one(&server.state.db).await.unwrap();
    (server, token, credential)
}

async fn scim(
    server: &TestServer,
    method: Method,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = if let Some(value) = body {
        request = request.header(header::CONTENT_TYPE, "application/scim+json");
        Body::from(value.to_string())
    } else {
        Body::empty()
    };
    server.request(request.body(body).unwrap()).await
}

fn user_body(subject: &str, email: &str) -> Value {
    json!({ "schemas": [USER_SCHEMA], "externalId": subject, "userName": email, "displayName": "Directory Person", "active": true })
}

async fn create_user(server: &TestServer, token: &str, subject: &str, email: &str) -> Uuid {
    let response = scim(
        server,
        Method::POST,
        "/scim/v2/Users",
        token,
        Some(user_body(subject, email)),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
    assert_eq!(
        response.headers[header::CONTENT_TYPE],
        "application/scim+json"
    );
    assert_eq!(response.headers[header::CACHE_CONTROL], "no-store");
    response.json()["id"].as_str().unwrap().parse().unwrap()
}

async fn create_group(server: &TestServer, token: &str, key: &str, members: &[Uuid]) -> Uuid {
    let response = scim(
        server,
        Method::POST,
        "/scim/v2/Groups",
        token,
        Some(json!({
            "schemas": [GROUP_SCHEMA], "externalId": key, "displayName": key,
            "members": members.iter().map(|id| json!({"value": id})).collect::<Vec<_>>()
        })),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
    response.json()["id"].as_str().unwrap().parse().unwrap()
}

async fn mapping(server: &TestServer, group: &str, role: &str, orgs: &[Uuid]) {
    sqlx::query("INSERT INTO directory_mappings(issuer,group_key,role,organization_ids) VALUES($1,$2,$3,$4)")
        .bind(ISSUER).bind(group).bind(role).bind(orgs).execute(&server.state.db).await.unwrap();
}

async fn organization(server: &TestServer, name: &str) -> Uuid {
    sqlx::query_as::<_, (Uuid,)>("INSERT INTO organizations(name) VALUES($1) RETURNING id")
        .bind(name)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

async fn enabled(server: &TestServer, id: Uuid) -> bool {
    sqlx::query_as::<_, (bool,)>("SELECT disabled_at IS NULL FROM users WHERE id=$1")
        .bind(id)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

async fn directory_browser(server: &TestServer, user: Uuid) -> Browser {
    let mut tx = server.state.db.begin().await.unwrap();
    let cookie = auth::create_session(
        &server.state,
        &mut tx,
        user,
        "127.0.0.1",
        "SCIM test",
        auth::Stage::Full,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE sessions SET auth_method='oidc',provider_authenticated_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL")
        .bind(user).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    server
        .browser(cookie.split(';').next().unwrap().to_string())
        .await
}

fn patch(operations: Value) -> Value {
    json!({ "schemas": [PATCH_SCHEMA], "Operations": operations })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn scim_credentials_and_local_accounts_are_separate_planes() {
    let (server, token, credential) = setup().await;
    let admin = server.admin().await;
    let cookie_request = Request::get("/scim/v2/Users")
        .header(header::COOKIE, &admin.cookie)
        .body(Body::empty())
        .unwrap();
    let refused = server.request(cookie_request).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.json()["status"], "401");
    assert_eq!(refused.headers[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(
        scim(
            &server,
            Method::GET,
            "/scim/v2/Users",
            "fw8_personal_token_cannot_sync_directory",
            None
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .api(Method::GET, "/api/v1/devices", &token, None, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let local_collision = scim(
        &server,
        Method::POST,
        "/scim/v2/Users",
        &token,
        Some(user_body("different-subject", ADMIN_EMAIL)),
    )
    .await;
    assert_eq!(
        local_collision.status,
        StatusCode::BAD_REQUEST,
        "{}",
        local_collision.body
    );
    let local: Uuid = sqlx::query_as::<_, (Uuid,)>("SELECT id FROM users WHERE email=$1")
        .bind(ADMIN_EMAIL)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0;
    assert_eq!(
        scim(
            &server,
            Method::GET,
            &format!("/scim/v2/Users/{local}"),
            &token,
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        scim(
            &server,
            Method::DELETE,
            &format!("/scim/v2/Users/{local}"),
            &token,
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert!(enabled(&server, local).await);
    let list = scim(&server, Method::GET, "/scim/v2/Users", &token, None).await;
    assert_eq!(list.json()["totalResults"], 0);
    assert!(!list.body.contains(&token));
    let (hash,): (Vec<u8>,) = sqlx::query_as("SELECT token_hash FROM scim_credentials WHERE id=$1")
        .bind(credential)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(hash, auth::digest(&token));
    assert_ne!(hash, token.as_bytes());
    sqlx::query("UPDATE scim_credentials SET revoked_at=now() WHERE id=$1")
        .bind(credential)
        .execute(&server.state.db)
        .await
        .unwrap();
    assert_eq!(
        scim(&server, Method::GET, "/scim/v2/Users", &token, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn membership_sync_applies_role_scope_and_revokes_every_form_of_old_authority() {
    let (server, token, _) = setup().await;
    let acme = organization(&server, "Acme").await;
    let beta = organization(&server, "Beta").await;
    mapping(&server, "technicians", "technician", &[acme, beta]).await;
    mapping(&server, "viewers", "readonly", &[beta]).await;
    let user = create_user(&server, &token, "opaque-subject", "person@example.test").await;
    assert!(
        !enabled(&server, user).await,
        "no mapped group means no access"
    );
    let group = create_group(&server, &token, "technicians", &[user]).await;
    create_group(&server, &token, "viewers", &[user]).await;
    assert!(enabled(&server, user).await);
    let browser = directory_browser(&server, user).await;
    assert_eq!(
        browser
            .get(&server, &format!("/organizations/{acme}"))
            .await
            .status,
        StatusCode::OK
    );
    let pat = format!("fw8_{}", auth::random_secret(32));
    sqlx::query("INSERT INTO api_tokens(user_id,name,prefix,token_hash,scopes) VALUES($1,'directory token',$2,$3,ARRAY['read','jobs:run'])")
        .bind(user).bind(&pat[..12]).bind(auth::digest(&pat)).execute(&server.state.db).await.unwrap();
    sqlx::query("INSERT INTO enrollment_tokens(organization_id,token_hash,created_by,expires_at,max_uses) VALUES($1,$2,$3,now()+interval '1 hour',1)")
        .bind(acme).bind(auth::digest("test enrollment secret")).bind(user).execute(&server.state.db).await.unwrap();
    let support = browser
        .post(
            &server,
            "/support",
            &[
                ("organization", &acme.to_string()),
                ("capability", "view"),
                ("note", "Directory support"),
            ],
        )
        .await;
    assert_eq!(support.status, StatusCode::OK, "{}", support.body);
    let changed = scim(
        &server,
        Method::PATCH,
        &format!("/scim/v2/Groups/{group}"),
        &token,
        Some(patch(
            json!([{ "op": "remove", "path": format!("members[value eq \"{user}\"]") }]),
        )),
    )
    .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    let (role,): (String,) = sqlx::query_as("SELECT role FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(role, "readonly");
    let assignments: Vec<(Uuid,)> =
        sqlx::query_as("SELECT organization_id FROM user_organizations WHERE user_id=$1")
            .bind(user)
            .fetch_all(&server.state.db)
            .await
            .unwrap();
    assert_eq!(assignments, vec![(beta,)]);
    assert_eq!(
        browser.get(&server, "/").await.status,
        StatusCode::SEE_OTHER,
        "old browser must be signed out"
    );
    assert_eq!(
        server
            .api(Method::GET, "/api/v1/devices", &pat, None, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let (sessions, api, enrollment, support): (i64,i64,i64,i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL),
                (SELECT count(*) FROM api_tokens WHERE user_id=$1 AND revoked_at IS NULL),
                (SELECT count(*) FROM enrollment_tokens WHERE created_by=$1 AND revoked_at IS NULL),
                (SELECT count(*) FROM support_sessions WHERE created_by=$1 AND state IN ('created','waiting','authorizing','connecting','connected'))")
        .bind(user).fetch_one(&server.state.db).await.unwrap();
    assert_eq!((sessions, api, enrollment, support), (0, 0, 0, 0));
    let fresh = directory_browser(&server, user).await;
    assert_eq!(
        fresh
            .get(&server, &format!("/organizations/{acme}"))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fresh
            .get(&server, &format!("/organizations/{beta}"))
            .await
            .status,
        StatusCode::OK
    );
    let deleted = scim(
        &server,
        Method::DELETE,
        &format!("/scim/v2/Users/{user}"),
        &token,
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert!(!enabled(&server, user).await);
    assert_eq!(fresh.get(&server, "/").await.status, StatusCode::SEE_OTHER);
    let (active, subject): (bool, String) =
        sqlx::query_as("SELECT active,subject FROM directory_users WHERE user_id=$1")
            .bind(user)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert!(!active);
    assert_eq!(subject, "opaque-subject");
    let retained = scim(
        &server,
        Method::GET,
        &format!("/scim/v2/Users/{user}"),
        &token,
        None,
    )
    .await;
    assert_eq!(retained.status, StatusCode::OK);
    assert_eq!(retained.json()["active"], false);
    let listed = scim(
        &server,
        Method::GET,
        "/scim/v2/Users?filter=externalId%20eq%20%22opaque-subject%22",
        &token,
        None,
    )
    .await
    .json();
    assert_eq!(listed["totalResults"], 1);
    assert_eq!(listed["Resources"][0]["active"], false);
    let restored = scim(
        &server,
        Method::PUT,
        &format!("/scim/v2/Users/{user}"),
        &token,
        Some(user_body("opaque-subject", "person@example.test")),
    )
    .await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.body);
    assert_eq!(restored.json()["id"], user.to_string());
    assert_eq!(restored.json()["active"], true);
    assert!(enabled(&server, user).await);
    assert_eq!(
        fresh.get(&server, "/").await.status,
        StatusCode::SEE_OTHER,
        "restoration never restores revoked sessions"
    );
    assert_eq!(
        server
            .api(Method::GET, "/api/v1/devices", &pat, None, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn user_updates_are_atomic_and_identity_is_immutable() {
    let (server, token, _) = setup().await;
    mapping(&server, "readers", "readonly", &[]).await;
    let user = create_user(&server, &token, "stable-subject", "original@example.test").await;
    create_group(&server, &token, "readers", &[user]).await;
    let path = format!("/scim/v2/Users/{user}");
    let duplicate = scim(
        &server,
        Method::POST,
        "/scim/v2/Users",
        &token,
        Some(user_body("stable-subject", "other@example.test")),
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::BAD_REQUEST);
    let refused = scim(
        &server,
        Method::PATCH,
        &path,
        &token,
        Some(patch(json!([
            { "op": "replace", "path": "displayName", "value": "Must roll back" },
            { "op": "replace", "path": "externalId", "value": "replacement-subject" }
        ]))),
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.json()["scimType"], "mutability");
    let original = scim(&server, Method::GET, &path, &token, None).await.json();
    assert_eq!(original["displayName"], "Directory Person");
    assert_eq!(original["externalId"], "stable-subject");
    let renamed = scim(&server, Method::PATCH, &path, &token, Some(patch(json!([
        { "op": "replace", "value": { "userName": "renamed@example.test", "displayName": "Renamed" } }
    ])))).await;
    assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.body);
    assert_eq!(renamed.json()["userName"], "renamed@example.test");
    assert!(enabled(&server, user).await);
    let disabled = scim(
        &server,
        Method::PATCH,
        &path,
        &token,
        Some(patch(
            json!([{ "op": "replace", "path": "active", "value": false }]),
        )),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.body);
    assert!(!enabled(&server, user).await);
    let restored = scim(
        &server,
        Method::PUT,
        &path,
        &token,
        Some(user_body("stable-subject", "renamed@example.test")),
    )
    .await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.body);
    assert!(enabled(&server, user).await);
    let local_password = server
        .request(
            server
                .login_request("renamed@example.test", "!directory-only")
                .await,
        )
        .await;
    assert_eq!(local_password.status, StatusCode::UNAUTHORIZED);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn group_updates_refuse_local_or_foreign_members_and_roll_back_all_operations() {
    let (server, token, _) = setup().await;
    mapping(&server, "operators", "technician", &[]).await;
    let user = create_user(&server, &token, "member", "member@example.test").await;
    let group = create_group(&server, &token, "operators", &[user]).await;
    let (local,): (Uuid,) = sqlx::query_as("SELECT id FROM users WHERE email=$1")
        .bind(ADMIN_EMAIL)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    let path = format!("/scim/v2/Groups/{group}");
    let invalid = scim(
        &server,
        Method::PATCH,
        &path,
        &token,
        Some(patch(json!([
            { "op": "remove", "path": "members" },
            { "op": "add", "path": "members", "value": [{ "value": local }] }
        ]))),
    )
    .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST, "{}", invalid.body);
    let after = scim(&server, Method::GET, &path, &token, None).await.json();
    assert_eq!(after["members"].as_array().unwrap().len(), 1);
    assert_eq!(after["members"][0]["value"], user.to_string());
    assert!(enabled(&server, user).await);
    let foreign = {
        let mut tx = server.state.db.begin().await.unwrap();
        directory::lock_all(&mut tx).await.unwrap();
        let user = directory::ensure_identity(
            &mut tx,
            "https://different-issuer.example.test/",
            "foreign",
            "foreign@example.test",
            "Foreign User",
            true,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        user
    };
    let invalid = scim(
        &server,
        Method::PATCH,
        &path,
        &token,
        Some(patch(json!([
            { "op": "add", "path": "members", "value": [{ "value": foreign }] }
        ]))),
    )
    .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST, "{}", invalid.body);
    assert_eq!(
        scim(
            &server,
            Method::GET,
            &format!("/scim/v2/Users/{foreign}"),
            &token,
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    let unsupported = scim(
        &server,
        Method::PATCH,
        &path,
        &token,
        Some(patch(json!([
            { "op": "remove", "path": "members" },
            { "op": "replace", "path": "password", "value": "bad" }
        ]))),
    )
    .await;
    assert_eq!(unsupported.status, StatusCode::BAD_REQUEST);
    let after = scim(&server, Method::GET, &path, &token, None).await.json();
    assert_eq!(after["members"].as_array().unwrap().len(), 1);
    let deleted = scim(&server, Method::DELETE, &path, &token, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.body);
    assert!(!enabled(&server, user).await);
    assert_eq!(
        scim(&server, Method::GET, &path, &token, None).await.status,
        StatusCode::NOT_FOUND
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn list_filters_paging_and_metadata_are_bounded_and_explicit() {
    let (server, token, _) = setup().await;
    create_user(&server, &token, "subject-one", "one@example.test").await;
    create_user(&server, &token, "subject-two", "two@example.test").await;
    let filtered = scim(
        &server,
        Method::GET,
        "/scim/v2/Users?filter=externalId%20eq%20%22subject-two%22&count=1",
        &token,
        None,
    )
    .await;
    assert_eq!(filtered.status, StatusCode::OK, "{}", filtered.body);
    assert_eq!(filtered.json()["totalResults"], 1);
    assert_eq!(
        filtered.json()["Resources"][0]["userName"],
        "two@example.test"
    );
    let empty = scim(&server, Method::GET, "/scim/v2/Users?count=0", &token, None)
        .await
        .json();
    assert_eq!(empty["totalResults"], 2);
    assert_eq!(empty["itemsPerPage"], 0);
    let page = scim(
        &server,
        Method::GET,
        "/scim/v2/Users?count=1&startIndex=2",
        &token,
        None,
    )
    .await
    .json();
    assert_eq!(page["totalResults"], 2);
    assert_eq!(page["startIndex"], 2);
    assert_eq!(page["Resources"].as_array().unwrap().len(), 1);
    for path in [
        "/scim/v2/Users?count=201",
        "/scim/v2/Users?startIndex=-1",
        "/scim/v2/Users?filter=userName%20co%20%22x%22",
        "/scim/v2/Users?attributes=password",
    ] {
        let response = scim(&server, Method::GET, path, &token, None).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{path}: {}",
            response.body
        );
        assert_eq!(
            response.json()["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:Error"
        );
    }
    for path in [
        "/scim/v2/ServiceProviderConfig",
        "/scim/v2/ResourceTypes",
        "/scim/v2/Schemas",
    ] {
        let response = scim(&server, Method::GET, path, &token, None).await;
        assert_eq!(response.status, StatusCode::OK, "{path}: {}", response.body);
    }
    let unsupported = scim(&server, Method::POST, "/scim/v2/Users", &token, Some(json!({
        "schemas": [USER_SCHEMA], "externalId": "new", "userName": "new@example.test", "password": "cannot provision a password"
    }))).await;
    assert_eq!(unsupported.status, StatusCode::BAD_REQUEST);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn concurrent_directory_deprovision_cannot_remove_the_last_enabled_administrator() {
    let (server, token, _) = setup().await;
    mapping(&server, "admins", "admin", &[]).await;
    let first = create_user(&server, &token, "first", "first@example.test").await;
    let second = create_user(&server, &token, "second", "second@example.test").await;
    let group = create_group(&server, &token, "admins", &[first, second]).await;
    sqlx::query("UPDATE users SET disabled_at=now() WHERE email=$1")
        .bind(ADMIN_EMAIL)
        .execute(&server.state.db)
        .await
        .unwrap();
    let first_path = format!("/scim/v2/Users/{first}");
    let second_path = format!("/scim/v2/Users/{second}");
    let deprovision = patch(json!([{ "op": "replace", "path": "active", "value": false }]));
    let (a, b) = tokio::join!(
        scim(
            &server,
            Method::PATCH,
            &first_path,
            &token,
            Some(deprovision.clone())
        ),
        scim(
            &server,
            Method::PATCH,
            &second_path,
            &token,
            Some(deprovision)
        )
    );
    let mut statuses = [a.status.as_u16(), b.status.as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 409], "{} / {}", a.body, b.body);
    let (enabled,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM users WHERE role='admin' AND disabled_at IS NULL")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(enabled, 1);
    let group_path = format!("/scim/v2/Groups/{group}");
    let refused = scim(&server, Method::DELETE, &group_path, &token, None).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    let intact = scim(&server, Method::GET, &group_path, &token, None)
        .await
        .json();
    assert_eq!(
        intact["members"].as_array().unwrap().len(),
        2,
        "a rejected change must roll back group membership too"
    );
    let (enabled,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM users WHERE role='admin' AND disabled_at IS NULL")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(enabled, 1);
    let (remaining,): (Uuid,) =
        sqlx::query_as("SELECT id FROM users WHERE role='admin' AND disabled_at IS NULL")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    let fixture_remove =
        patch(json!([{"op":"remove","path":"members","value":[{"value":remaining}]}]));
    let refused = scim(
        &server,
        Method::PATCH,
        &group_path,
        &token,
        Some(fixture_remove),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::CONFLICT,
        "Authentik removal cannot delete the last admin: {}",
        refused.body
    );
    assert!(self::enabled(&server, remaining).await);
    let intact = scim(&server, Method::GET, &group_path, &token, None)
        .await
        .json();
    assert_eq!(
        intact["members"].as_array().unwrap().len(),
        2,
        "failed targeted removal must roll back membership"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_key_revoked_while_sync_waits_on_directory_lock_cannot_finish_a_write() {
    use tower::ServiceExt;
    let (server, token, credential) = setup().await;
    let user = create_user(&server, &token, "waiting-subject", "waiting@example.test").await;
    let mut blocker = server.state.db.begin().await.unwrap();
    directory::lock_all(&mut blocker).await.unwrap();
    let state = server.state.clone();
    let request = Request::patch(format!("/scim/v2/Users/{user}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/scim+json")
        .body(Body::from(patch(json!([{ "op": "replace", "path": "displayName", "value": "Revoked request must not write" }])).to_string())).unwrap();
    let pending =
        tokio::spawn(async move { flyw8t_server::router(state).oneshot(request).await.unwrap() });
    wait_for("SCIM request waiting on directory advisory lock", Duration::from_secs(10), || async {
        sqlx::query_as::<_, (bool,)>("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock%')")
            .fetch_one(&server.state.db).await.unwrap().0
    }).await;
    sqlx::query("UPDATE scim_credentials SET revoked_at=now() WHERE id=$1")
        .bind(credential)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let (name,): (String,) = sqlx::query_as("SELECT display_name FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(name, "Directory Person");
    server.stop().await;
}

async fn issue_scim(server: &TestServer, browser: &Browser) -> String {
    let response = browser
        .post(server, "/admin/directory/credentials", &[])
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(response.headers[header::CACHE_CONTROL], "no-store");
    let secret = extract(&response.body, r"<code>(fw8s_[A-Za-z0-9_-]{43})</code>")
        .expect("SCIM credential shown once");
    let reload = browser.get(server, "/admin/directory").await;
    assert!(
        !reload.body.contains(&secret),
        "reload must not redisplay a secret"
    );
    let (leaked,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_events WHERE detail::text LIKE '%' || $1 || '%'",
    )
    .bind(&secret)
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(
        leaked, 0,
        "the audit log must not contain the raw credential"
    );
    secret
}

async fn create_local_admin(server: &TestServer, admin: &Browser, email: &str) -> Uuid {
    let response = admin
        .post(
            server,
            "/admin/users",
            &[
                ("email", email),
                ("display_name", "Credential Owner"),
                ("password", "credential-owner-password"),
                ("role", "admin"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER, "{}", response.body);
    sqlx::query_as::<_, (Uuid,)>("SELECT id FROM users WHERE email=$1")
        .bind(email)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_scim_key_dies_when_its_creator_is_disabled_demoted_or_directory_deprovisioned() {
    let (server, _, _) = setup().await;
    let admin = server.admin_sudo().await;
    for change in ["disable", "demote"] {
        let email = format!("{change}-owner@example.test");
        let owner = create_local_admin(&server, &admin, &email).await;
        let browser = server.login(&email, "credential-owner-password").await;
        browser.sudo(&server, "credential-owner-password").await;
        let token = issue_scim(&server, &browser).await;
        assert_eq!(
            scim(&server, Method::GET, "/scim/v2/Users", &token, None)
                .await
                .status,
            StatusCode::OK
        );
        let response = if change == "disable" {
            admin
                .post(&server, &format!("/admin/users/{owner}/disable"), &[])
                .await
        } else {
            admin
                .post(
                    &server,
                    &format!("/admin/users/{owner}/edit"),
                    &[
                        ("display_name", "Former administrator"),
                        ("role", "readonly"),
                    ],
                )
                .await
        };
        assert_eq!(
            response.status,
            StatusCode::SEE_OTHER,
            "{change}: {}",
            response.body
        );
        assert_eq!(
            scim(&server, Method::GET, "/scim/v2/Users", &token, None)
                .await
                .status,
            StatusCode::UNAUTHORIZED,
            "{change}: creator's old key stayed authorized"
        );
    }
    // Exercise the same ownership invariant through a real directory membership sync.
    let bootstrap_token = issue_scim(&server, &admin).await;
    mapping(&server, "directory-key-owner", "admin", &[]).await;
    let owner = create_user(
        &server,
        &bootstrap_token,
        "directory-key-owner",
        "directory-key-owner@example.test",
    )
    .await;
    let group = create_group(&server, &bootstrap_token, "directory-key-owner", &[owner]).await;
    let browser = directory_browser(&server, owner).await;
    let mut key = SoftKey::new(&server);
    assert_eq!(
        browser.add_passkey(&server, &key, &[]).await.location(),
        "/account?m=passkey-added"
    );
    assert_eq!(
        browser
            .confirm_sudo(&server, &mut key, "/admin/directory")
            .await
            .location(),
        "/admin/directory"
    );
    let token = issue_scim(&server, &browser).await;
    let response = scim(
        &server,
        Method::PATCH,
        &format!("/scim/v2/Groups/{group}"),
        &token,
        Some(patch(json!([{ "op": "remove", "path": "members" }]))),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert!(!enabled(&server, owner).await);
    assert_eq!(
        scim(&server, Method::GET, "/scim/v2/Users", &token, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED,
        "directory reconciliation must revoke the creator's key"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn directory_identity_cannot_use_or_change_local_passwords_or_override_mapped_role() {
    let (server, token, _) = setup().await;
    let admin = server.admin_sudo().await;
    mapping(&server, "directory-only", "readonly", &[]).await;
    let user = create_user(
        &server,
        &token,
        "directory-only",
        "directory-only@example.test",
    )
    .await;
    create_group(&server, &token, "directory-only", &[user]).await;
    // A usable hash proves the identity-plane checks, rather than merely relying on the
    // normal '!directory-only' sentinel being impossible to verify as Argon2.
    let original_hash = auth::hash_password("a-valid-local-looking-password").unwrap();
    sqlx::query("UPDATE users SET password_hash=$2 WHERE id=$1")
        .bind(user)
        .bind(&original_hash)
        .execute(&server.state.db)
        .await
        .unwrap();
    let password_login = server
        .request(
            server
                .login_request(
                    "directory-only@example.test",
                    "a-valid-local-looking-password",
                )
                .await,
        )
        .await;
    assert_eq!(
        password_login.status,
        StatusCode::UNAUTHORIZED,
        "a directory identity used a local password"
    );
    let response = admin
        .post(&server, &format!("/admin/users/{user}/password"), &[])
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    let browser = directory_browser(&server, user).await;
    let response = browser
        .post(
            &server,
            "/account/password",
            &[
                ("current", "a-valid-local-looking-password"),
                ("new", "a-different-valid-password"),
                ("repeat", "a-different-valid-password"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    let response = admin
        .post(
            &server,
            &format!("/admin/users/{user}/edit"),
            &[
                ("display_name", "Not directory managed anymore"),
                ("role", "admin"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    let (hash, name, role): (String, String, String) =
        sqlx::query_as("SELECT password_hash,display_name,role FROM users WHERE id=$1")
            .bind(user)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(
        hash, original_hash,
        "local password mutation changed a directory account"
    );
    assert_eq!(name, "Directory Person");
    assert_eq!(role, "readonly");
    server.stop().await;
}
// These literal serialized fixtures were produced by installed Authentik 2026.5.3
// groups.py _update_patch_general/_patch_remove_users/_patch_chunked. Only public
// synthetic UUIDs were supplied; this test performs no live provisioning.
fn authentik_fixture(general: bool, group: Uuid, user: Uuid) -> Value {
    let raw = if general {
        include_str!("fixtures/authentik-2026.5.3-group-general.json")
    } else {
        include_str!("fixtures/authentik-2026.5.3-group-remove.json")
    };
    serde_json::from_str(
        &raw.replace("22222222-2222-2222-2222-222222222222", &group.to_string())
            .replace("33333333-3333-3333-3333-333333333333", &user.to_string()),
    )
    .unwrap()
}
const AUTHENTIK_GROUP_KEY: &str = "11111111-1111-1111-1111-111111111111";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn authentik_metadata_and_member_removal_fixtures_preserve_other_members_and_revoke_removed_authority(
) {
    let (server, token, _) = setup().await;
    let org = organization(&server, "Authentik fixture organization").await;
    mapping(&server, AUTHENTIK_GROUP_KEY, "technician", &[org]).await;
    let first = create_user(
        &server,
        &token,
        "fixture-first",
        "fixture-first@example.test",
    )
    .await;
    let second = create_user(
        &server,
        &token,
        "fixture-second",
        "fixture-second@example.test",
    )
    .await;
    let group = create_group(&server, &token, AUTHENTIK_GROUP_KEY, &[first, second]).await;
    let first_browser = directory_browser(&server, first).await;
    let second_browser = directory_browser(&server, second).await;
    let pat = format!("fw8_{}", auth::random_secret(32));
    sqlx::query("INSERT INTO api_tokens(user_id,name,prefix,token_hash,scopes) VALUES($1,'fixture',$2,$3,ARRAY['read'])").bind(first).bind(&pat[..12]).bind(auth::digest(&pat)).execute(&server.state.db).await.unwrap();
    sqlx::query("INSERT INTO enrollment_tokens(organization_id,token_hash,created_by,expires_at,max_uses) VALUES($1,$2,$3,now()+interval '1 hour',1)").bind(org).bind(auth::digest("fixture enrollment")).bind(first).execute(&server.state.db).await.unwrap();
    assert_eq!(
        first_browser
            .post(
                &server,
                "/support",
                &[
                    ("organization", &org.to_string()),
                    ("capability", "view"),
                    ("note", "Fixture support")
                ]
            )
            .await
            .status,
        StatusCode::OK
    );
    let path = format!("/scim/v2/Groups/{group}");
    let metadata = scim(
        &server,
        Method::PATCH,
        &path,
        &token,
        Some(authentik_fixture(true, group, first)),
    )
    .await;
    assert_eq!(metadata.status, StatusCode::OK, "{}", metadata.body);
    assert_eq!(metadata.json()["displayName"], "Synthetic Group");
    assert_eq!(
        metadata.json()["members"].as_array().unwrap().len(),
        2,
        "metadata omission must retain members"
    );
    let removed = scim(
        &server,
        Method::PATCH,
        &path,
        &token,
        Some(authentik_fixture(false, group, first)),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.body);
    assert_eq!(removed.json()["members"].as_array().unwrap().len(), 1);
    assert_eq!(removed.json()["members"][0]["value"], second.to_string());
    assert!(!enabled(&server, first).await);
    assert!(enabled(&server, second).await);
    assert_eq!(
        first_browser.get(&server, "/").await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        second_browser.get(&server, "/").await.status,
        StatusCode::OK
    );
    assert_eq!(
        server
            .api(Method::GET, "/api/v1/devices", &pat, None, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let (enrollments,support):(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM enrollment_tokens WHERE created_by=$1 AND revoked_at IS NULL),(SELECT count(*) FROM support_sessions WHERE created_by=$1 AND state IN ('created','waiting','authorizing','connecting','connected'))").bind(first).fetch_one(&server.state.db).await.unwrap();
    assert_eq!((enrollments, support), (0, 0));
    let repeated = scim(
        &server,
        Method::PATCH,
        &path,
        &token,
        Some(authentik_fixture(false, group, first)),
    )
    .await;
    assert_eq!(repeated.status, StatusCode::OK, "{}", repeated.body);
    assert_eq!(repeated.json()["members"].as_array().unwrap().len(), 1);
    assert_eq!(
        second_browser.get(&server, "/").await.status,
        StatusCode::OK,
        "idempotent targeted removal cannot revoke other members"
    );
    let config = scim(
        &server,
        Method::GET,
        "/scim/v2/ServiceProviderConfig",
        &token,
        None,
    )
    .await
    .json();
    assert_eq!(config["bulk"]["supported"], false);
    assert_eq!(config["bulk"]["maxOperations"], 100);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn authentik_compatibility_rejects_ambiguous_removals_and_identity_changes_atomically() {
    let (server, token, _) = setup().await;
    let user = create_user(
        &server,
        &token,
        "negative-fixture",
        "negative-fixture@example.test",
    )
    .await;
    let group = create_group(&server, &token, AUTHENTIK_GROUP_KEY, &[user]).await;
    let path = format!("/scim/v2/Groups/{group}");
    let fixture = authentik_fixture(true, group, user);
    let mut cases = Vec::new();
    for (field, value) in [
        ("id", json!(Uuid::new_v4())),
        ("externalId", json!("changed")),
        ("schemas", json!([USER_SCHEMA])),
        ("unexpected", json!(true)),
    ] {
        let mut value_fixture = fixture.clone();
        value_fixture["Operations"][0]["value"][field] = value;
        cases.push(value_fixture);
    }
    let mut wrong_outer = fixture.clone();
    wrong_outer["schemas"] = json!([GROUP_SCHEMA]);
    cases.push(wrong_outer);
    cases.push(json!({"Operations":[{"op":"remove","path":"members","value":[{"value":user}]}]}));
    cases.push(json!({"Operations":[{"op":"replace","path":"displayName","value":"name"}]}));
    for bad in [
        json!("not an array"),
        json!([{"value":"not-a-uuid"}]),
        json!([{"value":user,"unexpected":true}]),
        json!(vec![json!({"value":user}); 1001]),
    ] {
        cases.push(patch(json!([{ "op":"replace","path":"displayName","value":"must roll back"},{"op":"remove","path":"members","value":bad}])));
    }
    cases.push(patch(json!([{"op":"replace","path":"displayName","value":"must roll back"},{"op":"remove","path":format!("members[value eq \"{user}\"]"),"value":[{"value":user}]}])));
    for body in cases {
        let response = scim(&server, Method::PATCH, &path, &token, Some(body.clone())).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "accepted malformed fixture {body}: {}",
            response.body
        );
        let current = scim(&server, Method::GET, &path, &token, None).await.json();
        assert_eq!(current["displayName"], AUTHENTIK_GROUP_KEY);
        assert_eq!(current["externalId"], AUTHENTIK_GROUP_KEY);
        assert_eq!(current["members"].as_array().unwrap().len(), 1);
        assert_eq!(current["members"][0]["value"], user.to_string());
    }
    let foreign = Uuid::new_v4();
    let (local,): (Uuid,) = sqlx::query_as("SELECT id FROM users WHERE email=$1")
        .bind(ADMIN_EMAIL)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    let absent = patch(
        json!([{"op":"remove","path":"members","value":[{"value":foreign},{"value":local}]}]),
    );
    let result = scim(&server, Method::PATCH, &path, &token, Some(absent)).await;
    assert_eq!(result.status, StatusCode::OK);
    assert_eq!(result.json()["members"].as_array().unwrap().len(), 1);
    let (other,):(Uuid,)=sqlx::query_as("INSERT INTO directory_groups(issuer,external_id,display_name) VALUES('https://other.example','other','Other issuer') RETURNING id").fetch_one(&server.state.db).await.unwrap();
    let result = scim(
        &server,
        Method::PATCH,
        &format!("/scim/v2/Groups/{other}"),
        &token,
        Some(authentik_fixture(true, other, user)),
    )
    .await;
    assert_eq!(result.status, StatusCode::NOT_FOUND);
    let (name,): (String,) =
        sqlx::query_as("SELECT display_name FROM directory_groups WHERE id=$1")
            .bind(other)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(name, "Other issuer");
    server.stop().await;
}
// Synthetic driver for installed Authentik2026.5.3's create decision: only409
// triggers an email/displayName lookup;200/201 bind the immutable response.id directly.
async fn authentik_binding(
    server: &TestServer,
    token: &str,
    kind: &str,
    attribute: &str,
    name: &str,
    response: &Response,
) -> (Option<Uuid>, usize) {
    if response.status == StatusCode::CONFLICT {
        let filter = format!("{attribute} eq {}", serde_json::to_string(name).unwrap());
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("filter", &filter)
            .finish();
        let list = scim(
            server,
            Method::GET,
            &format!("/scim/v2/{kind}?{query}"),
            token,
            None,
        )
        .await
        .json();
        (
            list["Resources"]
                .as_array()
                .and_then(|rows| rows.first())
                .and_then(|row| row["id"].as_str())
                .and_then(|id| id.parse().ok()),
            1,
        )
    } else if response.status.is_success() {
        (
            response.json()["id"]
                .as_str()
                .and_then(|id| id.parse().ok()),
            0,
        )
    } else {
        (None, 0)
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn user_post_binds_exact_subject_directly_and_never_adopts_a_mutable_email_match() {
    let (server, token, _) = setup().await;
    let first = create_user(&server, &token, "post-subject-a", "post-a@example.test").await;
    let second = create_user(&server, &token, "post-subject-b", "post-b@example.test").await;
    for body in [
        user_body("different-subject", "post-a@example.test"),
        user_body("post-subject-a", "post-b@example.test"),
        user_body("post-subject-a", "unused-new-email@example.test"),
        user_body("different-local-subject", ADMIN_EMAIL),
    ] {
        let response = scim(
            &server,
            Method::POST,
            "/scim/v2/Users",
            &token,
            Some(body.clone()),
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "must not expose Authentik409adoption: {}",
            response.body
        );
        assert_eq!(
            authentik_binding(
                &server,
                &token,
                "Users",
                "userName",
                body["userName"].as_str().unwrap(),
                &response
            )
            .await,
            (None, 0)
        );
    }
    for (field, value) in [
        ("displayName", json!("Changed profile")),
        ("active", json!(false)),
    ] {
        let mut body = user_body("post-subject-a", "post-a@example.test");
        body[field] = value;
        let response = scim(&server, Method::POST, "/scim/v2/Users", &token, Some(body)).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    }
    let body = user_body("post-subject-a", "POST-A@EXAMPLE.TEST");
    let response = scim(&server, Method::POST, "/scim/v2/Users", &token, Some(body)).await;
    assert!(
        response.status.is_success() || response.status == StatusCode::CONFLICT,
        "{}",
        response.body
    );
    // Rename and reuse the old email AFTER the POST response, before a naive fallback GET.
    let renamed = scim(
        &server,
        Method::PATCH,
        &format!("/scim/v2/Users/{first}"),
        &token,
        Some(patch(
            json!([{"op":"replace","path":"userName","value":"moved-a@example.test"}]),
        )),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::OK);
    let replacement = create_user(&server, &token, "post-subject-c", "post-a@example.test").await;
    assert_ne!(replacement, first);
    assert_eq!(
        authentik_binding(
            &server,
            &token,
            "Users",
            "userName",
            "post-a@example.test",
            &response
        )
        .await,
        (Some(first), 0),
        "a separate mutable-email lookup would bind the replacement subject"
    );
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["externalId"], "post-subject-a");
    let current = scim(
        &server,
        Method::GET,
        &format!("/scim/v2/Users/{first}"),
        &token,
        None,
    )
    .await
    .json();
    assert_eq!(current["externalId"], "post-subject-a");
    assert_eq!(current["userName"], "moved-a@example.test");
    let current = scim(
        &server,
        Method::GET,
        &format!("/scim/v2/Users/{second}"),
        &token,
        None,
    )
    .await
    .json();
    assert_eq!(current["externalId"], "post-subject-b");
    server.stop().await;
}

async fn named_group(
    server: &TestServer,
    token: &str,
    key: &str,
    name: &str,
    members: Option<&[Uuid]>,
) -> Response {
    let mut value = json!({"schemas":[GROUP_SCHEMA],"externalId":key,"displayName":name});
    if let Some(members) = members {
        value["members"] = json!(members
            .iter()
            .map(|id| json!({"value":id}))
            .collect::<Vec<_>>());
    }
    scim(server, Method::POST, "/scim/v2/Groups", token, Some(value)).await
}
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn group_post_binds_exact_key_directly_and_refuses_name_ambiguity_or_membership_drift() {
    let (server, token, _) = setup().await;
    let first = create_user(
        &server,
        &token,
        "group-post-first",
        "group-post-first@example.test",
    )
    .await;
    let second = create_user(
        &server,
        &token,
        "group-post-second",
        "group-post-second@example.test",
    )
    .await;
    let created = named_group(
        &server,
        &token,
        "post-group-a",
        "Unique group",
        Some(&[first]),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let group: Uuid = created.json()["id"].as_str().unwrap().parse().unwrap();
    let replay = named_group(&server, &token, "post-group-a", "UNIQUE GROUP", None).await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(replay.json()["id"], group.to_string());
    assert_eq!(
        replay.json()["members"].as_array().unwrap().len(),
        1,
        "metadata-only create replay must preserve members"
    );
    assert_eq!(
        authentik_binding(
            &server,
            &token,
            "Groups",
            "displayName",
            "UNIQUE GROUP",
            &replay
        )
        .await,
        (Some(group), 0)
    );
    let changed = named_group(
        &server,
        &token,
        "post-group-a",
        "Unique group",
        Some(&[second]),
    )
    .await;
    assert_eq!(changed.status, StatusCode::BAD_REQUEST);
    let changed = named_group(&server, &token, "post-group-a", "Changed name", None).await;
    assert_eq!(changed.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        authentik_binding(
            &server,
            &token,
            "Groups",
            "displayName",
            "Changed name",
            &changed
        )
        .await,
        (None, 0)
    );
    let ambiguous = named_group(&server, &token, "post-group-b", "unique GROUP", None).await;
    assert_eq!(ambiguous.status, StatusCode::CREATED);
    for name in ["Unique group", "UNIQUE GROUP"] {
        let response = named_group(&server, &token, "post-group-a", name, None).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            authentik_binding(&server, &token, "Groups", "displayName", name, &response).await,
            (None, 0)
        );
    }
    let created = named_group(&server, &token, "race-group-a", "Race group", None).await;
    let race: Uuid = created.json()["id"].as_str().unwrap().parse().unwrap();
    let response = named_group(&server, &token, "race-group-a", "Race group", None).await;
    let renamed = scim(
        &server,
        Method::PATCH,
        &format!("/scim/v2/Groups/{race}"),
        &token,
        Some(patch(
            json!([{"op":"replace","path":"displayName","value":"Moved race group"}]),
        )),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::OK);
    let replacement = named_group(&server, &token, "race-group-b", "Race group", None).await;
    assert_eq!(replacement.status, StatusCode::CREATED);
    assert_eq!(
        authentik_binding(
            &server,
            &token,
            "Groups",
            "displayName",
            "Race group",
            &response
        )
        .await,
        (Some(race), 0),
        "a separate mutable-name lookup would bind a different group"
    );
    assert_eq!(response.status, StatusCode::OK);
    let current = scim(
        &server,
        Method::GET,
        &format!("/scim/v2/Groups/{group}"),
        &token,
        None,
    )
    .await
    .json();
    assert_eq!(current["members"].as_array().unwrap().len(), 1);
    assert_eq!(current["members"][0]["value"], first.to_string());
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn every_create_conflict_is_a_non_409_refusal_and_rolls_back_authority() {
    let (server, token, _) = setup().await;
    // Fault injection exercises unexpected uniqueness failures after create prechecks.
    sqlx::raw_sql("CREATE FUNCTION fail_create_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='directory.scim.user.create' THEN RAISE EXCEPTION 'synthetic audit collision' USING ERRCODE='23505'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_create_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_create_audit();").execute(&server.state.db).await.unwrap();
    let response = scim(
        &server,
        Method::POST,
        "/scim/v2/Users",
        &token,
        Some(user_body("fault-user", "fault-user@example.test")),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    assert_eq!(
        sqlx::query_as::<_, (i64,)>(
            "SELECT count(*) FROM directory_users WHERE subject='fault-user'"
        )
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0,
        0
    );
    sqlx::raw_sql("DROP TRIGGER fail_create_audit ON audit_events; DROP FUNCTION fail_create_audit(); CREATE FUNCTION fail_group_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic group collision' USING ERRCODE='23505'; END $$; CREATE TRIGGER fail_group_insert BEFORE INSERT ON directory_groups FOR EACH ROW EXECUTE FUNCTION fail_group_insert();").execute(&server.state.db).await.unwrap();
    let response = named_group(&server, &token, "fault-group", "Fault group", None).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    sqlx::raw_sql(
        "DROP TRIGGER fail_group_insert ON directory_groups; DROP FUNCTION fail_group_insert();",
    )
    .execute(&server.state.db)
    .await
    .unwrap();
    // Converting a sole JIT admin to an unrelated SCIM group must fail atomically.
    let mut tx = server.state.db.begin().await.unwrap();
    directory::lock_all(&mut tx).await.unwrap();
    sqlx::query(
        "INSERT INTO directory_mappings(issuer,group_key,role) VALUES($1,'jit-only-admin','admin')",
    )
    .bind(ISSUER)
    .execute(&mut *tx)
    .await
    .unwrap();
    let sole = directory::ensure_identity(
        &mut tx,
        ISSUER,
        "jit-only-admin",
        "jit-only-admin@example.test",
        "Directory Person",
        false,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE directory_users SET groups=ARRAY['jit-only-admin'] WHERE user_id=$1")
        .bind(sole)
        .execute(&mut *tx)
        .await
        .unwrap();
    directory::reconcile(&mut tx, sole).await.unwrap();
    tx.commit().await.unwrap();
    sqlx::query("UPDATE users SET disabled_at=now() WHERE email=$1")
        .bind(ADMIN_EMAIL)
        .execute(&server.state.db)
        .await
        .unwrap();
    let response = named_group(
        &server,
        &token,
        "unmapped-adoption",
        "Unmapped adoption",
        Some(&[sole]),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    assert!(enabled(&server, sole).await);
    assert_eq!(
        sqlx::query_as::<_, (i64,)>(
            "SELECT count(*) FROM directory_groups WHERE external_id='unmapped-adoption'"
        )
        .fetch_one(&server.state.db)
        .await
        .unwrap()
        .0,
        0
    );
    sqlx::query("UPDATE users SET disabled_at=now() WHERE id=$1")
        .bind(sole)
        .execute(&server.state.db)
        .await
        .unwrap();
    let response = scim(
        &server,
        Method::POST,
        "/scim/v2/Users",
        &token,
        Some(user_body("no-admin-user", "no-admin-user@example.test")),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    server.stop().await;
}
