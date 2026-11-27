use super::*;
use axum::http::Method;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use flyw8t_server::auth;

async fn credential(server: &TestServer, email: &str, scope: &str) -> String {
    let secret = format!("fw8_{}", auth::random_secret(32));
    sqlx::query("INSERT INTO api_tokens (user_id, name, prefix, token_hash, scopes)
                 SELECT id, 'Test client', 'fixture', $2, ARRAY[$3]::text[] FROM users WHERE email = $1")
        .bind(email).bind(auth::digest(&secret)).bind(scope).execute(&server.state.db).await.unwrap();
    secret
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn screenshot_rechecks_recipient_token_and_creator_at_release() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let org = admin.create_org(&server, "Support users").await;
    let email = "technician@example.test";
    let user = add_user(&server, &admin, email, "technician", Some(org)).await;
    let token = credential(&server, email, "support:screenshot").await;
    let read = credential(&server, email, "read").await;
    let alternate = credential(&server, ADMIN_EMAIL, "support:screenshot").await;
    let inv = create_invite_in(&server, &user, org).await;
    let path = format!("/api/v1/support/{}/screenshot", inv.session);
    let status_path = format!("/api/v1/support/{}/status", inv.session);
    let status = || server.api(Method::GET, &status_path, &token, None, None);
    let request_id = Uuid::new_v4();
    let public_key = STANDARD.encode(hex::decode("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap());
    let body = json!({"request_id":request_id, "public_key":public_key});
    assert_eq!(
        server
            .api(Method::GET, "/api/v1/mcp/capabilities", &read, None, None)
            .await
            .json()["support_screenshot"],
        false
    );
    assert_eq!(
        server
            .api(Method::POST, &path, &read, Some(body.clone()), None)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .api(Method::POST, &path, &alternate, Some(body.clone()), None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server
            .api(Method::GET, &status_path, &read, None, None)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .api(Method::GET, &status_path, &alternate, None, None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let waiting = status().await;
    assert_eq!(waiting.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        waiting.json(),
        json!({
            "session_id":inv.session,"state":"waiting","screenshot_access":"unavailable"
        })
    );
    let mut technician = ws(
        &server,
        &format!("/api/support/{}/ws", inv.session),
        &user.cookie,
        origin(&server),
    )
    .await
    .unwrap();
    until_state(&mut technician, "waiting").await;
    let cookie = spend_link(&server, &inv.link_token).await.unwrap();
    let mut participant = ws(
        &server,
        "/api/support/participant/ws",
        &cookie,
        origin(&server),
    )
    .await
    .unwrap();
    until_state(&mut participant, "authorizing").await;
    send(&mut participant, json!({"type":"approve"})).await;
    until_state(&mut participant, "connecting").await;
    send(
        &mut participant,
        json!({"type":"media","state":"connected"}),
    )
    .await;
    send(&mut technician, json!({"type":"media","state":"connected"})).await;
    until_state(&mut technician, "connected").await;
    assert_eq!(
        status().await.json()["screenshot_access"],
        "consent_required"
    );
    let first = server
        .api(Method::POST, &path, &token, Some(body.clone()), None)
        .await;
    assert_eq!(first.json()["error"], "consent_required");
    assert_eq!(
        status().await.json()["screenshot_access"],
        "consent_pending"
    );
    let prompt = recv_kind(&mut participant, "screenshot_consent").await;
    let mut audit_gate = server.state.db.begin().await.unwrap();
    sqlx::query("LOCK TABLE audit_events IN SHARE MODE")
        .execute(&mut *audit_gate)
        .await
        .unwrap();
    send(
        &mut participant,
        json!({"type":"screenshot_permission","grant_id":prompt["grant_id"],"allow":true}),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let audit_waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE relation = 'audit_events'::regclass
                  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
                  AND mode = 'RowExclusiveLock' AND NOT granted)",
            )
            .fetch_one(&server.state.db)
            .await
            .unwrap();
            if audit_waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("permission audit waiting for the table lock");
    assert_eq!(
        status().await.json()["screenshot_access"],
        "consent_pending"
    );
    // The participant's socket must still be handling messages while the audit waits.
    send(&mut participant, json!({"type":"invalid_message"})).await;
    let error = recv_kind(&mut participant, "error").await;
    assert_eq!(error["message"], "malformed message");
    audit_gate.commit().await.unwrap();
    recv_kind(&mut technician, "screenshot_allowed").await;
    assert_eq!(status().await.json()["screenshot_access"], "allowed");
    let request = server.api(Method::POST, &path, &token, Some(body.clone()), None);
    let capture = async {
        let task = recv_kind(&mut technician, "screenshot_capture").await;
        assert_eq!(task["request_id"], request_id.to_string());
        let duplicate = server
            .api(Method::POST, &path, &token, Some(body.clone()), None)
            .await;
        assert_eq!(duplicate.json()["error"], "already_requested");
        sqlx::query("UPDATE api_tokens SET revoked_at=now() WHERE token_hash=$1")
            .bind(auth::digest(&token))
            .execute(&server.state.db)
            .await
            .unwrap();
        let reply = json!({"csrf":user.csrf, "grant_id":prompt["grant_id"],"envelope":{
            "public_key":public_key,"iv":STANDARD.encode([0;12]),"ciphertext":STANDARD.encode([0;48])}});
        server
            .request(
                Request::post(format!("/support/{}/screenshot/{request_id}", inv.session))
                    .header(header::HOST, server.addr.to_string())
                    .header(header::ORIGIN, origin(&server).unwrap())
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &user.cookie)
                    .body(Body::from(reply.to_string()))
                    .unwrap(),
            )
            .await
    };
    let (answer, upload) = tokio::join!(request, capture);
    assert_eq!(upload.status, StatusCode::NO_CONTENT, "{}", upload.body);
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(status().await.status, StatusCode::UNAUTHORIZED);
    assert!(!answer.body.contains("ciphertext"));
    assert!(audit_rows(&server, "support.screenshot.release_authorized")
        .await
        .is_empty());
    let (channel,): (String,) = sqlx::query_as(
        "SELECT channel FROM audit_events WHERE action='support.screenshot.request'",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(channel, "mcp");
    send(&mut participant, json!({"type":"end"})).await;
    recv_kind(&mut technician, "ended").await;
    drop((technician, participant));
    server.stop().await;
}
