//! Protocol tests with a hand-driven agent: the server's behavior when a device is slow,
//! silent, late, wrong, replaying, or hostile. Real server and PostgreSQL.

mod common;

use base64::Engine;
use common::*;
use flyw8t_agent::identity::DeviceKey;
use flyw8t_protocol::messages::{
    AgentMsg, AgentUpdatePolicy, CapturedStream, ExecOutcome, Finished, JobPhase, JobReport,
    RefusalCode,
};
use flyw8t_protocol::{auth, ServerMsg, PROTOCOL_VERSION};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use time::OffsetDateTime;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct RawAgent {
    ws: Ws,
    nonce: Vec<u8>,
}

impl RawAgent {
    async fn connect(server: &TestServer) -> RawAgent {
        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{}/api/agent/ws", server.addr))
                .await
                .unwrap();
        let ServerMsg::Challenge { nonce, .. } = next(&mut ws).await else {
            panic!("expected challenge")
        };
        RawAgent {
            ws,
            nonce: base64::engine::general_purpose::STANDARD
                .decode(nonce)
                .unwrap(),
        }
    }

    async fn send(&mut self, msg: &AgentMsg) {
        self.ws
            .send(Message::text(serde_json::to_string(msg).unwrap()))
            .await
            .unwrap();
    }

    async fn authenticate(server: &TestServer, agent: &TestAgent) -> RawAgent {
        Self::authenticate_with_capabilities(server, agent, false, &[]).await
    }

    async fn authenticate_with_capabilities(
        server: &TestServer,
        agent: &TestAgent,
        physical_console_check: bool,
        capabilities: &[&str],
    ) -> RawAgent {
        let key = DeviceKey::load(&agent.dir.path().join("device.key")).unwrap();
        let mut raw = RawAgent::connect(server).await;
        let sig = key.sign_b64(&auth::auth_message(&raw.nonce, agent.device_id));
        raw.send(&AgentMsg::Authenticate {
            protocol_version: PROTOCOL_VERSION,
            device_id: agent.device_id,
            signature: sig,
            agent_version: "raw".into(),
            physical_console_check,
            capabilities: capabilities.iter().map(|cap| (*cap).into()).collect(),
        })
        .await;
        assert!(matches!(next(&mut raw.ws).await, ServerMsg::Welcome { .. }));
        raw
    }

    /// Next message that is not unrelated noise.
    async fn expect_offer(&mut self) -> Uuid {
        loop {
            if let ServerMsg::JobOffer { job_id, .. } = next(&mut self.ws).await {
                return job_id;
            }
        }
    }

    async fn report(&mut self, job_id: Uuid, phase: JobPhase) {
        self.send(&AgentMsg::Job(JobReport { job_id, phase })).await;
    }
}

async fn next(ws: &mut Ws) -> ServerMsg {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(15), ws.next())
            .await
            .expect("server message")
            .expect("open")
            .unwrap();
        if let Message::Text(t) = frame {
            return serde_json::from_str(t.as_str()).unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn update_preflight_observes_current_fleet_policy_without_replacing_the_live_agent() {
    use flyw8t_agent::{connection::observe_update_policy, AgentConfig};
    use flyw8t_protocol::agent_update::Release;

    let server = start_fresh().await;
    let (admin, org, agent) = enrolled(&server).await;
    let _live = RawAgent::authenticate(&server, &agent).await;
    wait_connected(&server, agent.device_id).await;
    let live_session = server.state.registry.current_conn(agent.device_id).unwrap();
    let cfg = AgentConfig::load(agent.dir.path()).unwrap();
    let candidate = Release::from_artifact("0.3.1".into(), b"synthetic device claim").unwrap();

    assert_eq!(
        observe_update_policy(&cfg, candidate.clone())
            .await
            .unwrap(),
        AgentUpdatePolicy::Enabled,
    );
    sqlx::query("UPDATE devices SET agent_updates_opt_out = true WHERE id = $1")
        .bind(agent.device_id)
        .execute(&server.state.db)
        .await
        .unwrap();
    assert_eq!(
        observe_update_policy(&cfg, candidate.clone())
            .await
            .unwrap(),
        AgentUpdatePolicy::DeviceOptedOut,
    );
    sqlx::query("UPDATE organizations SET automatic_agent_updates = false WHERE id = $1")
        .bind(org)
        .execute(&server.state.db)
        .await
        .unwrap();
    assert_eq!(
        observe_update_policy(&cfg, candidate.clone())
            .await
            .unwrap(),
        AgentUpdatePolicy::OrganizationPaused,
    );

    let key = DeviceKey::load(&cfg.key_path()).unwrap();
    let mut probe = RawAgent::connect(&server).await;
    let signature = key.sign_b64(&auth::agent_update_policy_message(
        &probe.nonce,
        agent.device_id,
        &candidate,
    ));
    let request = AgentMsg::AgentUpdatePolicyRequest {
        protocol_version: PROTOCOL_VERSION,
        device_id: agent.device_id,
        signature: signature.clone(),
        candidate: candidate.clone(),
    };
    let mut tampered = candidate.clone();
    tampered.version = "0.3.2".into();
    probe
        .send(&AgentMsg::AgentUpdatePolicyRequest {
            protocol_version: PROTOCOL_VERSION,
            device_id: agent.device_id,
            signature,
            candidate: tampered,
        })
        .await;
    assert!(matches!(
        next(&mut probe.ws).await,
        ServerMsg::Refused {
            code: RefusalCode::AuthFailed,
            ..
        }
    ));
    let mut replay = RawAgent::connect(&server).await;
    replay.send(&request).await;
    assert!(matches!(
        next(&mut replay.ws).await,
        ServerMsg::Refused {
            code: RefusalCode::AuthFailed,
            ..
        }
    ));

    assert_eq!(
        server.state.registry.current_conn(agent.device_id),
        Some(live_session)
    );
    sqlx::query("UPDATE device_credentials SET revoked_at = now() WHERE device_id = $1")
        .bind(agent.device_id)
        .execute(&server.state.db)
        .await
        .unwrap();
    let error = observe_update_policy(&cfg, candidate.clone())
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref(),
        Some(flyw8t_agent::Fatal::Revoked(_))
    ));

    let evidence: Vec<(String, serde_json::Value, serde_json::Value)> = sqlx::query_as(
        "SELECT outcome, detail->'policy', detail->'device_reported_candidate'
           FROM audit_events
          WHERE action = 'device.agent_update_preflight' AND organization_id = $1
            AND target_type = 'device' AND actor_id = $2 AND target_id = $2
          ORDER BY id",
    )
    .bind(org)
    .bind(agent.device_id)
    .fetch_all(&server.state.db)
    .await
    .unwrap();
    let claimed = serde_json::to_value(&candidate).unwrap();
    assert_eq!(
        evidence,
        [
            (
                "success".into(),
                serde_json::json!("enabled"),
                claimed.clone()
            ),
            (
                "denied".into(),
                serde_json::json!("device_opted_out"),
                claimed.clone()
            ),
            (
                "denied".into(),
                serde_json::json!("organization_paused"),
                claimed
            ),
        ]
    );
    let activity = admin
        .get(&server, &format!("/devices/{}/activity", agent.device_id))
        .await;
    assert_eq!(activity.status, axum::http::StatusCode::OK);
    assert!(activity
        .body
        .contains("Fleet policy allowed the update preflight"));
    assert!(activity
        .body
        .contains("Update preflight blocked by device opt-out"));
    assert!(activity
        .body
        .contains("Update preflight blocked by organization policy"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn physical_console_check_uses_the_enrolled_connection_and_audits_the_reply() {
    use axum::http::StatusCode;
    use flyw8t_protocol::PhysicalConsoleState;

    let server = start_fresh().await;
    let (admin, org, agent) = enrolled(&server).await;
    let device = agent.device_id;
    // The test runs on Linux too. Set only the display fact that selects the Windows UI.
    sqlx::query("UPDATE devices SET os_family='windows' WHERE id=$1")
        .bind(device)
        .execute(&server.state.db)
        .await
        .unwrap();
    let path = format!("/devices/{device}/physical-console/check");
    let other_org = admin.create_org(&server, "Outside the pilot").await;
    let added = admin
        .post(
            &server,
            "/admin/users",
            &[
                ("email", "other@example.test"),
                ("display_name", "Other technician"),
                ("password", "example-password-123"),
                ("role", "technician"),
                ("org", &other_org.to_string()),
            ],
        )
        .await;
    assert_eq!(added.status, StatusCode::SEE_OTHER);
    let outsider = server
        .login("other@example.test", "example-password-123")
        .await;
    assert_eq!(
        outsider.post(&server, &path, &[]).await.status,
        StatusCode::NOT_FOUND
    );
    // A CSRF-less POST must fail even for the administrator.
    let invalid = axum::http::Request::post(&path)
        .header(axum::http::header::COOKIE, &admin.cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(server.request(invalid).await.status, StatusCode::FORBIDDEN);

    let legacy = RawAgent::authenticate(&server, &agent).await;
    wait_connected(&server, device).await;
    let page = admin.get(&server, &format!("/devices/{device}")).await;
    let section = page.body.find("id=\"device-connection-options\"").unwrap();
    let button = page.body.find("Check background terminal policy</button>").unwrap();
    let details = page.body.find("class=\"desktop-link-help\"").unwrap();
    assert!(section < button && button < details);
    assert!(page.body.contains("This check does not open a terminal."));
    assert!(page.body.contains(&format!("action=\"{path}\"")));
    let legacy_connection = server.state.registry.current_conn(device).unwrap();
    let response = admin.post(&server, &path, &[]).await;
    assert_eq!(response.status, StatusCode::OK);
    let mut current = RawAgent::authenticate_with_capabilities(&server, &agent, true, &[]).await;
    wait_for(
        "the new console-capable connection",
        Duration::from_secs(10),
        || async {
            server
                .state
                .registry
                .current_conn(device)
                .is_some_and(|id| id != legacy_connection)
        },
    )
    .await;
    drop(legacy);
    let (_, served) = tokio::join!(
        async {
            let ServerMsg::CheckPhysicalConsole { request_id } = next(&mut current.ws).await else {
                panic!("expected a physical console check")
            };
            // A delayed reply from another request must not satisfy this request.
            current
                .send(&AgentMsg::PhysicalConsoleStatus {
                    request_id: Uuid::new_v4(),
                    state: PhysicalConsoleState::NoConsole,
                })
                .await;
            current
                .send(&AgentMsg::PhysicalConsoleStatus {
                    request_id,
                    state: PhysicalConsoleState::ActiveConsole,
                })
                .await;
        },
        admin.post(&server, &path, &[])
    );
    assert_eq!(served.status, StatusCode::OK, "{}", served.body);
    assert!(served.body.contains("signed in"));
    let audited: Vec<(String, String)> = sqlx::query_as(
        "SELECT detail->>'request_id', COALESCE(detail->>'status','requested')
         FROM audit_events WHERE organization_id=$1 AND target_id=$2
           AND action IN ('device.physical_console.requested','device.physical_console.result') ORDER BY id",
    ).bind(org).bind(device).fetch_all(&server.state.db).await.unwrap();
    assert_eq!(audited.len(), 4);
    assert_eq!(audited[0].0, audited[1].0);
    assert_eq!(audited[2].0, audited[3].0);
    assert_ne!(audited[0].0, audited[2].0);
    assert_eq!(
        audited
            .iter()
            .map(|(_, outcome)| outcome.as_str())
            .collect::<Vec<_>>(),
        ["requested", "unsupported", "requested", "active_console"]
    );
    drop(current);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn background_terminal_policy_is_scoped_live_and_audited() {
    use axum::http::StatusCode;
    use flyw8t_protocol::messages::{BackgroundTerminalPolicy, CAP_BACKGROUND_TERMINAL_POLICY};
    use flyw8t_protocol::PhysicalConsoleState;

    let server = start_fresh().await;
    let (admin, org, agent) = enrolled(&server).await;
    let device = agent.device_id;
    sqlx::query("UPDATE devices SET os_family = 'windows' WHERE id = $1")
        .bind(device)
        .execute(&server.state.db)
        .await
        .unwrap();
    let path = format!("/devices/{device}/background-terminal/check");
    for (email, role, member_org, expected) in [
        (
            "reader@example.test",
            "readonly",
            org,
            StatusCode::FORBIDDEN,
        ),
        (
            "other@example.test",
            "technician",
            admin.create_org(&server, "Outside the pilot").await,
            StatusCode::NOT_FOUND,
        ),
    ] {
        let added = admin
            .post(
                &server,
                "/admin/users",
                &[
                    ("email", email),
                    ("display_name", "Test user"),
                    ("password", "example-password-123"),
                    ("role", role),
                    ("org", &member_org.to_string()),
                ],
            )
            .await;
        assert_eq!(added.status, StatusCode::SEE_OTHER);
        let user = server.login(email, "example-password-123").await;
        assert_eq!(user.post(&server, &path, &[]).await.status, expected);
    }

    let invalid = axum::http::Request::post(&path)
        .header(axum::http::header::COOKIE, &admin.cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(server.request(invalid).await.status, StatusCode::FORBIDDEN);

    let legacy = RawAgent::authenticate(&server, &agent).await;
    wait_connected(&server, device).await;
    let legacy_connection = server.state.registry.current_conn(device).unwrap();
    let response = admin.post(&server, &path, &[]).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response
        .body
        .contains("does not report local terminal policy"));

    let capabilities = &[CAP_BACKGROUND_TERMINAL_POLICY];
    let mut current =
        RawAgent::authenticate_with_capabilities(&server, &agent, true, capabilities).await;
    wait_for("policy-capable agent", Duration::from_secs(10), || async {
        server
            .state
            .registry
            .current_conn(device)
            .is_some_and(|id| {
                id != legacy_connection
                    && server
                        .state
                        .registry
                        .has_capability(device, id, capabilities[0])
            })
    })
    .await;
    drop(legacy);

    let (request, served) = tokio::join!(
        async {
            let ServerMsg::CheckBackgroundTerminalPolicy { request_id } =
                next(&mut current.ws).await
            else {
                panic!("expected a background terminal policy check");
            };
            current
                .send(&AgentMsg::PhysicalConsoleStatus {
                    request_id,
                    state: PhysicalConsoleState::ActiveConsole,
                })
                .await;
            current
                .send(&AgentMsg::BackgroundTerminalPolicyStatus {
                    request_id: Uuid::new_v4(),
                    policy: BackgroundTerminalPolicy::Disabled,
                })
                .await;
            current
                .send(&AgentMsg::BackgroundTerminalPolicyStatus {
                    request_id,
                    policy: BackgroundTerminalPolicy::Enabled,
                })
                .await;
            request_id
        },
        admin.post(&server, &path, &[])
    );
    assert_eq!(served.status, StatusCode::OK);
    assert!(served.body.contains("Local policy is enabled"));
    let original = server.state.registry.current_conn(device).unwrap();

    let (mut replacement, served) = tokio::join!(
        async {
            assert!(matches!(
                next(&mut current.ws).await,
                ServerMsg::CheckBackgroundTerminalPolicy { .. }
            ));
            RawAgent::authenticate_with_capabilities(&server, &agent, true, capabilities).await
        },
        admin.post(&server, &path, &[])
    );
    assert_eq!(served.status, StatusCode::OK);
    assert!(served.body.contains("disconnected or reconnected"));
    assert_ne!(server.state.registry.current_conn(device), Some(original));
    drop(current);

    let (_, served) = tokio::join!(
        async {
            let ServerMsg::CheckBackgroundTerminalPolicy { request_id } =
                next(&mut replacement.ws).await
            else {
                panic!("expected a new policy check after reconnect");
            };
            replacement
                .send(&AgentMsg::BackgroundTerminalPolicyStatus {
                    request_id: request,
                    policy: BackgroundTerminalPolicy::Enabled,
                })
                .await;
            replacement
                .send(&AgentMsg::BackgroundTerminalPolicyStatus {
                    request_id,
                    policy: BackgroundTerminalPolicy::Disabled,
                })
                .await;
        },
        admin.post(&server, &path, &[])
    );
    assert_eq!(served.status, StatusCode::OK);
    assert!(served.body.contains("Local policy is disabled"));

    let audit: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT detail->>'request_id', COALESCE(detail->>'status', 'requested'), detail->>'connection'
         FROM audit_events
         WHERE organization_id = $1 AND target_id = $2
           AND action IN ('device.background_terminal_policy.requested', 'device.background_terminal_policy.result')
         ORDER BY id",
    )
    .bind(org)
    .bind(device)
    .fetch_all(&server.state.db)
    .await
    .unwrap();
    assert_eq!(
        audit
            .iter()
            .map(|(_, status, _)| status.as_str())
            .collect::<Vec<_>>(),
        [
            "requested",
            "unsupported",
            "requested",
            "enabled",
            "requested",
            "not_connected",
            "requested",
            "disabled"
        ]
    );
    let (pairs, remainder) = audit.as_chunks::<2>();
    assert!(remainder.is_empty());
    for [requested, observed] in pairs {
        assert_eq!(requested.0, observed.0);
    }
    assert_eq!(audit[3].0, request.to_string());
    assert_eq!(audit[3].2, Some(original.to_string()));

    let activity = admin
        .get(&server, &format!("/devices/{device}/activity"))
        .await;
    assert_eq!(activity.status, StatusCode::OK);
    assert!(activity
        .body
        .contains("Background terminal policy check requested"));
    drop(replacement);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn background_terminal_policy_audits_access_revoked_during_check() {
    use axum::http::StatusCode;
    use flyw8t_protocol::messages::{BackgroundTerminalPolicy, CAP_BACKGROUND_TERMINAL_POLICY};

    let server = start_fresh().await;
    let (admin, org, agent) = enrolled(&server).await;
    let device = agent.device_id;
    sqlx::query("UPDATE devices SET os_family = 'windows' WHERE id = $1")
        .bind(device)
        .execute(&server.state.db)
        .await
        .unwrap();
    let email = "policy-technician@example.test";
    let added = admin
        .post(
            &server,
            "/admin/users",
            &[
                ("email", email),
                ("display_name", "Policy technician"),
                ("password", "example-password-123"),
                ("role", "technician"),
                ("org", &org.to_string()),
            ],
        )
        .await;
    assert_eq!(added.status, StatusCode::SEE_OTHER);
    let technician = server.login(email, "example-password-123").await;
    let mut current = RawAgent::authenticate_with_capabilities(
        &server,
        &agent,
        true,
        &[CAP_BACKGROUND_TERMINAL_POLICY],
    )
    .await;
    wait_connected(&server, device).await;

    let path = format!("/devices/{device}/background-terminal/check");
    let (request_id, response) = tokio::join!(
        async {
            let ServerMsg::CheckBackgroundTerminalPolicy { request_id } =
                next(&mut current.ws).await
            else {
                panic!("expected a background terminal policy check");
            };
            let removal = sqlx::query(
                "DELETE FROM user_organizations WHERE organization_id = $1
                 AND user_id = (SELECT id FROM users WHERE email = $2)",
            )
            .bind(org)
            .bind(email)
            .execute(&server.state.db)
            .await
            .unwrap();
            assert_eq!(removal.rows_affected(), 1);
            current
                .send(&AgentMsg::BackgroundTerminalPolicyStatus {
                    request_id,
                    policy: BackgroundTerminalPolicy::Enabled,
                })
                .await;
            request_id
        },
        technician.post(&server, &path, &[])
    );
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(!response.body.contains("Local policy is enabled"));

    let events: Vec<(String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT action, outcome, detail FROM audit_events
         WHERE organization_id = $1 AND target_id = $2 AND actor_label = $3
           AND action IN ('device.background_terminal_policy.requested', 'device.background_terminal_policy.result')
         ORDER BY id",
    )
    .bind(org)
    .bind(device)
    .bind(email)
    .fetch_all(&server.state.db)
    .await
    .unwrap();
    assert_eq!(
        events,
        [
            (
                "device.background_terminal_policy.requested".into(),
                "success".into(),
                serde_json::json!({"request_id": request_id})
            ),
            (
                "device.background_terminal_policy.result".into(),
                "denied".into(),
                serde_json::json!({"request_id": request_id, "status": "access_changed"})
            )
        ]
    );
    drop(current);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn terminal_confirmation_is_single_use_and_rechecks_the_same_browser_and_agent() {
    use axum::http::{header, StatusCode};
    use flyw8t_protocol::messages::{
        BackgroundTerminalPolicy as Policy, CAP_BACKGROUND_TERMINAL_POLICY,
    };

    async fn reply(agent: &mut RawAgent, policy: Policy) -> Uuid {
        let ServerMsg::CheckBackgroundTerminalPolicy { request_id } = next(&mut agent.ws).await
        else {
            panic!("expected a background terminal policy request");
        };
        agent
            .send(&AgentMsg::BackgroundTerminalPolicyStatus { request_id, policy })
            .await;
        request_id
    }

    let server = start_fresh().await;
    let (admin, org, agent) = enrolled(&server).await;
    let device = agent.device_id;
    sqlx::query("UPDATE devices SET os_family = 'windows' WHERE id = $1")
        .bind(device)
        .execute(&server.state.db)
        .await
        .unwrap();
    let same_user = server.login(ADMIN_EMAIL, ADMIN_PASSWORD).await;
    let capabilities = &[CAP_BACKGROUND_TERMINAL_POLICY];
    let mut live =
        RawAgent::authenticate_with_capabilities(&server, &agent, true, capabilities).await;
    wait_connected(&server, device).await;
    let previous = server.state.registry.current_conn(device).unwrap();
    let check = format!("/devices/{device}/background-terminal/check");
    let confirm = format!("/devices/{device}/background-terminal/admission");
    let token_from = |html: &str| extract(html, r#"name="admission" value="([^"]+)""#).unwrap();

    let (policy_check, initial) = tokio::join!(
        reply(&mut live, Policy::Enabled),
        admin.post(&server, &check, &[]),
    );
    assert_eq!(initial.status, StatusCode::OK);
    assert_eq!(initial.headers[header::CACHE_CONTROL], "no-store");
    assert!(initial.body.contains("Verify session access"));
    let secret = token_from(&initial.body);
    let fields = [("admission", secret.as_str())];
    let missing_csrf = axum::http::Request::post(&confirm)
        .header(header::COOKIE, &admin.cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!("admission={secret}")))
        .unwrap();
    assert_eq!(
        server.request(missing_csrf).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        same_user.post(&server, &confirm, &fields).await.status,
        StatusCode::NOT_FOUND
    );
    let other_device = format!("/devices/{}/background-terminal/admission", Uuid::new_v4());
    assert_eq!(
        admin.post(&server, &other_device, &fields).await.status,
        StatusCode::NOT_FOUND
    );
    let (attempt, confirmed) = tokio::join!(
        reply(&mut live, Policy::Enabled),
        admin.post(&server, &confirm, &fields),
    );
    assert_ne!(attempt, policy_check);
    assert_eq!(confirmed.status, StatusCode::OK);
    assert!(confirmed.body.contains("Technician access verified."));
    assert!(!confirmed.body.contains("Verify session access"));
    assert_eq!(
        admin.post(&server, &confirm, &fields).await.status,
        StatusCode::NOT_FOUND
    );

    let (_, ready) = tokio::join!(
        reply(&mut live, Policy::Enabled),
        admin.post(&server, &check, &[])
    );
    let declined_secret = token_from(&ready.body);
    let fields = [("admission", declined_secret.as_str())];
    let (_, denied) = tokio::join!(
        reply(&mut live, Policy::Disabled),
        admin.post(&server, &confirm, &fields)
    );
    assert!(denied.body.contains("Local policy is disabled."));
    assert!(!denied.body.contains("Technician access verified."));

    let (_, ready) = tokio::join!(
        reply(&mut live, Policy::Enabled),
        admin.post(&server, &check, &[])
    );
    let stale_secret = token_from(&ready.body);
    let mut replacement =
        RawAgent::authenticate_with_capabilities(&server, &agent, true, capabilities).await;
    wait_for("replacement agent", Duration::from_secs(10), || async {
        server
            .state
            .registry
            .current_conn(device)
            .is_some_and(|connection| connection != previous)
    })
    .await;
    let stale = admin
        .post(&server, &confirm, &[("admission", &stale_secret)])
        .await;
    assert!(stale.body.contains("disconnected or reconnected"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next(&mut replacement.ws))
            .await
            .is_err()
    );

    let recorded: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT outcome, detail FROM audit_events WHERE organization_id = $1 AND target_id = $2
           AND action = 'device.background_terminal_admission.result' ORDER BY id",
    )
    .bind(org)
    .bind(device)
    .fetch_all(&server.state.db)
    .await
    .unwrap();
    assert_eq!(recorded.len(), 3);
    assert_eq!(
        recorded[0],
        (
            "success".into(),
            serde_json::json!({
                "request_id": attempt, "policy_check_id": policy_check, "status": "enabled", "connection": previous
            })
        )
    );
    assert_eq!(recorded[1].0, "denied");
    assert_eq!(recorded[1].1["status"], "disabled");
    assert_eq!(recorded[2].0, "failed");
    assert_eq!(recorded[2].1["status"], "not_connected");
    let activity = admin
        .get(&server, &format!("/devices/{device}/activity"))
        .await;
    assert!(activity
        .body
        .contains("Background terminal access confirmation recorded"));
    assert!(!activity.body.contains(&secret));
    drop(live);
    drop(replacement);
    server.stop().await;
}

fn finished_exit0(text: &str) -> JobPhase {
    JobPhase::Finished(Box::new(Finished {
        outcome: ExecOutcome::Exited { code: 0 },
        started_at: Some(OffsetDateTime::now_utc()),
        finished_at: OffsetDateTime::now_utc(),
        stdout: Some(CapturedStream {
            data: text.into(),
            total_bytes: text.len() as u64,
            truncated: false,
        }),
        stderr: None,
        structured: None,
    }))
}

/// AT-23: accepted, then silent past timeout + grace -> outcome unknown; a late final report
/// resolves it, and says it was late.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn silent_device_becomes_unknown_then_late_result_resolves() {
    let server = start_fresh().await;
    let (admin, _org, agent) = enrolled(&server).await;
    let mut raw = RawAgent::authenticate(&server, &agent).await;
    let r = admin
        .post(
            &server,
            &format!("/devices/{}/jobs", agent.device_id),
            &[("action", "net.ipconfig")],
        )
        .await;
    let job: Uuid = extract(&r.location(), r"/jobs/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(raw.expect_offer().await, job);
    raw.report(job, JobPhase::Accepted).await;
    raw.report(
        job,
        JobPhase::Started {
            at: OffsetDateTime::now_utc(),
        },
    )
    .await;
    wait_state(&server, job, "running", Duration::from_secs(5)).await;
    // Shrink the window instead of waiting 30 s: the deadline is acknowledged_at + timeout + grace.
    sqlx::query("UPDATE jobs SET timeout_secs = 1 WHERE id = $1")
        .bind(job)
        .execute(&server.state.db)
        .await
        .unwrap();
    wait_state(&server, job, "outcome_unknown", Duration::from_secs(10)).await;
    assert!(!admin
        .get(&server, &format!("/jobs/{job}"))
        .await
        .body
        .contains(">Succeeded<"));

    raw.report(job, finished_exit0("Windows IP Configuration"))
        .await;
    let reply = next(&mut raw.ws).await;
    assert!(
        matches!(reply, ServerMsg::ReportAck { job_id } if job_id == job),
        "got {reply:?}"
    );
    assert_eq!(
        job_state(&server, job).await,
        ("completed".into(), "verified".into())
    );
    assert!(event_kinds(&server, job)
        .await
        .contains(&"resolved_late".to_string()));
    server.stop().await;
}

/// AT-25: offered but never acknowledged before the delivery deadline -> outcome unknown,
/// not "expired": the device may have received it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn unacknowledged_delivery_is_unknown_not_expired() {
    let mut cfg = test_config(&fresh_database().await);
    cfg.delivery_window = Duration::from_secs(2);
    let server = start(cfg).await;
    let (admin, _org, agent) = enrolled(&server).await;
    let mut raw = RawAgent::authenticate(&server, &agent).await;
    let r = admin
        .post(
            &server,
            &format!("/devices/{}/jobs", agent.device_id),
            &[("action", "net.ipconfig")],
        )
        .await;
    let job: Uuid = extract(&r.location(), r"/jobs/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();
    raw.expect_offer().await; // received, never acknowledged
    wait_state(&server, job, "outcome_unknown", Duration::from_secs(10)).await;
    server.stop().await;
}

/// AT-24: a device cannot report on another device's job.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn device_cannot_report_another_devices_job() {
    let server = start_fresh().await;
    let (admin, org, victim) = enrolled(&server).await;
    let token = admin.enrollment_token(&server, org, "60", "1").await;
    let attacker = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let r = admin
        .post(
            &server,
            &format!("/devices/{}/jobs", victim.device_id),
            &[("action", "net.ipconfig")],
        )
        .await;
    let job: Uuid = extract(&r.location(), r"/jobs/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();

    let mut raw = RawAgent::authenticate(&server, &attacker).await;
    raw.report(job, finished_exit0("forged")).await;
    raw.report(job, JobPhase::Accepted).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        job_state(&server, job).await.0,
        "queued",
        "foreign report must not move the job"
    );
    let (denied,): (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events WHERE action = 'device.job_report' AND outcome = 'denied' AND actor_id = $1")
        .bind(attacker.device_id)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(denied, 2);
    server.stop().await;
}

/// AT-27: a signature captured from one connection cannot authenticate another.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn replayed_authentication_is_refused() {
    let server = start_fresh().await;
    let (_admin, _org, agent) = enrolled(&server).await;
    let key = DeviceKey::load(&agent.dir.path().join("device.key")).unwrap();
    let first = RawAgent::connect(&server).await;
    let captured = key.sign_b64(&auth::auth_message(&first.nonce, agent.device_id));

    let mut second = RawAgent::connect(&server).await;
    assert_ne!(first.nonce, second.nonce);
    second
        .send(&AgentMsg::Authenticate {
            protocol_version: PROTOCOL_VERSION,
            device_id: agent.device_id,
            signature: captured,
            agent_version: "x".into(),
            physical_console_check: false,
            capabilities: vec![],
        })
        .await;
    assert!(matches!(
        next(&mut second.ws).await,
        ServerMsg::Refused {
            code: RefusalCode::AuthFailed,
            ..
        }
    ));

    // A valid signature by a different (unregistered) key for this device id also fails.
    let stranger = DeviceKey::generate().unwrap();
    let mut third = RawAgent::connect(&server).await;
    let sig = stranger.sign_b64(&auth::auth_message(&third.nonce, agent.device_id));
    third
        .send(&AgentMsg::Authenticate {
            protocol_version: PROTOCOL_VERSION,
            device_id: agent.device_id,
            signature: sig,
            agent_version: "x".into(),
            physical_console_check: false,
            capabilities: vec![],
        })
        .await;
    assert!(matches!(
        next(&mut third.ws).await,
        ServerMsg::Refused {
            code: RefusalCode::AuthFailed,
            ..
        }
    ));
    assert!(server
        .state
        .registry
        .connected_since(agent.device_id)
        .is_none());
    server.stop().await;
}

/// AT-26: malformed, oversized, or out-of-sequence messages end the connection, and the
/// server keeps serving everyone else.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn hostile_frames_close_the_connection() {
    let server = start_fresh().await;
    let (_admin, _org, agent) = enrolled(&server).await;

    // Garbage instead of a handshake.
    let mut raw = RawAgent::connect(&server).await;
    raw.ws
        .send(Message::text("{\"type\":\"exec\",\"cmd\":\"whoami\"}"))
        .await
        .unwrap();
    assert!(matches!(
        next(&mut raw.ws).await,
        ServerMsg::Refused {
            code: RefusalCode::BadMessage,
            ..
        }
    ));

    // Wrong protocol version.
    let mut raw = RawAgent::connect(&server).await;
    raw.send(&AgentMsg::Authenticate {
        protocol_version: 99,
        device_id: agent.device_id,
        signature: String::new(),
        agent_version: "x".into(),
        physical_console_check: false,
        capabilities: vec![],
    })
    .await;
    assert!(matches!(
        next(&mut raw.ws).await,
        ServerMsg::Refused {
            code: RefusalCode::ProtocolVersion,
            ..
        }
    ));

    // Authenticated, then garbage.
    let mut raw = RawAgent::authenticate(&server, &agent).await;
    raw.ws.send(Message::text("not json")).await.unwrap();
    assert!(matches!(
        next(&mut raw.ws).await,
        ServerMsg::Refused {
            code: RefusalCode::BadMessage,
            ..
        }
    ));

    // Oversized frame (> 1 MiB) is rejected by the transport.
    let mut raw = RawAgent::authenticate(&server, &agent).await;
    let _ = raw
        .ws
        .send(Message::text("x".repeat(2 * 1024 * 1024)))
        .await;
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match raw.ws.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return true,
                _ => continue,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(closed, "oversized message must close the connection");

    // Still healthy for a well-behaved agent.
    let (stop, task) = agent.connect(&server.url());
    wait_connected(&server, agent.device_id).await;
    stop.cancel();
    task.await.unwrap().unwrap();
    server.stop().await;
}

/// A newer connection for the same device supersedes the older one.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn newer_connection_supersedes_older() {
    let server = start_fresh().await;
    let (_admin, _org, agent) = enrolled(&server).await;
    let mut old = RawAgent::authenticate(&server, &agent).await;
    let _new = RawAgent::authenticate(&server, &agent).await;
    assert!(matches!(
        next(&mut old.ws).await,
        ServerMsg::Refused {
            code: RefusalCode::Superseded,
            ..
        }
    ));
    assert!(server
        .state
        .registry
        .connected_since(agent.device_id)
        .is_some());
    server.stop().await;
}

/// A device reports progress on a job the server records as `queued` (e.g. the database was
/// restored from a backup taken before the dispatch committed). The server records the
/// implied dispatch and accepts the evidence instead of rejecting it into a resend loop.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn report_for_job_recorded_as_queued_is_accepted_not_looped() {
    let server = start_fresh().await;
    let (admin, _org, agent) = enrolled(&server).await;
    let mut raw = RawAgent::authenticate(&server, &agent).await;
    let r = admin
        .post(
            &server,
            &format!("/devices/{}/jobs", agent.device_id),
            &[("action", "net.ipconfig")],
        )
        .await;
    let job: Uuid = extract(&r.location(), r"/jobs/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();
    raw.expect_offer().await;
    // Keep the row locked from the edit until the server is waiting to apply the report.
    // Otherwise the sweeper (every 200 ms here) or a late dispatch announcement can find the
    // job `queued` first and dispatch it in the ordinary way, and the report implies nothing.
    let mut edit = server.state.db.begin().await.unwrap();
    sqlx::query("UPDATE jobs SET state = 'queued' WHERE id = $1")
        .bind(job)
        .execute(&mut *edit)
        .await
        .unwrap();
    raw.report(job, finished_exit0("Windows IP Configuration"))
        .await;
    let waiting_since = std::time::Instant::now();
    loop {
        let (waiting,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM pg_stat_activity
              WHERE datname = current_database() AND wait_event_type = 'Lock'
                AND query LIKE '%FROM jobs WHERE id = $1 FOR UPDATE'",
        )
        .fetch_one(&server.state.db)
        .await
        .unwrap();
        if waiting > 0 {
            break;
        }
        assert!(
            waiting_since.elapsed() < Duration::from_secs(15),
            "the report never reached the job's row lock"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    edit.commit().await.unwrap();
    let reply = next(&mut raw.ws).await;
    assert!(
        matches!(reply, ServerMsg::ReportAck { job_id } if job_id == job),
        "got {reply:?}"
    );
    assert_eq!(
        job_state(&server, job).await,
        ("completed".into(), "verified".into())
    );
    assert!(event_kinds(&server, job)
        .await
        .contains(&"implied_dispatch".to_string()));
    assert!(
        server
            .state
            .registry
            .connected_since(agent.device_id)
            .is_some(),
        "connection survives"
    );
    server.stop().await;
}

/// Review finding 5: a device repeating a final report cannot grow job history without
/// bound, and a burst of messages closes the connection.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn repeated_reports_are_counted_not_logged_and_bursts_are_cut_off() {
    let server = start_fresh().await;
    let (admin, _org, agent) = enrolled(&server).await;
    let mut raw = RawAgent::authenticate(&server, &agent).await;
    let r = admin
        .post(
            &server,
            &format!("/devices/{}/jobs", agent.device_id),
            &[("action", "net.ipconfig")],
        )
        .await;
    let job: Uuid = extract(&r.location(), r"/jobs/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();
    raw.expect_offer().await;
    for i in 0..80 {
        raw.report(job, finished_exit0("Windows IP Configuration"))
            .await;
        if i % 40 == 39 {
            tokio::time::sleep(Duration::from_millis(1100)).await; // stay under the rate limit
        }
    }
    let db = server.state.db.clone();
    wait_for("all reports processed", Duration::from_secs(15), || {
        let db = db.clone();
        async move {
            sqlx::query_as::<_, (i32,)>("SELECT unchanged_reports FROM jobs WHERE id = $1")
                .bind(job)
                .fetch_one(&db)
                .await
                .unwrap()
                .0
                == 79
        }
    })
    .await;
    let (events,): (i64,) = sqlx::query_as("SELECT count(*) FROM job_events WHERE job_id = $1")
        .bind(job)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert!(events <= 50, "{events} events kept for one job");
    assert_eq!(
        job_state(&server, job).await,
        ("completed".into(), "verified".into())
    );

    // A burst far beyond any healthy agent: refused and closed.
    for _ in 0..300 {
        if raw
            .ws
            .send(Message::text(
                serde_json::to_string(&AgentMsg::Heartbeat {
                    agent_version: "x".into(),
                    uptime_secs: 1,
                    running_jobs: 0,
                })
                .unwrap(),
            ))
            .await
            .is_err()
        {
            break;
        }
    }
    let refused = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match raw.ws.next().await {
                Some(Ok(Message::Text(t))) if t.as_str().contains("rate_limited") => return true,
                None | Some(Err(_)) => return false,
                _ => continue,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(refused, "burst must be refused with RateLimited");
    server.stop().await;
}

/// Review finding 9: a cross-site form post (login CSRF) is refused by Origin.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn cross_origin_posts_are_refused() {
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    let server = start_fresh().await;
    let (cookie, token) = server.login_token().await;
    let body = form(&[
        ("login_csrf", token.as_str()),
        ("email", ADMIN_EMAIL),
        ("password", ADMIN_PASSWORD),
    ]);
    let req = |origin: &str| {
        Request::post("/login")
            .header(header::COOKIE, &cookie)
            .header(header::HOST, "rmm.example.test")
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.clone()))
            .unwrap()
    };
    assert_eq!(
        server.request(req("https://evil.example")).await.status,
        StatusCode::FORBIDDEN
    );
    // The test server's public URL is http://, so an https:// page on the same host is a
    // different origin.
    assert_eq!(
        server.request(req("https://rmm.example.test")).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server.request(req("null")).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server.request(req("http://rmm.example.test")).await.status,
        StatusCode::SEE_OTHER
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn the_console_is_installable_as_a_mobile_app() {
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    let server = start_fresh().await;
    let get = |p: &str| Request::get(p).body(Body::empty()).unwrap();
    let m = server.request(get("/manifest.webmanifest")).await;
    assert_eq!(m.status, StatusCode::OK);
    assert_eq!(m.headers[header::CONTENT_TYPE], "application/manifest+json");
    let manifest = m.json();
    assert_eq!(manifest["display"], "standalone");
    assert_eq!(manifest["start_url"], "/");
    // Every icon the manifest names is served, with its declared type and, for PNGs, its
    // declared size (read from the PNG header, not trusted from the file name).
    let mut purposes = vec![];
    for icon in manifest["icons"].as_array().unwrap() {
        let r = server.request(get(icon["src"].as_str().unwrap())).await;
        assert_eq!(r.status, StatusCode::OK, "{icon}");
        assert_eq!(
            r.headers[header::CONTENT_TYPE],
            icon["type"].as_str().unwrap()
        );
        purposes.push(icon["purpose"].as_str().unwrap().to_string());
    }
    assert!(purposes.contains(&"maskable".to_string()));
    // Sizes from the PNG headers (the test client returns bodies as text; read raw bytes).
    // The served bodies come back as text here, so check the embedded PNGs directly.
    for (name, _, bytes) in flyw8t_web::APP_ICONS
        .iter()
        .filter(|(_, t, _)| *t == "image/png")
    {
        assert_eq!(&bytes[1..4], b"PNG", "{name}");
        let w = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        let h = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        let want = name.trim_end_matches(".png").rsplit('-').next().unwrap();
        let want: u32 = if *name == "apple-touch-icon.png" {
            180
        } else {
            want.parse().unwrap()
        };
        assert_eq!((w, h), (want, want), "{name}");
    }
    assert_eq!(
        server.request(get("/static/icons/nope.png")).await.status,
        StatusCode::NOT_FOUND
    );
    // Every page links the manifest, and the policy lets the browser fetch it.
    let login = server.request(get("/login")).await;
    assert!(login.body.contains(r#"rel="manifest""#));
    let csp = login.headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("manifest-src 'self'"), "{csp}");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn the_client_address_comes_through_a_trusted_proxy_only() {
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use flyw8t_server::client_ip::Cidr;
    // A login token is a cookie and form value only, with nothing held by the server, so one
    // minted by any test server is good for another with the same (insecure) cookie name.
    let token = start_fresh().await;
    let (cookie, csrf) = token.login_token().await;
    token.stop().await;
    let login_as = |email: &'static str, via: &'static str| {
        Request::post("/login")
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("cf-connecting-ip", via)
            .body(Body::from(form(&[
                ("login_csrf", csrf.as_str()),
                ("email", email),
                ("password", "wrong"),
            ])))
            .unwrap()
    };
    let failed_login = |via: &'static str| login_as("nobody@example.test", via);
    let last_ip = |server: &TestServer| {
        let db = server.state.db.clone();
        async move {
            sqlx::query_as::<_, (Option<String>,)>(
                "SELECT client_ip FROM audit_events WHERE action = 'user.login' ORDER BY id DESC LIMIT 1",
            )
            .fetch_one(&db)
            .await
            .unwrap()
            .0
        }
    };

    // Default: no proxy is trusted, so a client cannot pick its own address with a header.
    let server = start_fresh().await;
    server.request(failed_login("198.51.100.7")).await;
    assert_eq!(last_ip(&server).await.as_deref(), Some("127.0.0.1"));
    server.stop().await;

    // Behind a trusted proxy (the test client connects from 127.0.0.1), its header is used.
    let mut cfg = test_config(&fresh_database().await);
    cfg.trusted_proxies = vec![Cidr::parse("127.0.0.0/8").unwrap()];
    let server = start(cfg).await;
    server.request(failed_login("198.51.100.7")).await;
    assert_eq!(last_ip(&server).await.as_deref(), Some("198.51.100.7"));
    // And per-address limits count the real client, not the proxy: one address hitting the
    // limit does not lock out another.
    for _ in 0..25 {
        server.request(failed_login("198.51.100.8")).await;
    }
    // (A different email too: logins are also limited per email.)
    let other = server
        .request(login_as("someone-else@example.test", "198.51.100.9"))
        .await;
    assert_ne!(
        other.status,
        StatusCode::TOO_MANY_REQUESTS,
        "another client is not throttled"
    );
    server.stop().await;
}
