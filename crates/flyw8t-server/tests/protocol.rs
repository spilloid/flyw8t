//! Protocol tests with a hand-driven agent: the server's behavior when a device is slow,
//! silent, late, wrong, replaying, or hostile. Real server and PostgreSQL.

mod common;

use base64::Engine;
use common::*;
use flyw8t_agent::identity::DeviceKey;
use flyw8t_protocol::messages::{
    AgentMsg, CapturedStream, ExecOutcome, Finished, JobPhase, JobReport, RefusalCode,
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
        let key = DeviceKey::load(&agent.dir.path().join("device.key")).unwrap();
        let mut raw = RawAgent::connect(server).await;
        let sig = key.sign_b64(&auth::auth_message(&raw.nonce, agent.device_id));
        raw.send(&AgentMsg::Authenticate {
            protocol_version: PROTOCOL_VERSION,
            device_id: agent.device_id,
            signature: sig,
            agent_version: "raw".into(),
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
    let (_a, stop, task) = agent.connect(&server.url());
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
    sqlx::query("UPDATE jobs SET state = 'queued' WHERE id = $1")
        .bind(job)
        .execute(&server.state.db)
        .await
        .unwrap();
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
