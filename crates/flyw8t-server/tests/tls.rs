//! Native TLS: the server serves HTTPS/WSS with rustls, and an agent that pins the server's
//! private CA enrolls, connects and runs a job over it. An agent that does not trust the CA
//! cannot connect at all.

mod common;

use common::*;
use flyw8t_agent::{Agent, AgentConfig};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn agent_enrolls_and_runs_jobs_over_native_tls() {
    let dir = tempfile::tempdir().unwrap();
    let ca = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = ca.cert.pem();
    std::fs::write(dir.path().join("cert.pem"), &cert_pem).unwrap();
    std::fs::write(dir.path().join("key.pem"), ca.key_pair.serialize_pem()).unwrap();

    let mut cfg = test_config(&fresh_database().await);
    cfg.tls = Some((dir.path().join("cert.pem"), dir.path().join("key.pem")));
    cfg.public_url = "https://localhost".into();
    let server = start(cfg).await;
    let url = format!("https://localhost:{}", server.addr.port());

    let admin = server.admin().await;
    let org = admin.create_org(&server, "TLS Org").await;
    let token = admin.enrollment_token(&server, org, "60", "2").await;

    // Without the CA: the TLS handshake fails, so nothing is enrolled.
    let untrusting = tempfile::tempdir().unwrap();
    let cfg = AgentConfig {
        server_url: url.clone(),
        ca_cert_pem: None,
        device_id: None,
        state_dir: untrusting.path().into(),
    };
    let err = flyw8t_agent::enroll(cfg, &token).await.unwrap_err();
    assert!(
        format!("{err:#}").to_lowercase().contains("certificate"),
        "{err:#}"
    );

    // With the CA pinned: enroll, connect, run.
    let state = tempfile::tempdir().unwrap();
    let cfg = AgentConfig {
        server_url: url.clone(),
        ca_cert_pem: Some(cert_pem),
        device_id: None,
        state_dir: state.path().into(),
    };
    let (device_id, _) = flyw8t_agent::enroll(cfg, &token).await.unwrap();
    let agent = Agent::new(AgentConfig::load(state.path()).unwrap()).unwrap();
    let stop = CancellationToken::new();
    let (a, s) = (agent.clone(), stop.clone());
    let task = tokio::spawn(async move { a.run_session(&s).await });
    wait_connected(&server, device_id).await;
    let job = admin
        .run(&server, device_id, &[("action", "net.ipconfig")])
        .await;
    wait_state(&server, job, "completed", Duration::from_secs(30)).await;
    assert_eq!(job_state(&server, job).await.1, "verified");
    stop.cancel();
    task.await.unwrap().unwrap();
    server.stop().await;
}
