//! Script trust (ADR-0015 build step 3): the server stores only versions that verify, hands the chain to agents,
//! agents pin it against a fingerprint and organization given locally and extend it on every connection, and
//! approvals are verified before they are stored.

mod common;

use axum::http::StatusCode;
use common::*;
use flyw8t_agent::trust::{Pin, Trust};
use flyw8t_agent::AgentConfig;
use flyw8t_protocol::script::Revision;
use flyw8t_protocol::trust::sig::sign_offline;
use flyw8t_protocol::trust::{
    Bytes, Hash, MayApprove, RevisionApproval, Role, Scope, SignedApproval, SignedList, Signer,
    SignerKind, TrustList,
};
use std::time::Duration;
use uuid::Uuid;

fn root() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
}

fn signed(list: TrustList, key: &ed25519_dalek::SigningKey) -> SignedList {
    let h = list.hash().unwrap();
    SignedList {
        signatures: vec![sign_offline(key, &h)],
        list,
    }
}

fn genesis() -> SignedList {
    let k = root();
    signed(
        TrustList {
            deployment_id: Uuid::new_v4(),
            version: 1,
            previous: None,
            rp_id: "localhost".into(),
            origins: vec!["http://localhost".into()],
            threshold: 1,
            signers: vec![Signer {
                kind: SignerKind::Offline,
                public_key: Bytes(k.verifying_key().to_bytes().to_vec()),
                credential_id: None,
                person_id: Uuid::from_u128(1),
                person_name: "Root Person".into(),
                may_approve: MayApprove::C3,
                scope: Scope::All,
                role: Role::Root,
            }],
            removed_keys: vec![],
            revoked_revisions: vec![],
            made_at: 1_800_000_000,
        },
        &k,
    )
}

fn next(prev: &SignedList, key: &ed25519_dalek::SigningKey, revoke: u8) -> SignedList {
    let mut l = prev.list.clone();
    l.version += 1;
    l.previous = Some(prev.list.hash().unwrap());
    l.revoked_revisions.push(Hash([revoke; 32]));
    signed(l, key)
}

async fn upload(server: &TestServer, admin: &Browser, v: &SignedList) -> String {
    let r = admin
        .post(
            server,
            "/admin/trust/versions",
            &[("version", &serde_json::to_string(v).unwrap())],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    r.location()
}

fn agent_cfg(server: &TestServer, dir: &std::path::Path) -> AgentConfig {
    AgentConfig {
        server_url: server.url(),
        ca_cert_pem: None,
        device_id: None,
        enrollment_scope: None,
        state_dir: dir.to_path_buf(),
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn the_server_keeps_only_versions_that_verify_and_agents_pin_and_follow_them() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let g = genesis();
    let fp = g.list.hash().unwrap();

    // Changing the list needs sudo mode.
    let plain = server.admin().await;
    let r = plain
        .post(
            &server,
            "/admin/trust/versions",
            &[("version", &serde_json::to_string(&g).unwrap())],
        )
        .await;
    assert!(r.location().contains("/sudo"), "{}", r.location());

    assert!(upload(
        &server,
        &admin,
        &SignedList {
            signatures: vec![],
            ..g.clone()
        }
    )
    .await
    .contains("trust-refused"));
    assert!(admin
        .post(
            &server,
            "/admin/trust/versions",
            &[("version", "{\"list\":1}")]
        )
        .await
        .location()
        .contains("trust-bad-json"));
    assert!(upload(&server, &admin, &g).await.contains("trust-stored"));
    assert!(
        upload(&server, &admin, &genesis())
            .await
            .contains("trust-refused"),
        "a second genesis"
    );
    let v2 = next(&g, &root(), 1);
    let forged = next(&g, &ed25519_dalek::SigningKey::from_bytes(&[8; 32]), 1);
    assert!(upload(&server, &admin, &forged)
        .await
        .contains("trust-refused"));
    assert!(upload(&server, &admin, &v2).await.contains("trust-stored"));
    let page = admin.get(&server, "/admin/trust").await;
    assert!(
        page.body.contains(&fp.to_string()) && page.body.contains("Root Person"),
        "{}",
        page.body
    );

    // Enrollment pins only the right fingerprint and organization.
    let org = admin.create_org(&server, "Pinned").await;
    let other_org = admin.create_org(&server, "Other").await;
    let token = admin.enrollment_token(&server, org, "60", "5").await;
    let bad = tempfile::tempdir().unwrap();
    let err = flyw8t_agent::enroll(
        agent_cfg(&server, bad.path()),
        &token,
        Some(Pin {
            fingerprint: Hash([9; 32]),
            organization_id: org,
        }),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("does not verify"), "{err:#}");
    assert!(
        !bad.path().join("config.json").exists()
            && !bad.path().join(flyw8t_agent::trust::FILE).exists()
    );
    let wrong_org = tempfile::tempdir().unwrap();
    let err = flyw8t_agent::enroll(
        agent_cfg(&server, wrong_org.path()),
        &token,
        Some(Pin {
            fingerprint: fp,
            organization_id: other_org,
        }),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("nothing was saved"), "{err:#}");
    assert!(!wrong_org.path().join(flyw8t_agent::trust::FILE).exists());

    let dir = tempfile::tempdir().unwrap();
    let (device, _, pinned) = flyw8t_agent::enroll(
        agent_cfg(&server, dir.path()),
        &token,
        Some(Pin {
            fingerprint: fp,
            organization_id: org,
        }),
    )
    .await
    .unwrap();
    assert_eq!(pinned.unwrap().head.list.version, 2);

    // A connected agent extends its head with what is new, and only that.
    let v3 = next(&v2, &root(), 3);
    assert!(upload(&server, &admin, &v3).await.contains("trust-stored"));
    let agent = TestAgent {
        dir,
        device_id: device,
    };
    let (stop, task) = agent.connect(&server.url());
    let state_dir = agent.dir.path().to_path_buf();
    wait_for(
        "the agent to hold version 3",
        Duration::from_secs(20),
        || {
            let d = state_dir.clone();
            async move { Trust::load(&d).unwrap().get().unwrap().head.list.version == 3 }
        },
    )
    .await;
    stop.cancel();
    let _ = task.await;

    // An agent enrolled without a pin is pinned later, with the service stopped.
    let unpinned = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let cfg = AgentConfig::load(unpinned.dir.path()).unwrap();
    let err = flyw8t_agent::trust_pin(
        cfg.clone(),
        Pin {
            fingerprint: fp,
            organization_id: other_org,
        },
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("nothing was pinned"), "{err:#}");
    let p = flyw8t_agent::trust_pin(
        cfg,
        Pin {
            fingerprint: fp,
            organization_id: org,
        },
    )
    .await
    .unwrap();
    assert_eq!(p.head.list.version, 3);
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn approvals_are_verified_before_they_are_stored() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let r = admin
        .post(
            &server,
            "/scripts",
            &[
                ("name", "Reboot"),
                ("scope", "global"),
                ("language", "powershell"),
            ],
        )
        .await;
    let script: Uuid = extract(&r.location(), r"/scripts/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();
    let r = admin
        .post(
            &server,
            &format!("/scripts/{script}/revisions"),
            &[
                ("base", "0"),
                ("source", "shutdown.exe /r /t 30\n"),
                ("parameters", ""),
                ("risk_class", "C3"),
                ("note", ""),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let page = format!("/scripts/{script}/revisions/1");
    assert!(admin
        .get(&server, &page)
        .await
        .body
        .contains("No trust list yet"));

    let g = genesis();
    assert!(upload(&server, &admin, &g).await.contains("trust-stored"));
    let req = admin
        .get(&server, &format!("{page}/approval-request.json"))
        .await;
    assert_eq!(req.status, StatusCode::OK, "{}", req.body);
    let req = req.json();
    let rev: Revision = serde_json::from_value(req["revision"].clone()).unwrap();
    assert_eq!(rev.source, "shutdown.exe /r /t 30\n");
    let dep: Uuid = serde_json::from_value(req["deployment_id"].clone()).unwrap();
    assert_eq!(dep, g.list.deployment_id);

    let sign = |a: RevisionApproval| SignedApproval {
        signature: sign_offline(&root(), &a.hash()),
        approval: a,
    };
    let me = g.list.signers[0].key_id();
    let post = |a: &SignedApproval| {
        let body = serde_json::to_string(a).unwrap();
        let admin = &admin;
        let server = &server;
        let path = format!("{page}/approvals");
        async move {
            admin
                .post(server, &path, &[("approval", &body)])
                .await
                .location()
        }
    };
    // Approving it as C0 does not approve this C3 revision.
    let mut as_c0 = RevisionApproval::of(dep, &rev, 1_800_000_100, me);
    as_c0.risk = flyw8t_protocol::trust::RiskClass::C0;
    assert!(post(&sign(as_c0)).await.contains("approval-refused"));
    let mut tampered = sign(RevisionApproval::of(dep, &rev, 1_800_000_100, me));
    tampered.approval.approved_at += 1;
    assert!(post(&tampered).await.contains("approval-refused"));
    assert!(
        post(&sign(RevisionApproval::of(dep, &rev, 1_800_000_100, me)))
            .await
            .contains("approval-stored")
    );
    let shown = admin.get(&server, &page).await.body;
    assert!(
        shown.contains("Root Person") && shown.contains(">valid<"),
        "{shown}"
    );

    // Revoking the revision leaves the approval stored but no longer valid.
    let mut l2 = g.list.clone();
    l2.version = 2;
    l2.previous = Some(g.list.hash().unwrap());
    l2.revoked_revisions.push(rev.content_hash());
    assert!(upload(&server, &admin, &signed(l2, &root()))
        .await
        .contains("trust-stored"));
    let shown = admin.get(&server, &page).await.body;
    assert!(shown.contains("no longer valid"), "{shown}");
    server.stop().await;
}

async fn connect_script_fixture(
    server: &TestServer,
    agent: &TestAgent,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    use base64::Engine;
    use flyw8t_agent::identity::DeviceKey;
    use flyw8t_protocol::messages::{AgentMsg, CAP_SCRIPTS};
    use flyw8t_protocol::{auth, ServerMsg, PROTOCOL_VERSION};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let device = agent.device_id;
    let (mut peer, _) =
        tokio_tungstenite::connect_async(format!("ws://{}/api/agent/ws", server.addr))
            .await
            .unwrap();
    let msg = peer.next().await.unwrap().unwrap();
    let ServerMsg::Challenge { nonce, .. } = serde_json::from_str(msg.to_text().unwrap()).unwrap()
    else {
        panic!("expected an authentication challenge");
    };
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(nonce)
        .unwrap();
    let key = DeviceKey::load(&agent.dir.path().join("device.key")).unwrap();
    let authenticate = AgentMsg::Authenticate {
        protocol_version: PROTOCOL_VERSION,
        device_id: device,
        signature: key.sign_b64(&auth::auth_message(&nonce, device)),
        agent_version: "fixture".into(),
        physical_console_check: false,
        capabilities: vec![CAP_SCRIPTS.into()],
    };
    peer.send(Message::text(serde_json::to_string(&authenticate).unwrap()))
        .await
        .unwrap();
    peer
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn queued_run_snapshots_field_values_and_records_its_delivery_window() {
    use flyw8t_protocol::messages::{AgentMsg, ExecOutcome, Finished, JobPhase, JobReport};
    use flyw8t_protocol::ServerMsg;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let org = admin.create_org(&server, "Script field fixture").await;
    let token = admin.enrollment_token(&server, org, "60", "1").await;
    let agent = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let device = agent.device_id;
    let db = &server.state.db;
    let (site,): (Uuid,) = sqlx::query_as(
        "INSERT INTO sites (organization_id, name) VALUES ($1, 'Test site') RETURNING id",
    )
    .bind(org)
    .fetch_one(db)
    .await
    .unwrap();
    sqlx::query("UPDATE devices SET site_id = $2 WHERE id = $1")
        .bind(device)
        .bind(site)
        .execute(db)
        .await
        .unwrap();
    let (field, actor): (Uuid, Uuid) = sqlx::query_as(
        "INSERT INTO field_definitions (key, label, kind, scopes, created_by)
         SELECT 'marker', 'Marker', 'text', ARRAY['organization','site','device'], id FROM users WHERE email = $1
         RETURNING id, created_by",
    ).bind(ADMIN_EMAIL).fetch_one(db).await.unwrap();
    sqlx::query(
        "INSERT INTO field_values (field_id, scope, organization_id, site_id, device_id, value, set_by)
         VALUES ($1, 'organization', $2, NULL, NULL, 'company value', $5),
                ($1, 'site', NULL, $3, NULL, 'site value', $5),
                ($1, 'device', NULL, NULL, $4, 'device value', $5)",
    ).bind(field).bind(org).bind(site).bind(device).bind(actor).execute(db).await.unwrap();

    let g = genesis();
    assert!(upload(&server, &admin, &g).await.contains("trust-stored"));
    let script_page = admin
        .post(
            &server,
            "/scripts",
            &[
                ("name", "Echo fields"),
                ("scope", "global"),
                ("language", "powershell"),
            ],
        )
        .await
        .location();
    let script: Uuid = extract(&script_page, r"/scripts/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();
    let revision_path = format!("/scripts/{script}/revisions");
    let saved = admin.post(
        &server, &revision_path,
        &[
            ("base", "0"),
            ("source", "param([string]$Company, [string]$Site, [string]$Device)\nWrite-Output $Company $Site $Device\n"),
            ("parameters", "Company = {{org.marker}}\nSite = {{site.marker}}\nDevice = {{device.marker}}"),
            ("risk_class", "C0"),
        ],
    ).await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    let req = admin
        .get(&server, &format!("{revision_path}/1/approval-request.json"))
        .await;
    let rev: Revision = serde_json::from_value(req.json()["revision"].clone()).unwrap();
    let approval = RevisionApproval::of(
        g.list.deployment_id,
        &rev,
        1_800_000_100,
        g.list.signers[0].key_id(),
    );
    let proof = serde_json::to_string(&SignedApproval {
        signature: sign_offline(&root(), &approval.hash()),
        approval,
    })
    .unwrap();
    let approved = admin
        .post(
            &server,
            &format!("{revision_path}/1/approvals"),
            &[("approval", &proof)],
        )
        .await;
    assert!(approved.location().contains("approval-stored"));

    let run_path = format!("/devices/{device}/scripts");
    let run = admin
        .post(
            &server,
            &run_path,
            &[
                ("script", &script.to_string()),
                ("number", "1"),
                ("delivery", "day"),
                ("v_Company", "an injected form value"),
            ],
        )
        .await;
    assert_eq!(run.status, StatusCode::SEE_OTHER, "{}", run.body);
    let job: Uuid = extract(&run.location(), r"/jobs/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();
    let (state, request, seconds): (String, serde_json::Value, f64) = sqlx::query_as(
        "SELECT state, request, extract(epoch FROM deliver_by - clock_timestamp())::float8 FROM jobs WHERE id = $1",
    ).bind(job).fetch_one(db).await.unwrap();
    assert_eq!(state, "queued");
    assert!((86_300.0..=86_400.0).contains(&seconds), "{seconds}");
    assert_eq!(
        request["values"],
        serde_json::json!({
            "Company": "company value", "Site": "site value", "Device": "device value"
        })
    );
    // Connect an authenticated, script-capable fixture peer after queuing. This proves
    // delivery and result handling on any test host. Windows script_runs exercises PowerShell.
    let mut peer = connect_script_fixture(&server, &agent).await;
    let offer = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(frame) = peer.next().await {
            if let ServerMsg::ScriptOffer(offer) =
                serde_json::from_str(frame.unwrap().to_text().unwrap()).unwrap()
            {
                return offer;
            }
        }
        panic!("agent connection closed before script delivery");
    })
    .await
    .unwrap();
    assert_eq!(offer.job_id, job);
    assert_eq!(
        serde_json::to_value(&offer.values).unwrap(),
        request["values"]
    );
    let at = time::OffsetDateTime::now_utc();
    for phase in [
        JobPhase::Accepted,
        JobPhase::Started { at },
        JobPhase::Finished(Box::new(Finished {
            outcome: ExecOutcome::Exited { code: 0 },
            started_at: Some(at),
            finished_at: at,
            stdout: None,
            stderr: None,
            structured: Some(serde_json::json!({"windows_account": "local_system"})),
        })),
    ] {
        let report = AgentMsg::Job(JobReport { job_id: job, phase });
        peer.send(Message::text(serde_json::to_string(&report).unwrap()))
            .await
            .unwrap();
    }
    wait_state(&server, job, "completed", Duration::from_secs(15)).await;
    let (dispatches,): (i32,) = sqlx::query_as("SELECT dispatch_count FROM jobs WHERE id = $1")
        .bind(job)
        .fetch_one(db)
        .await
        .unwrap();
    assert_eq!(dispatches, 1);
    let result = admin.get(&server, &format!("/jobs/{job}")).await.body;
    assert!(result.contains("Windows account reported by agent"));
    assert!(result.contains(r"LocalSystem (NT AUTHORITY\SYSTEM)"));
    assert!(!result.contains("Structured result"));
    let activity = admin
        .get(&server, &format!("/devices/{device}/activity"))
        .await
        .body;
    assert!(activity.contains("Echo fields · revision 1") && activity.contains(ADMIN_EMAIL));
    assert!(activity.contains("Agent reported job completion"));
    assert!(!activity.contains("device value"));
    peer.close(None).await.unwrap();
    let disconnected = async || {
        tokio::time::timeout(Duration::from_secs(5), async {
            while server.state.registry.current_conn(device).is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    };
    disconnected().await;
    let queue_again = async || {
        let response = admin
            .post(
                &server,
                &run_path,
                &[
                    ("script", &script.to_string()),
                    ("number", "1"),
                    ("delivery", "day"),
                ],
            )
            .await;
        assert_eq!(response.status, StatusCode::SEE_OTHER, "{}", response.body);
        let job: Uuid = extract(&response.location(), r"/jobs/([0-9a-f-]{36})")
            .unwrap()
            .parse()
            .unwrap();
        wait_state(&server, job, "queued", Duration::from_secs(5)).await;
        job
    };

    let delayed = queue_again().await;
    let mut publishing = db.begin().await.unwrap();
    sqlx::query("LOCK TABLE trust_versions IN ROW EXCLUSIVE MODE")
        .execute(&mut *publishing)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE jobs SET deliver_by = clock_timestamp() + interval '4 seconds' WHERE id = $1",
    )
    .bind(delayed)
    .execute(db)
    .await
    .unwrap();
    let mut peer = connect_script_fixture(&server, &agent).await;
    wait_for(
        "dispatch waiting for the trust list",
        Duration::from_secs(4),
        || async {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE relation = 'trust_versions'::regclass
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
             AND mode = 'ShareLock' AND NOT granted)",
            )
            .fetch_one(db)
            .await
            .unwrap()
        },
    )
    .await;
    wait_for(
        "delivery window elapsed",
        Duration::from_secs(6),
        || async {
            sqlx::query_scalar::<_, bool>(
                "SELECT deliver_by <= clock_timestamp() FROM jobs WHERE id = $1",
            )
            .bind(delayed)
            .fetch_one(db)
            .await
            .unwrap()
        },
    )
    .await;
    publishing.commit().await.unwrap();
    wait_state(&server, delayed, "expired", Duration::from_secs(5)).await;
    let dispatches: i32 = sqlx::query_scalar("SELECT dispatch_count FROM jobs WHERE id = $1")
        .bind(delayed)
        .fetch_one(db)
        .await
        .unwrap();
    assert_eq!(dispatches, 0);
    peer.close(None).await.unwrap();
    disconnected().await;

    // The new connection has never synced the revocation. The server must withhold this offer.
    let withheld = queue_again().await;
    let revoked = {
        let mut next = g.list.clone();
        next.version += 1;
        next.previous = Some(g.list.hash().unwrap());
        next.revoked_revisions.push(rev.content_hash());
        signed(next, &root())
    };
    assert!(upload(&server, &admin, &revoked)
        .await
        .contains("trust-stored"));
    let mut peer = connect_script_fixture(&server, &agent).await;
    wait_state(&server, withheld, "cancelled", Duration::from_secs(5)).await;
    let (dispatches, note): (i32, String) =
        sqlx::query_as("SELECT dispatch_count, state_note FROM jobs WHERE id = $1")
            .bind(withheld)
            .fetch_one(db)
            .await
            .unwrap();
    assert_eq!(dispatches, 0);
    assert!(note.contains("revoked"));
    peer.close(None).await.unwrap();
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL (FLYW8T_TEST_DATABASE_URL)"]
async fn scheduled_occurrences_are_scoped_rechecked_and_materialized_once() {
    use flyw8t_server::schedules::sweep;
    use time::{macros::format_description, Duration as Span, OffsetDateTime};

    let mut config = test_config(&fresh_database().await);
    config.sweep_interval = Duration::from_secs(3600);
    let server = start(config).await;
    let admin = server.admin_sudo().await;
    let org = admin.create_org(&server, "Scheduled lab").await;
    let other = admin.create_org(&server, "Other lab").await;
    let token = admin.enrollment_token(&server, org, "60", "1").await;
    let agent = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let device = agent.device_id;
    // This fixture exercises scheduling and offline queuing on every host.
    sqlx::query("UPDATE devices SET os_family = 'windows' WHERE id = $1")
        .bind(device)
        .execute(&server.state.db)
        .await
        .unwrap();
    let register = |email: &'static str, org: Uuid| {
        let server = &server;
        let admin = &admin;
        async move {
            let result = admin
                .post(
                    server,
                    "/admin/users",
                    &[
                        ("email", email),
                        ("display_name", "Tech"),
                        ("role", "technician"),
                        ("password", "schedule-password-123"),
                        ("org", &org.to_string()),
                    ],
                )
                .await;
            assert_eq!(
                result.location(),
                "/admin?m=user-created",
                "{}",
                result.body
            );
            server.login(email, "schedule-password-123").await
        }
    };
    let tech = register("scheduled@example.test", org).await;
    let outsider = register("outside@example.test", other).await;
    let list = genesis();
    assert!(upload(&server, &admin, &list)
        .await
        .contains("trust-stored"));
    let response = admin
        .post(
            &server,
            "/scripts",
            &[
                ("name", "Read-only marker"),
                ("scope", "global"),
                ("language", "powershell"),
            ],
        )
        .await;
    let script: Uuid = extract(&response.location(), r"/scripts/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();
    let response = admin
        .post(
            &server,
            &format!("/scripts/{script}/revisions"),
            &[
                ("base", "0"),
                ("source", "param([string]$Label)\nWrite-Output $Label\n"),
                ("parameters", "Label = ask"),
                ("risk_class", "C0"),
                ("note", ""),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER, "{}", response.body);
    let revision: Revision = serde_json::from_value(
        admin
            .get(
                &server,
                &format!("/scripts/{script}/revisions/1/approval-request.json"),
            )
            .await
            .json()["revision"]
            .clone(),
    )
    .unwrap();
    let approval = RevisionApproval::of(
        list.list.deployment_id,
        &revision,
        1_800_000_100,
        list.list.signers[0].key_id(),
    );
    let signed_approval = SignedApproval {
        signature: sign_offline(&root(), &approval.hash()),
        approval,
    };
    let approval_json = serde_json::to_string(&signed_approval).unwrap();
    assert!(admin
        .post(
            &server,
            &format!("/scripts/{script}/revisions/1/approvals"),
            &[("approval", &approval_json),]
        )
        .await
        .location()
        .contains("approval-stored"));

    let schedules = format!("/devices/{device}/schedules");
    let new = format!("{schedules}/new/{script}/1");
    assert_eq!(
        outsider.get(&server, &schedules).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        outsider.get(&server, &new).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(tech
        .get(&server, &new)
        .await
        .body
        .contains("First run (UTC)"));
    let starts = (OffsetDateTime::now_utc() + Span::hours(2))
        .format(format_description!("[year]-[month]-[day]T[hour]:[minute]"))
        .unwrap();
    for cadence in ["once", "daily", "weekly"] {
        let response = tech
            .post(
                &server,
                &new,
                &[
                    ("starts", &starts),
                    ("cadence", cadence),
                    ("delivery", "900"),
                    ("timeout", "30"),
                    ("v_Label", "fixture marker"),
                ],
            )
            .await;
        assert_eq!(response.location(), schedules, "{}", response.body);
    }
    let (cancelled,): (Uuid,) =
        sqlx::query_as("SELECT id FROM script_schedules WHERE cadence = 'weekly'")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    let cancel = format!("{schedules}/{cancelled}/cancel");
    assert_eq!(
        outsider.post(&server, &cancel, &[]).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(tech.post(&server, &cancel, &[]).await.location(), schedules);
    assert!(tech
        .get(&server, &schedules)
        .await
        .body
        .contains("Cancelled by an operator"));

    sqlx::query(
        "UPDATE script_schedules SET first_at = now() - interval '1 minute',
                  next_at = now() - interval '1 minute' WHERE next_at IS NOT NULL",
    )
    .execute(&server.state.db)
    .await
    .unwrap();
    let (first, second) = tokio::join!(sweep(&server.state), sweep(&server.state));
    first.unwrap();
    second.unwrap();
    sweep(&server.state).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM script_schedule_occurrences")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(count, 2);
    let (queued,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM script_schedule_occurrences o JOIN jobs j ON j.id = o.job_id
         WHERE j.state = 'queued' AND j.request_channel = 'scheduler'
           AND j.deliver_by = o.due_at + interval '15 minutes'
           AND j.request->'values'->>'Label' = 'fixture marker'",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(queued, 2);
    let (cadence_preserved,): (bool,) = sqlx::query_as(
        "SELECT next_at = first_at + interval '24 hours' FROM script_schedules WHERE cadence = 'daily'"
    ).fetch_one(&server.state.db).await.unwrap();
    assert!(cadence_preserved);
    assert!(tech
        .get(&server, &schedules)
        .await
        .body
        .contains("View job"));

    // A revoked creator cannot materialize a later occurrence.
    sqlx::query(
        "DELETE FROM user_organizations WHERE user_id = (SELECT id FROM users WHERE email = 'scheduled@example.test')",
    )
    .execute(&server.state.db).await.unwrap();
    sqlx::query("UPDATE script_schedules SET next_at = now() WHERE cadence = 'daily'")
        .execute(&server.state.db)
        .await
        .unwrap();
    sweep(&server.state).await.unwrap();
    let (stopped, reason): (bool, String) = sqlx::query_as(
        "SELECT next_at IS NULL, stop_reason FROM script_schedules WHERE cadence = 'daily'",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert!(stopped);
    assert_eq!(reason, "The schedule owner lost organization access.");

    for cadence in ["once", "daily"] {
        let response = admin
            .post(
                &server,
                &new,
                &[
                    ("starts", &starts),
                    ("cadence", cadence),
                    ("delivery", "900"),
                    ("timeout", "30"),
                    ("v_Label", "fixture marker"),
                ],
            )
            .await;
        assert_eq!(response.location(), schedules, "{}", response.body);
    }
    sqlx::query(
        "UPDATE script_schedules
         SET first_at = now() - CASE WHEN cadence = 'once' THEN interval '20 minutes' ELSE interval '1 minute' END,
             next_at = now() - CASE WHEN cadence = 'once' THEN interval '20 minutes' ELSE interval '1 minute' END
         WHERE next_at IS NOT NULL",
    )
    .execute(&server.state.db).await.unwrap();
    let mut revoked = list.list.clone();
    revoked.version += 1;
    revoked.previous = Some(list.list.hash().unwrap());
    revoked.revoked_revisions.push(revision.content_hash());
    assert!(upload(&server, &admin, &signed(revoked, &root()))
        .await
        .contains("trust-stored"));
    sweep(&server.state).await.unwrap();
    let (missed, blocked): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE outcome = 'missed'),
                count(*) FILTER (WHERE outcome = 'blocked' AND reason LIKE '%revoked%')
         FROM script_schedule_occurrences WHERE job_id IS NULL",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!((missed, blocked), (1, 1));
    let (job_count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM jobs WHERE request_channel = 'scheduler'")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(job_count, 2);
    server.stop().await;
}
