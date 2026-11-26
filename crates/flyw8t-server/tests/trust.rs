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
