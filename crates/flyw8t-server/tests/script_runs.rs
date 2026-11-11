//! Running approved scripts end to end (ADR-0015 build step 4): a C0 revision runs once approved; a C3 revision
//! waits for a run signature for that device, runs once it is uploaded, and the agent refuses what it cannot verify.

mod common;

use axum::http::StatusCode;
use common::*;
use flyw8t_agent::trust::Pin;
use flyw8t_agent::AgentConfig;
use flyw8t_protocol::script::Revision;
use flyw8t_protocol::trust::run::RunRequest;
use flyw8t_protocol::trust::sig::sign_offline;
use flyw8t_protocol::trust::{
    commitment, Bytes, MayApprove, RevisionApproval, Role, RunAuthorization, Scope, SignedApproval,
    SignedAuthorization, SignedList, Signer, SignerKind, TrustList,
};
use std::time::Duration;
use uuid::Uuid;

fn root() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[11; 32])
}

fn genesis() -> SignedList {
    let k = root();
    let list = TrustList {
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
            person_name: "Operator".into(),
            may_approve: MayApprove::C3,
            scope: Scope::All,
            role: Role::Root,
        }],
        removed_keys: vec![],
        revoked_revisions: vec![],
        made_at: 1_800_000_000,
    };
    let h = list.hash().unwrap();
    SignedList {
        signatures: vec![sign_offline(&k, &h)],
        list,
    }
}

async fn approved_script(
    server: &TestServer,
    admin: &Browser,
    name: &str,
    source: &str,
    params: &str,
    risk: &str,
) -> (Uuid, Revision) {
    let r = admin
        .post(
            server,
            "/scripts",
            &[
                ("name", name),
                ("scope", "global"),
                ("language", "powershell"),
            ],
        )
        .await;
    let id: Uuid = extract(&r.location(), r"/scripts/([0-9a-f-]{36})")
        .unwrap()
        .parse()
        .unwrap();
    let r = admin
        .post(
            server,
            &format!("/scripts/{id}/revisions"),
            &[
                ("base", "0"),
                ("source", source),
                ("parameters", params),
                ("risk_class", risk),
                ("note", ""),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let req = admin
        .get(
            server,
            &format!("/scripts/{id}/revisions/1/approval-request.json"),
        )
        .await
        .json();
    let rev: Revision = serde_json::from_value(req["revision"].clone()).unwrap();
    let dep: Uuid = serde_json::from_value(req["deployment_id"].clone()).unwrap();
    let key_id = flyw8t_protocol::trust::key_id(
        flyw8t_protocol::trust::KeyKind::Offline,
        &root().verifying_key().to_bytes(),
    );
    let a = RevisionApproval::of(dep, &rev, 1_800_000_100, key_id);
    let signed = SignedApproval {
        signature: sign_offline(&root(), &a.hash()),
        approval: a,
    };
    let loc = admin
        .post(
            server,
            &format!("/scripts/{id}/revisions/1/approvals"),
            &[("approval", &serde_json::to_string(&signed).unwrap())],
        )
        .await
        .location();
    assert!(loc.contains("approval-stored"), "{loc}");
    (id, rev)
}

async fn start(
    server: &TestServer,
    admin: &Browser,
    device: Uuid,
    script: Uuid,
    extra: &[(&str, &str)],
) -> (Uuid, String) {
    let id = script.to_string();
    let mut fields = vec![("script", id.as_str()), ("number", "1"), ("timeout", "120")];
    fields.extend_from_slice(extra);
    let r = admin
        .post(server, &format!("/devices/{device}/scripts"), &fields)
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let loc = r.location();
    (
        extract(&loc, r"/jobs/([0-9a-f-]{36})")
            .unwrap()
            .parse()
            .unwrap(),
        loc,
    )
}

async fn output(server: &TestServer, job: Uuid) -> String {
    let (out,): (Option<String>,) = sqlx::query_as("SELECT stdout FROM jobs WHERE id = $1")
        .bind(job)
        .fetch_one(&server.state.db)
        .await
        .unwrap_or((None,));
    out.unwrap_or_default()
}

#[tokio::test]
#[cfg_attr(not(windows), ignore = "scripts run on Windows only in this version")]
async fn approved_scripts_run_and_c3_waits_for_a_signature_for_this_device() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let g = genesis();
    let fp = g.list.hash().unwrap();
    let r = admin
        .post(
            &server,
            "/admin/trust/versions",
            &[("version", &serde_json::to_string(&g).unwrap())],
        )
        .await;
    assert!(r.location().contains("trust-stored"));

    let org = admin.create_org(&server, "Lab").await;
    let token = admin.enrollment_token(&server, org, "60", "5").await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = AgentConfig {
        server_url: server.url(),
        ca_cert_pem: None,
        device_id: None,
        state_dir: dir.path().to_path_buf(),
    };
    let (device, _, _) = flyw8t_agent::enroll(
        cfg,
        &token,
        Some(Pin {
            fingerprint: fp,
            organization_id: org,
        }),
    )
    .await
    .unwrap();
    let agent = TestAgent {
        dir,
        device_id: device,
    };
    let (stop, task) = agent.connect(&server.url());
    wait_connected(&server, device).await;

    // C0: runs once approved, with its asked value bound by name.
    let (c0, _) = approved_script(
        &server,
        &admin,
        "Echo",
        "param([string]$Word)\n\"said $Word\"\n",
        "Word = ask",
        "C0",
    )
    .await;
    let (job, _) = start(&server, &admin, device, c0, &[("v_Word", "-Force; hello")]).await;
    wait_state(&server, job, "completed", Duration::from_secs(60)).await;
    assert!(output(&server, job).await.contains("said -Force; hello"));

    // C3: waits for a run signature.
    let (c3, rev) = approved_script(
        &server,
        &admin,
        "Marker",
        "param([string]$Note)\n\"marker $Note\"\n",
        "Note = \"demo\"",
        "C3",
    )
    .await;
    let (job, loc) = start(&server, &admin, device, c3, &[]).await;
    assert!(loc.ends_with("/authorize"), "{loc}");
    let (state, _) = job_state(&server, job).await;
    assert_eq!(state, "created");
    let req: RunRequest = serde_json::from_value(
        admin
            .get(&server, &format!("/jobs/{job}/run-request.json"))
            .await
            .json(),
    )
    .unwrap();
    assert_eq!(req.revision, rev);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    let me = flyw8t_protocol::trust::key_id(
        flyw8t_protocol::trust::KeyKind::Offline,
        &root().verifying_key().to_bytes(),
    );
    let salt: [u8; 32] = req.salt.0.clone().try_into().unwrap();
    let sign = |devices: Vec<flyw8t_protocol::trust::Hash>, values: &[(&str, &str)]| {
        let auth = RunAuthorization {
            deployment_id: req.deployment_id,
            job_id: req.job_id,
            devices,
            content_hash: rev.content_hash(),
            parameters: commitment(&salt, values.iter().copied()).unwrap(),
            timeout_secs: req.timeout_secs,
            issued_at: now,
            expires_at: now + 600,
            signer: me,
        };
        let s = SignedAuthorization {
            signature: sign_offline(&root(), &auth.hash().unwrap()),
            authorization: auth,
        };
        serde_json::to_string(&s).unwrap()
    };
    let upload = |text: String| {
        let (admin, server) = (&admin, &server);
        async move {
            admin
                .post(
                    server,
                    &format!("/jobs/{job}/authorization"),
                    &[("authorization", &text)],
                )
                .await
                .location()
        }
    };
    // For another device, or other values: refused, and the job keeps waiting.
    let other = flyw8t_protocol::trust::key_id(flyw8t_protocol::trust::KeyKind::Device, &[1; 32]);
    assert!(upload(sign(vec![other], &[("Note", "demo")]))
        .await
        .contains("refused"));
    assert!(upload(sign(req.devices.clone(), &[("Note", "other")]))
        .await
        .contains("refused"));
    assert_eq!(job_state(&server, job).await.0, "created");
    // The right one runs it.
    let loc = upload(sign(req.devices.clone(), &[("Note", "demo")])).await;
    assert!(loc.ends_with(&format!("/jobs/{job}")), "{loc}");
    wait_state(&server, job, "completed", Duration::from_secs(60)).await;
    assert!(output(&server, job).await.contains("marker demo"));

    // The agent spent that signature: re-offering the job does not run it again.
    let spent = flyw8t_agent::spent::Spent::open(agent.dir.path());
    assert!(spent.is_err() || spent.unwrap().is_spent(req.deployment_id, job));

    stop.cancel();
    let _ = task.await;
    server.stop().await;
}
