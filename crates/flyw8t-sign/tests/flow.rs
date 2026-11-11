//! The whole offline flow through the real binary: a key, a genesis, an approval from the reviewed file, a run
//! authorization for a listed device, a list change, and the refusals that protect each step.

use flyw8t_protocol::script::Revision;
use flyw8t_protocol::trust::run::RunRequest;
use flyw8t_protocol::trust::{
    self, key_id, Bytes, Hash, KeyKind, RiskClass, SignedApproval, SignedAuthorization, SignedList,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

struct Env {
    dir: PathBuf,
    state: PathBuf,
}

impl Env {
    fn new() -> Env {
        let dir = std::env::temp_dir().join(format!("flyw8t-sign-flow-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        Env {
            state: dir.join("state"),
            dir,
        }
    }
    fn p(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    fn run(&self, args: &[&str]) -> (bool, String) {
        self.run_in(&self.state, args)
    }
    fn run_in(&self, state: &Path, args: &[&str]) -> (bool, String) {
        let o = Command::new(env!("CARGO_BIN_EXE_flyw8t-sign"))
            .args(args)
            .arg("--yes")
            .env("FLYW8T_SIGN_STATE", state)
            .env("FLYW8T_SIGN_PASSPHRASE", "a long enough passphrase")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        (o.status.success(), text)
    }
    fn ok(&self, args: &[&str]) -> String {
        let (ok, text) = self.run(args);
        assert!(ok, "{args:?} failed:\n{text}");
        text
    }
    fn fails(&self, args: &[&str], needle: &str) {
        let (ok, text) = self.run(args);
        assert!(!ok, "{args:?} should fail");
        assert!(
            text.contains(needle),
            "{args:?}: expected {needle:?} in:\n{text}"
        );
    }
    fn s(&self, name: &str) -> String {
        self.p(name).to_string_lossy().into_owned()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn refs(v: &[String]) -> Vec<&str> {
    v.iter().map(|s| s.as_str()).collect()
}

fn read<T: serde::de::DeserializeOwned>(p: &Path) -> T {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn a_signer_never_signs_two_versions_with_one_number() {
    let e = Env::new();
    let (sa, sb) = (e.p("state-a"), e.p("state-b"));
    let ok_in = |state: &Path, args: &[&str]| {
        let (ok, t) = e.run_in(state, args);
        assert!(ok, "{args:?}:\n{t}");
        t
    };
    ok_in(&sa, &["keygen", "--out", &e.s("a.key")]);
    ok_in(&sb, &["keygen", "--out", &e.s("b.key")]);
    ok_in(
        &sb,
        &[
            "export-signer",
            "--key",
            &e.s("b.key"),
            "--person",
            "Bea",
            "--role",
            "list_admin",
            "--out",
            &e.s("b.json"),
        ],
    );
    ok_in(
        &sa,
        &[
            "draft-genesis",
            "--key",
            &e.s("a.key"),
            "--person",
            "Al",
            "--rp-id",
            "rmm.example.com",
            "--origin",
            "https://rmm.example.com",
            "--signer",
            &e.s("b.json"),
            "--out",
            &e.s("draft.json"),
        ],
    );
    // Two people must sign every version.
    let mut draft: serde_json::Value = read(&e.p("draft.json"));
    draft["threshold"] = 2.into();
    std::fs::write(e.p("draft2.json"), draft.to_string()).unwrap();
    let t = ok_in(
        &sa,
        &[
            "genesis",
            "--key",
            &e.s("a.key"),
            "--draft",
            &e.s("draft2.json"),
            "--out",
            &e.s("g-a.json"),
        ],
    );
    assert!(t.contains("more signatures are needed"), "{t}");
    ok_in(
        &sb,
        &[
            "genesis",
            "--key",
            &e.s("b.key"),
            "--as-list-admin",
            "--draft",
            &e.s("g-a.json"),
            "--out",
            &e.s("g.json"),
        ],
    );
    let g: SignedList = read(&e.p("g.json"));
    let fp = g.list.hash().unwrap();
    std::fs::write(
        e.p("chain.json"),
        serde_json::to_vec(&vec![g.clone()]).unwrap(),
    )
    .unwrap();
    ok_in(
        &sa,
        &[
            "trust",
            "import",
            "--fingerprint",
            &fp.to_string(),
            "--chain",
            &e.s("chain.json"),
        ],
    );

    let next = |f: &dyn Fn(&mut flyw8t_protocol::trust::TrustList), name: &str| {
        let mut l = g.list.clone();
        l.version = 2;
        l.previous = Some(fp);
        f(&mut l);
        std::fs::write(e.p(name), serde_json::to_vec(&l).unwrap()).unwrap();
    };
    // A version that could never verify is refused before it uses up the signer's version 2.
    next(
        &|l| {
            l.signers.retain(|s| s.person_name != "Bea");
            l.threshold = 1;
        },
        "drop.json",
    );
    let (ok, t) = e.run_in(
        &sa,
        &[
            "sign-list",
            "--key",
            &e.s("a.key"),
            "--input",
            &e.s("drop.json"),
            "--out",
            &e.s("x.json"),
        ],
    );
    assert!(!ok && t.contains("without recording it as removed"), "{t}");
    // A real version 2, signed by A only: not complete, but A's number 2 is now taken.
    next(&|l| l.revoked_revisions.push(Hash([5; 32])), "v2.json");
    let t = ok_in(
        &sa,
        &[
            "sign-list",
            "--key",
            &e.s("a.key"),
            "--input",
            &e.s("v2.json"),
            "--out",
            &e.s("v2a.json"),
        ],
    );
    assert!(t.contains("more signatures are needed"), "{t}");
    next(&|l| l.revoked_revisions.push(Hash([6; 32])), "fork.json");
    let (ok, t) = e.run_in(
        &sa,
        &[
            "sign-list",
            "--key",
            &e.s("a.key"),
            "--input",
            &e.s("fork.json"),
            "--out",
            &e.s("f.json"),
        ],
    );
    assert!(!ok && t.contains("already signed version 2"), "{t}");
    // The same version again is fine (B's copy, say).
    ok_in(
        &sa,
        &[
            "sign-list",
            "--key",
            &e.s("a.key"),
            "--input",
            &e.s("v2.json"),
            "--out",
            &e.s("v2a-again.json"),
        ],
    );
}

#[test]
fn request_text_cannot_drive_the_terminal() {
    let e = Env::new();
    e.ok(&["keygen", "--out", &e.s("k.key")]);
    std::fs::write(
        e.p("evil.json"),
        r#"{"deployment_id":"\u001b]52;c;aGk=\u0007"}"#,
    )
    .unwrap();
    let (ok, t) = e.run(&[
        "approve",
        "--key",
        &e.s("k.key"),
        "--request",
        &e.s("evil.json"),
        "--source",
        &e.s("k.key"),
        "--out",
        &e.s("o.json"),
    ]);
    assert!(!ok);
    assert!(!t.contains('\u{1b}') && !t.contains('\u{7}'), "{t:?}");
}

#[test]
fn the_offline_flow_end_to_end() {
    let e = Env::new();
    e.ok(&["keygen", "--out", &e.s("root.key")]);
    e.fails(&["keygen", "--out", &e.s("root.key")], "");
    e.ok(&[
        "draft-genesis",
        "--key",
        &e.s("root.key"),
        "--person",
        "Operator",
        "--rp-id",
        "rmm.example.com",
        "--origin",
        "https://rmm.example.com",
        "--out",
        &e.s("draft.json"),
    ]);
    // A first version that could never verify is refused before it uses up this machine's version 1.
    let mut poisoned: serde_json::Value = read(&e.p("draft.json"));
    poisoned["removed_keys"] = serde_json::json!([Hash([3; 32]).to_string()]);
    std::fs::write(e.p("poisoned.json"), poisoned.to_string()).unwrap();
    e.fails(
        &[
            "genesis",
            "--key",
            &e.s("root.key"),
            "--draft",
            &e.s("poisoned.json"),
            "--out",
            &e.s("p.json"),
        ],
        "no removed keys",
    );
    let out = e.ok(&[
        "genesis",
        "--key",
        &e.s("root.key"),
        "--draft",
        &e.s("draft.json"),
        "--out",
        &e.s("g.json"),
    ]);
    let g: SignedList = read(&e.p("g.json"));
    let fp = g.list.hash().unwrap();
    assert!(
        out.contains(&fp.to_string()),
        "prints the fingerprint:\n{out}"
    );
    let head = trust::verify_genesis(&g, &fp).unwrap();
    let dep = head.list.deployment_id;
    let root_id = head.list.signers[0].key_id();

    // Another machine pins it only with the right fingerprint.
    std::fs::write(
        e.p("chain.json"),
        serde_json::to_vec(&vec![g.clone()]).unwrap(),
    )
    .unwrap();
    let other = e.p("other-state");
    let (ok, _) = e.run_in(
        &other,
        &[
            "trust",
            "import",
            "--fingerprint",
            &Hash([1; 32]).to_string(),
            "--chain",
            &e.s("chain.json"),
        ],
    );
    assert!(!ok);
    let (ok, t) = e.run_in(
        &other,
        &[
            "trust",
            "import",
            "--fingerprint",
            &fp.to_string(),
            "--chain",
            &e.s("chain.json"),
        ],
    );
    assert!(ok, "{t}");

    // Approve from the reviewed file, and only that file.
    let source = "param([string]$Delay)\nshutdown.exe /r /t $Delay\n";
    let rev = Revision {
        script_id: Uuid::new_v4(),
        revision: 1,
        language: "powershell".into(),
        risk: RiskClass::C3,
        scope: None,
        parameters: "Delay = \"30\"".into(),
        source: source.into(),
    };
    std::fs::write(
        e.p("req.json"),
        serde_json::json!({"deployment_id": dep, "revision": rev}).to_string(),
    )
    .unwrap();
    std::fs::write(e.p("reviewed.ps1"), source.replace('\n', "\r\n")).unwrap();
    std::fs::write(e.p("other.ps1"), "Remove-Item C:\\ -Recurse\n").unwrap();
    e.fails(
        &[
            "approve",
            "--key",
            &e.s("root.key"),
            "--request",
            &e.s("req.json"),
            "--source",
            &e.s("other.ps1"),
            "--out",
            &e.s("x.json"),
        ],
        "not this revision's source",
    );
    e.ok(&[
        "approve",
        "--key",
        &e.s("root.key"),
        "--request",
        &e.s("req.json"),
        "--source",
        &e.s("reviewed.ps1"),
        "--out",
        &e.s("a.json"),
    ]);
    let a: SignedApproval = read(&e.p("a.json"));
    assert!(trust::verify_approval(&a, &head.list).is_ok() && a.approval.matches(&dep, &rev));

    // Authorize one run on a listed device.
    let device = key_id(KeyKind::Device, &[7; 32]);
    let mut req = RunRequest {
        deployment_id: dep,
        job_id: Uuid::new_v4(),
        revision: rev.clone(),
        approvals: vec![a.clone()],
        values: BTreeMap::from([("Delay".to_string(), "30".to_string())]),
        salt: Bytes(vec![9; 32]),
        devices: vec![device],
        timeout_secs: 120,
    };
    let write_req = |r: &RunRequest, name: &str| {
        std::fs::write(e.p(name), serde_json::to_vec(r).unwrap()).unwrap()
    };
    write_req(&req, "run.json");
    let auth_args = |req: &str, out: &str| -> Vec<String> {
        [
            "authorize",
            "--key",
            &e.s("root.key"),
            "--request",
            &e.s(req),
            "--out",
            &e.s(out),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    };
    e.fails(
        &refs(&auth_args("run.json", "r.json")),
        "not in this machine's device list",
    );
    e.ok(&[
        "device",
        "add",
        "--name",
        "dev box",
        "--key-id",
        &device.to_string(),
    ]);
    let shown = e.ok(&refs(&auth_args("run.json", "r.json")));
    assert!(
        shown.contains("\"dev box\"") && shown.contains("shutdown.exe"),
        "{shown}"
    );
    let r: SignedAuthorization = read(&e.p("r.json"));
    assert!(trust::verify_authorization(&r, &head.list).is_ok());
    assert_eq!(r.authorization.signer, root_id);
    assert!(r.authorization.expires_at - r.authorization.issued_at <= 15 * 60);

    // Refusals: an extra value, a changed constant, two devices for C3, a revision nobody approved, too long a window.
    let mut bad = req.clone();
    bad.values.insert("Force".into(), "-Force".into());
    write_req(&bad, "bad1.json");
    e.fails(&refs(&auth_args("bad1.json", "x1.json")), "not declared");
    bad = req.clone();
    bad.values.insert("Delay".into(), "0".into());
    write_req(&bad, "bad2.json");
    e.fails(&refs(&auth_args("bad2.json", "x2.json")), "constant");
    bad = req.clone();
    bad.devices.push(key_id(KeyKind::Device, &[8; 32]));
    write_req(&bad, "bad3.json");
    e.fails(
        &refs(&auth_args("bad3.json", "x3.json")),
        "exactly one device",
    );
    bad = req.clone();
    bad.revision.source.push_str("Remove-Item C:\\\n");
    write_req(&bad, "bad4.json");
    e.fails(&refs(&auth_args("bad4.json", "x4.json")), "no approval");
    let mut long = auth_args("run.json", "x5.json");
    long.extend(["--valid-minutes".into(), "16".into()]);
    e.fails(&refs(&long), "at most 15 minutes");

    // A list change: revoke the revision. Afterwards it is not authorized again, and a second version 2 is refused.
    let mut l2 = head.list.clone();
    l2.version = 2;
    l2.previous = Some(head.hash);
    l2.revoked_revisions.push(rev.content_hash());
    std::fs::write(e.p("l2.json"), serde_json::to_vec(&l2).unwrap()).unwrap();
    e.ok(&[
        "sign-list",
        "--key",
        &e.s("root.key"),
        "--input",
        &e.s("l2.json"),
        "--out",
        &e.s("l2s.json"),
    ]);
    req.job_id = Uuid::new_v4();
    write_req(&req, "run2.json");
    e.fails(&refs(&auth_args("run2.json", "x6.json")), "revoked");
    let mut fork = l2.clone();
    fork.revoked_revisions.clear();
    fork.made_at += 1;
    std::fs::write(e.p("fork.json"), serde_json::to_vec(&fork).unwrap()).unwrap();
    e.fails(
        &[
            "sign-list",
            "--key",
            &e.s("root.key"),
            "--input",
            &e.s("fork.json"),
            "--out",
            &e.s("f.json"),
        ],
        "",
    );
    // The other machine follows with `trust update`, and refuses a different version 2.
    let l2s: SignedList = read(&e.p("l2s.json"));
    std::fs::write(
        e.p("chain2.json"),
        serde_json::to_vec(&vec![g.clone(), l2s]).unwrap(),
    )
    .unwrap();
    let (ok, t) = e.run_in(&other, &["trust", "update", "--chain", &e.s("chain2.json")]);
    assert!(ok, "{t}");
    let shown = e.run_in(&other, &["show"]).1;
    assert!(shown.contains("version 2"), "{shown}");
}
