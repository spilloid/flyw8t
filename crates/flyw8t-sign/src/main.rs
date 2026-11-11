//! `flyw8t-sign`: the offline signing tool of ADR-0015. It holds the trust root, signs trust-list versions, revision
//! approvals and run authorizations, and shows everything it signs computed from what is on this machine, never
//! from labels the server supplied.

mod keyfile;
mod state;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use flyw8t_protocol::display::{block, quoted, sanitized};
use flyw8t_protocol::script::{normalize_source, parse_parameters, ParamSource, Revision};
use flyw8t_protocol::trust::run::{check_approvals, check_limits, check_values, RunRequest};
use flyw8t_protocol::trust::sig::sign_offline;
use flyw8t_protocol::trust::statement::window_cap;
use flyw8t_protocol::trust::{
    self, commitment, Bytes, Hash, MayApprove, RevisionApproval, Role, RunAuthorization, Scope,
    SignedApproval, SignedAuthorization, SignedList, Signer, SignerKind, TrustList,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use state::{Device, State};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "flyw8t-sign",
    version,
    about = "flyw8t offline signing tool (ADR-0015)"
)]
struct Cli {
    /// Where this machine's chains, checkpoints and device list live.
    #[arg(long, global = true, env = "FLYW8T_SIGN_STATE")]
    state: Option<PathBuf>,
    /// Sign without asking for confirmation. For scripted tests only.
    #[arg(long, global = true)]
    yes: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make a new offline key in a passphrase-protected file.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Show a key's id, or what this machine holds.
    Show {
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Write this key as a signer entry, for someone drafting a list to add.
    ExportSigner {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        person: String,
        /// signer, list_admin or root.
        #[arg(long, default_value = "signer")]
        role: String,
        #[arg(long, default_value = "C3")]
        may_approve: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Draft a first trust list with this key as its root.
    DraftGenesis {
        #[arg(long)]
        key: PathBuf,
        /// The root key's person, as shown to everyone who checks the list.
        #[arg(long)]
        person: String,
        /// The highest class the root may approve and authorize itself.
        #[arg(long, default_value = "C3")]
        root_may_approve: String,
        /// The console's relying-party id (its host name).
        #[arg(long)]
        rp_id: String,
        /// Allowed origins, such as https://rmm.example.com
        #[arg(long = "origin", required = true)]
        origins: Vec<String>,
        /// More signers, each a JSON file (the console's passkey export).
        #[arg(long = "signer")]
        signers: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a first trust list as its root, and print its fingerprint.
    Genesis {
        #[arg(long)]
        key: PathBuf,
        /// A draft list, or a list already signed by others.
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a later trust-list version as a list admin.
    SignList {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Approve a revision, from the source file you reviewed.
    Approve {
        #[arg(long)]
        key: PathBuf,
        /// The console's approval request: the deployment and the revision.
        #[arg(long)]
        request: PathBuf,
        /// The file you reviewed. Its text must be the revision's, after line endings are normalized.
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign one run of a C2 or C3 revision.
    Authorize {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// How long the signature stays usable, at most the class's limit (15 minutes for C3, 24 hours for C2).
        #[arg(long)]
        valid_minutes: Option<u64>,
    },
    /// Pin, update and show trust chains.
    Trust {
        #[command(subcommand)]
        cmd: TrustCmd,
    },
    /// The device list `authorize` checks targets against.
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
}

#[derive(Subcommand)]
enum TrustCmd {
    /// Pin a deployment's chain by the fingerprint from your own notes.
    Import {
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        chain: PathBuf,
    },
    /// Extend a held chain with newer versions.
    Update {
        #[arg(long)]
        chain: PathBuf,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Add a device by the key id `flyw8t-agent status` shows on that device.
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        key_id: String,
    },
    List,
}

/// An approval request from the console.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRequest {
    deployment_id: Uuid,
    revision: Revision,
}

/// A draft or partly signed list.
#[derive(Deserialize)]
#[serde(untagged)]
enum ListInput {
    Signed(SignedList),
    Draft(TrustList),
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        // Errors can quote a request's text: never let it reach the terminal raw.
        eprintln!("flyw8t-sign: {}", sanitized(&format!("{e:#}")));
        std::process::exit(1);
    }
}

/// The largest file read: a full chain of large lists, or a request with a 256 KiB script and its approvals.
const MAX_INPUT: u64 = 16 * 1024 * 1024;

fn read_json<T: DeserializeOwned>(p: &Path) -> Result<T> {
    use std::io::Read;
    let mut raw = Vec::new();
    std::fs::File::open(p)
        .with_context(|| format!("reading {}", p.display()))?
        .take(MAX_INPUT + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_INPUT {
        bail!(
            "{} is larger than {} MiB",
            p.display(),
            MAX_INPUT / 1024 / 1024
        );
    }
    serde_json::from_slice(&raw)
        .with_context(|| format!("{} is not what was expected", p.display()))
}

fn write_json<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    if p.exists() {
        bail!("{} already exists", p.display());
    }
    std::fs::write(p, serde_json::to_vec_pretty(v)?)
        .with_context(|| format!("writing {}", p.display()))
}

fn passphrase(confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var("FLYW8T_SIGN_PASSPHRASE") {
        return Ok(p);
    }
    let p = rpassword::prompt_password("Passphrase: ")?;
    if confirm && rpassword::prompt_password("Again: ")? != p {
        bail!("the passphrases differ");
    }
    if confirm && p.chars().count() < 12 {
        bail!("use a passphrase of at least 12 characters");
    }
    Ok(p)
}

fn open_key(p: &Path) -> Result<keyfile::OfflineKey> {
    keyfile::open(p, &passphrase(false)?)
}

fn confirm(yes: bool, what: &str) -> Result<()> {
    if yes {
        return Ok(());
    }
    print!("\nType yes to sign {what}: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if line.trim() != "yes" {
        bail!("not signed");
    }
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn scope_text(s: &Scope) -> String {
    match s {
        Scope::All => "every organization".into(),
        Scope::Organizations(o) => o
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn show_signer(s: &Signer) -> String {
    format!(
        "  {} {:?} key {}\n    person {} ({}), role {:?}, may approve up to {:?}, scope {}",
        quoted(&s.person_name),
        s.kind,
        s.key_id(),
        s.person_id,
        if s.kind == SignerKind::Passkey {
            "passkey"
        } else {
            "offline"
        },
        s.role,
        s.may_approve,
        scope_text(&s.scope)
    )
}

fn show_list(l: &TrustList) -> String {
    let mut out = format!(
        "Trust list version {} of deployment {}\n  relying party {}\n  origins {}\n  threshold {} different list admins\n  previous {}\nSigners:\n",
        l.version,
        l.deployment_id,
        quoted(&l.rp_id),
        l.origins.iter().map(|o| quoted(o)).collect::<Vec<_>>().join(", "),
        l.threshold,
        l.previous.map(|h| h.to_string()).unwrap_or_else(|| "none (first version)".into()),
    );
    for s in &l.signers {
        out.push_str(&show_signer(s));
        out.push('\n');
    }
    out.push_str(&format!("Removed keys: {}\n", l.removed_keys.len()));
    for k in &l.removed_keys {
        out.push_str(&format!("  {k}\n"));
    }
    out.push_str(&format!(
        "Revoked revisions: {}\n",
        l.revoked_revisions.len()
    ));
    for k in &l.revoked_revisions {
        out.push_str(&format!("  {k}\n"));
    }
    out
}

fn show_changes(old: &TrustList, new: &TrustList) -> String {
    let mut out = String::from("Changes from the version held:\n");
    let ids = |l: &TrustList| {
        l.signers
            .iter()
            .map(|s| (s.key_id(), s.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let (a, b) = (ids(old), ids(new));
    for (id, s) in &b {
        match a.get(id) {
            None => out.push_str(&format!("+ added\n{}\n", show_signer(s))),
            Some(o) if o != s => out.push_str(&format!(
                "~ changed\n{}\n  now\n{}\n",
                show_signer(o),
                show_signer(s)
            )),
            _ => {}
        }
    }
    for (id, s) in &a {
        if !b.contains_key(id) {
            out.push_str(&format!("- removed\n{}\n", show_signer(s)));
        }
    }
    for h in new
        .revoked_revisions
        .iter()
        .filter(|h| !old.revoked_revisions.contains(h))
    {
        out.push_str(&format!("- revoked revision {h}\n"));
    }
    if old.threshold != new.threshold {
        out.push_str(&format!(
            "~ threshold {} -> {}\n",
            old.threshold, new.threshold
        ));
    }
    if old.origins != new.origins || old.rp_id != new.rp_id {
        out.push_str("~ relying party or origins changed (see above)\n");
    }
    out
}

fn show_revision(r: &Revision) -> String {
    let (params, _) = parse_parameters(&r.parameters);
    let mut out = format!(
        "Script {} revision {} ({}), class {}, {}\nContent hash {}\nParameters:\n",
        r.script_id,
        r.revision,
        quoted(&r.language),
        r.risk.as_str(),
        match r.scope {
            Some(o) => format!("organization {o}"),
            None => "global".into(),
        },
        r.content_hash()
    );
    if params.is_empty() {
        out.push_str("  none\n");
    }
    for p in params {
        let src = match &p.source {
            ParamSource::Field { level, key, secret } => {
                format!(
                    "{}field {level}.{key}",
                    if *secret { "secret " } else { "" }
                )
            }
            ParamSource::Constant(c) => format!("constant {}", quoted(c)),
            ParamSource::Ask { prompt: None } => "asked at run time".into(),
            ParamSource::Ask { prompt: Some(q) } => {
                format!("asked at run time, prompt {}", quoted(q))
            }
        };
        out.push_str(&format!("  {} = {src}\n", quoted(&p.name)));
    }
    out.push_str("Parameter declarations as signed:\n");
    out.push_str(&block(&r.parameters));
    out.push_str("Source:\n");
    out.push_str(&block(&r.source));
    out
}

/// What this signature is bound to: shown before every confirmation.
fn show_binding(c: &state::Chain, signer: &Signer) -> String {
    format!(
        "Deployment {} (pinned fingerprint {}, trust list version {})\nSigning as {} with key {}\n",
        c.head.list.deployment_id,
        c.fingerprint,
        c.head.list.version,
        quoted(&signer.person_name),
        signer.key_id()
    )
}

fn run(cli: Cli) -> Result<()> {
    let state = || State::open(cli.state.clone().unwrap_or_else(State::default_root));
    match cli.cmd {
        Cmd::Keygen { out } => {
            let (k, bytes) = keyfile::generate(&passphrase(true)?)?;
            keyfile::write_private(&out, &bytes)?;
            println!("Made {}\nkey id {}", out.display(), k.id());
            println!("Keep a second copy somewhere else: losing every copy of a root means re-enrolling every agent.");
        }
        Cmd::Show { key } => {
            if let Some(k) = key {
                let k = open_key(&k)?;
                println!("key id {}", k.id());
            }
            let st = state()?;
            for d in st.deployments()? {
                if let Some(c) = st.chain(&d)? {
                    println!(
                        "deployment {d}\n  fingerprint {}\n  version {}\n  head {}",
                        c.fingerprint, c.head.list.version, c.head.hash
                    );
                }
                if let Some(cp) = st.checkpoint(&d)? {
                    println!("  last signed here: version {} {}", cp.version, cp.hash);
                }
            }
            for d in st.devices()? {
                println!("device {} {}", quoted(&d.name), d.key_id);
            }
        }
        Cmd::ExportSigner {
            key,
            person,
            role,
            may_approve,
            out,
        } => {
            let k = open_key(&key)?;
            let s = Signer {
                kind: SignerKind::Offline,
                public_key: Bytes(k.public().to_vec()),
                credential_id: None,
                person_id: Uuid::new_v4(),
                person_name: person,
                may_approve: serde_json::from_value(serde_json::Value::String(may_approve))
                    .context("--may-approve is none, C0, C1, C2 or C3")?,
                scope: Scope::All,
                role: serde_json::from_value(serde_json::Value::String(role))
                    .context("--role is signer, list_admin or root")?,
            };
            write_json(&out, &s)?;
            println!("{}", show_signer(&s));
        }
        Cmd::DraftGenesis {
            key,
            person,
            root_may_approve,
            rp_id,
            origins,
            signers,
            out,
        } => {
            let k = open_key(&key)?;
            let may: MayApprove =
                serde_json::from_value(serde_json::Value::String(root_may_approve))
                    .context("--root-may-approve is none, C0, C1, C2 or C3")?;
            let mut all = vec![Signer {
                kind: SignerKind::Offline,
                public_key: Bytes(k.public().to_vec()),
                credential_id: None,
                person_id: Uuid::new_v4(),
                person_name: person,
                may_approve: may,
                scope: Scope::All,
                role: Role::Root,
            }];
            for p in signers {
                all.push(read_json(&p)?);
            }
            let l = TrustList {
                deployment_id: Uuid::new_v4(),
                version: trust::list::GENESIS_VERSION,
                previous: None,
                rp_id,
                origins,
                threshold: 1,
                signers: all,
                removed_keys: vec![],
                revoked_revisions: vec![],
                made_at: now(),
            };
            l.check_alone()?;
            write_json(&out, &l)?;
            println!("{}Drafted {}", show_list(&l), out.display());
        }
        Cmd::Genesis { key, draft, out } => {
            let st = state()?;
            let k = open_key(&key)?;
            let mut s = match read_json::<ListInput>(&draft)? {
                ListInput::Signed(s) => s,
                ListInput::Draft(l) => SignedList {
                    list: l,
                    signatures: vec![],
                },
            };
            let l = &s.list;
            l.check_alone()?;
            if l.version != trust::list::GENESIS_VERSION || l.previous.is_some() {
                bail!("this is not a first version");
            }
            if st.chain(&l.deployment_id)?.is_some() {
                bail!("this machine already holds deployment {}", l.deployment_id);
            }
            match l.signer(&k.id()) {
                // Every root must sign a first version, and enough list admins to meet its threshold.
                Some(me) if me.role.is_list_admin() => {}
                _ => bail!("this key is not a list admin or root of the list"),
            }
            let hash = l.hash()?;
            println!("{}", show_list(l));
            println!(
                "Check every passkey entry's key id against the console's passkey page. Genesis trusts the server for those entries (ADR-0015)."
            );
            confirm(cli.yes, "this first version")?;
            st.record_signing(&l.deployment_id, l.version, hash)?;
            s.signatures.retain(|x| x.key_id() != &k.id());
            s.signatures.push(sign_offline(&k.signing, &hash));
            write_json(&out, &s)?;
            match trust::verify_genesis(&s, &hash) {
                Ok(_) => {
                    st.import(hash, std::slice::from_ref(&s))?;
                    println!("\nSigned and complete. Trust fingerprint:\n  {hash}\nKeep it in your own notes and install scripts: it is what agents pin.");
                }
                Err(e) => println!("\nSigned; more signatures are needed: {e}"),
            }
        }
        Cmd::SignList { key, input, out } => {
            let st = state()?;
            let k = open_key(&key)?;
            let mut s = match read_json::<ListInput>(&input)? {
                ListInput::Signed(s) => s,
                ListInput::Draft(l) => SignedList {
                    list: l,
                    signatures: vec![],
                },
            };
            let c = st.require_chain(&s.list.deployment_id)?;
            let (held, next) = (&c.head.list, &s.list);
            if next.version != held.version + 1 || next.previous != Some(c.head.hash) {
                bail!(
                    "this is version {} after {:?}; this machine holds version {} ({}). Run `trust update` first.",
                    next.version,
                    next.previous,
                    held.version,
                    c.head.hash
                );
            }
            // Every rule that does not depend on signatures, before anything is recorded or signed: a version that
            // could never verify must not use up this machine's signature for its number.
            let hash = trust::list::check_transition(&c.head, next)?;
            let me = match held.signer(&k.id()) {
                Some(me) if me.role.is_list_admin() => me,
                _ => bail!("this key is not a list admin of the version held"),
            };
            if trust::list::changes_governance(held, next) && me.role != Role::Root {
                println!("This version changes list admins, roots or the threshold: a root of version {} must sign it too.", held.version);
            }
            println!(
                "{}{}\n{}",
                show_binding(&c, me),
                show_list(next),
                show_changes(held, next)
            );
            confirm(cli.yes, &format!("version {}", next.version))?;
            st.record_signing(&next.deployment_id, next.version, hash)?;
            s.signatures.retain(|x| x.key_id() != &k.id());
            s.signatures.push(sign_offline(&k.signing, &hash));
            write_json(&out, &s)?;
            match trust::verify_next(&c.head, &s) {
                Ok(_) => {
                    st.update(&next.deployment_id, std::slice::from_ref(&s))?;
                    println!("Signed and complete: version {} {hash}", next.version);
                }
                Err(e) => println!("Signed; more signatures are needed: {e}"),
            }
        }
        Cmd::Approve {
            key,
            request,
            source,
            out,
        } => {
            let st = state()?;
            let k = open_key(&key)?;
            let req: ApprovalRequest = read_json(&request)?;
            check_limits(&req.revision, 0, 0)?;
            let c = st.require_chain(&req.deployment_id)?;
            let reviewed =
                std::fs::read(&source).with_context(|| format!("reading {}", source.display()))?;
            let reviewed =
                String::from_utf8(reviewed).context("the reviewed file is not UTF-8 text")?;
            let reviewed = normalize_source(&reviewed).map_err(anyhow::Error::msg)?;
            let mut rev = req.revision;
            if reviewed != rev.source {
                bail!("the file you reviewed is not this revision's source");
            }
            // Only the reviewed text is used from here on.
            rev.source = reviewed;
            let (_, problems) = parse_parameters(&rev.parameters);
            if let Some(p) = problems.first() {
                bail!(
                    "the revision's parameters have problems (line {}): {}",
                    p.line,
                    p.message
                );
            }
            let me = c
                .head
                .list
                .signer(&k.id())
                .context("this key is not in the trust list held")?;
            if !me.may_approve.allows(rev.risk) {
                bail!(
                    "this key may approve up to {:?}; the revision is {}",
                    me.may_approve,
                    rev.risk.as_str()
                );
            }
            if let (Some(o), Scope::Organizations(_)) = (rev.scope, &me.scope) {
                if !me.scope.includes(&o) {
                    bail!("this key's scope does not include organization {o}");
                }
            }
            println!("{}{}", show_binding(&c, me), show_revision(&rev));
            confirm(cli.yes, "this approval")?;
            let a = RevisionApproval::of(req.deployment_id, &rev, now(), k.id());
            let signed = SignedApproval {
                signature: sign_offline(&k.signing, &a.hash()),
                approval: a,
            };
            trust::verify_approval(&signed, &c.head.list)?;
            write_json(&out, &signed)?;
            println!("Approved: {}", out.display());
        }
        Cmd::Authorize {
            key,
            request,
            out,
            valid_minutes,
        } => {
            let st = state()?;
            let k = open_key(&key)?;
            let req: RunRequest = read_json(&request)?;
            check_limits(&req.revision, req.approvals.len(), req.devices.len())?;
            let c = st.require_chain(&req.deployment_id)?;
            let head = &c.head.list;
            let rev = &req.revision;
            let cap = window_cap(rev.risk).context("C0 and C1 runs need no run signature")?;
            let approvers = check_approvals(head, rev, &req.approvals, None)?;
            let me = head
                .signer(&k.id())
                .context("this key is not in the trust list held")?;
            if !me.may_approve.allows(rev.risk) {
                bail!(
                    "this key may sign runs up to {:?}; the revision is {}",
                    me.may_approve,
                    rev.risk.as_str()
                );
            }
            if rev.risk == trust::RiskClass::C2
                && approvers.iter().all(|a| a.person_id == me.person_id)
            {
                bail!("a C2 run must be signed by someone other than the person who approved it");
            }
            if rev.risk == trust::RiskClass::C3 && req.devices.len() != 1 {
                bail!("a C3 run names exactly one device");
            }
            if parse_parameters(&rev.parameters)
                .0
                .iter()
                .any(|p| p.is_secret())
            {
                bail!("runs with secret parameters cannot be signed offline yet; sign this one in the console");
            }
            let values = check_values(rev, &req.values, &BTreeMap::new())?;
            let salt: [u8; 32] = req
                .salt
                .0
                .as_slice()
                .try_into()
                .context("the salt must be 32 bytes")?;
            let known = st.devices()?;
            let mut targets = vec![];
            for d in &req.devices {
                match known.iter().find(|x| x.key_id == *d) {
                    Some(x) => targets.push(format!("  {} {d}", quoted(&x.name))),
                    None => bail!(
                        "device {d} is not in this machine's device list: read its key id with `flyw8t-agent status` on the device, then `flyw8t-sign device add`"
                    ),
                }
            }
            let valid = valid_minutes.map(|m| m * 60).unwrap_or(cap);
            if valid == 0 || valid > cap {
                bail!(
                    "a {} run signature is valid for at most {} minutes",
                    rev.risk.as_str(),
                    cap / 60
                );
            }
            println!("{}{}", show_binding(&c, me), show_revision(rev));
            println!("Approved by:");
            for a in &approvers {
                println!("{}", show_signer(a));
            }
            println!("Values:");
            if values.is_empty() {
                println!("  none");
            }
            for (n, v) in &values {
                println!("  {} = {}", quoted(n), quoted(v));
            }
            println!(
                "Devices (from this machine's list):\n{}",
                targets.join("\n")
            );
            println!(
                "Job {}\nTimeout {} seconds\nValid for {} minutes from now",
                req.job_id,
                req.timeout_secs,
                valid / 60
            );
            confirm(cli.yes, "this run")?;
            let issued = now();
            let auth = RunAuthorization {
                deployment_id: req.deployment_id,
                job_id: req.job_id,
                devices: req.devices.clone(),
                content_hash: rev.content_hash(),
                parameters: commitment(
                    &salt,
                    values.iter().map(|(a, b)| (a.as_str(), b.as_str())),
                )?,
                timeout_secs: req.timeout_secs,
                issued_at: issued,
                expires_at: issued.checked_add(valid).context("time overflow")?,
                signer: k.id(),
            };
            let signed = SignedAuthorization {
                signature: sign_offline(&k.signing, &auth.hash()?),
                authorization: auth,
            };
            trust::verify_authorization(&signed, head)?;
            write_json(&out, &signed)?;
            println!("Authorized: {}", out.display());
        }
        Cmd::Trust { cmd } => {
            let st = state()?;
            match cmd {
                TrustCmd::Import { fingerprint, chain } => {
                    let fp = Hash::parse(&fingerprint)
                        .context("a fingerprint is sha256: and 64 hex digits")?;
                    let versions: Vec<SignedList> = read_json(&chain)?;
                    let head = st.import(fp, &versions)?;
                    println!(
                        "Pinned deployment {} at version {} ({})",
                        head.list.deployment_id, head.list.version, head.hash
                    );
                }
                TrustCmd::Update { chain } => {
                    let versions: Vec<SignedList> = read_json(&chain)?;
                    let d = versions
                        .first()
                        .context("the chain is empty")?
                        .list
                        .deployment_id;
                    let (from, to) = st.update(&d, &versions)?;
                    println!("Deployment {d}: version {from} -> {to}");
                }
            }
        }
        Cmd::Device { cmd } => {
            let st = state()?;
            match cmd {
                DeviceCmd::Add { name, key_id } => {
                    let key_id =
                        Hash::parse(&key_id).context("a key id is sha256: and 64 hex digits")?;
                    st.add_device(Device { name, key_id })?;
                    println!("Added.");
                }
                DeviceCmd::List => {
                    for d in st.devices()? {
                        println!("{} {}", quoted(&d.name), d.key_id);
                    }
                }
            }
        }
    }
    Ok(())
}
