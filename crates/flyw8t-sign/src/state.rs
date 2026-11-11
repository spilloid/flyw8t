//! What `flyw8t-sign` remembers on the signer's own machine (ADR-0015 sections 2 and 8): per deployment, the
//! verified chain and the last version this machine signed; and the device list `authorize` checks targets against.
//! None of it comes from the server unverified.

use anyhow::{bail, Context, Result};
use flyw8t_protocol::trust::{self, Hash, SignedList, TrustError, Verified};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct State {
    root: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainFile {
    fingerprint: Hash,
    versions: Vec<SignedList>,
}

/// The newest version this machine has signed for a deployment: it never signs a different one at that number or
/// below, so the server cannot collect signatures for two successors of one version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u64,
    pub hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub name: String,
    pub key_id: Hash,
}

pub struct Chain {
    pub fingerprint: Hash,
    pub versions: Vec<SignedList>,
    pub head: Verified,
}

impl State {
    pub fn open(root: PathBuf) -> Result<State> {
        std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
        Ok(State { root })
    }

    pub fn default_root() -> PathBuf {
        if let Some(p) = std::env::var_os("FLYW8T_SIGN_STATE") {
            return PathBuf::from(p);
        }
        let base = std::env::var_os("APPDATA")
            .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("flyw8t-sign")
    }

    fn dir(&self, deployment: &Uuid) -> PathBuf {
        self.root.join(deployment.to_string())
    }

    pub fn deployments(&self) -> Result<Vec<Uuid>> {
        let mut out = vec![];
        for e in std::fs::read_dir(&self.root)? {
            if let Some(u) = e?
                .file_name()
                .to_str()
                .and_then(|n| Uuid::parse_str(n).ok())
            {
                out.push(u);
            }
        }
        out.sort();
        Ok(out)
    }

    /// The chain held for `deployment`, re-verified from its fingerprint every time it is read.
    pub fn chain(&self, deployment: &Uuid) -> Result<Option<Chain>> {
        let p = self.dir(deployment).join("chain.json");
        let Some(raw) = read_opt(&p)? else {
            return Ok(None);
        };
        let f: ChainFile =
            serde_json::from_slice(&raw).with_context(|| format!("reading {}", p.display()))?;
        let head = trust::verify_chain(&f.fingerprint, &f.versions)
            .with_context(|| format!("the chain in {} no longer verifies", p.display()))?;
        if head.list.deployment_id != *deployment {
            bail!("{} holds another deployment's chain", p.display());
        }
        Ok(Some(Chain {
            fingerprint: f.fingerprint,
            versions: f.versions,
            head,
        }))
    }

    pub fn require_chain(&self, deployment: &Uuid) -> Result<Chain> {
        self.chain(deployment)?.ok_or_else(|| {
            anyhow::anyhow!(
                "this machine holds no chain for deployment {deployment}: run `flyw8t-sign trust import` with the fingerprint from your own notes"
            )
        })
    }

    fn save_chain(&self, fingerprint: Hash, versions: &[SignedList]) -> Result<()> {
        let head = trust::verify_chain(&fingerprint, versions)?;
        let dir = self.dir(&head.list.deployment_id);
        std::fs::create_dir_all(&dir)?;
        write_atomic(
            &dir.join("chain.json"),
            &serde_json::to_vec_pretty(&ChainFile {
                fingerprint,
                versions: versions.to_vec(),
            })?,
        )
    }

    /// Pin a chain by its fingerprint. Refuses a deployment already held: use `update`.
    pub fn import(&self, fingerprint: Hash, versions: &[SignedList]) -> Result<Verified> {
        let head = trust::verify_chain(&fingerprint, versions)?;
        if self.chain(&head.list.deployment_id)?.is_some() {
            bail!(
                "deployment {} is already held; use `trust update`",
                head.list.deployment_id
            );
        }
        self.save_chain(fingerprint, versions)?;
        Ok(head)
    }

    /// Extend the held chain with `offered`, which may repeat versions already held: those must be identical.
    pub fn update(&self, deployment: &Uuid, offered: &[SignedList]) -> Result<(u64, u64)> {
        let c = self.require_chain(deployment)?;
        let from = c.head.list.version;
        let mut versions = c.versions.clone();
        let mut new = vec![];
        for v in offered {
            match versions.iter().find(|h| h.list.version == v.list.version) {
                Some(held) if held.list != v.list => {
                    bail!(
                        "the server offers a different version {} from the one held: refusing",
                        v.list.version
                    )
                }
                Some(_) => {}
                None => new.push(v.clone()),
            }
        }
        new.sort_by_key(|v| v.list.version);
        let head = trust::extend(c.head, &new).map_err(|e: TrustError| anyhow::anyhow!(e))?;
        if let Some(cp) = self.checkpoint(deployment)? {
            if let Some(v) = versions
                .iter()
                .chain(&new)
                .find(|v| v.list.version == cp.version)
            {
                if v.list.hash()? != cp.hash {
                    bail!(
                        "version {} differs from the one this machine signed ({}): the server is offering two versions with one number",
                        cp.version,
                        cp.hash
                    );
                }
            }
        }
        versions.extend(new);
        self.save_chain(c.fingerprint, &versions)?;
        Ok((from, head.list.version))
    }

    pub fn checkpoint(&self, deployment: &Uuid) -> Result<Option<Checkpoint>> {
        let p = self.dir(deployment).join("signed.json");
        read_opt(&p)?
            .map(|raw| {
                serde_json::from_slice(&raw).with_context(|| format!("reading {}", p.display()))
            })
            .transpose()
    }

    /// Record that this machine signs `version` with `hash`, refusing a second version at that number or below.
    pub fn record_signing(&self, deployment: &Uuid, version: u64, hash: Hash) -> Result<()> {
        if let Some(cp) = self.checkpoint(deployment)? {
            if version < cp.version || (version == cp.version && hash != cp.hash) {
                bail!(
                    "this machine already signed version {} ({}); it will not sign another version {version}",
                    cp.version,
                    cp.hash
                );
            }
        }
        let dir = self.dir(deployment);
        std::fs::create_dir_all(&dir)?;
        write_atomic(
            &dir.join("signed.json"),
            &serde_json::to_vec_pretty(&Checkpoint { version, hash })?,
        )
    }

    pub fn devices(&self) -> Result<Vec<Device>> {
        let p = self.root.join("devices.json");
        Ok(match read_opt(&p)? {
            Some(raw) => {
                serde_json::from_slice(&raw).with_context(|| format!("reading {}", p.display()))?
            }
            None => vec![],
        })
    }

    pub fn add_device(&self, d: Device) -> Result<()> {
        let mut all = self.devices()?;
        if all.iter().any(|x| x.key_id == d.key_id || x.name == d.name) {
            bail!("a device with that name or key id is already listed");
        }
        all.push(d);
        write_atomic(
            &self.root.join("devices.json"),
            &serde_json::to_vec_pretty(&all)?,
        )
    }
}

fn read_opt(p: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(p) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}

/// Write to a temporary file, flush it, and rename it over `p`.
pub fn write_atomic(p: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = p.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, p).with_context(|| format!("writing {}", p.display()))
}
