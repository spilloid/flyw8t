use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use flyw8t_agent::{config, AgentConfig};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[cfg(windows)]
mod windows_setup;
#[cfg(any(windows, test))]
mod windows_setup_mode;

/// flyw8t endpoint agent.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Directory holding the agent's identity, configuration and job journal.
    #[arg(long, global = true, env = "FLYW8T_AGENT_STATE_DIR")]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll this device with a one-time enrollment token.
    Enroll {
        /// Server base URL, e.g. https://rmm.example.com
        #[arg(long)]
        server: String,
        /// Enrollment token from the flyw8t web console.
        #[arg(long, env = "FLYW8T_ENROLL_TOKEN")]
        token: String,
        /// PEM file of an extra CA to trust (for a private CA).
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// The deployment's trust fingerprint (sha256:…), from `flyw8t-sign genesis` on your own machine, never
        /// copied from the console. Without it this agent runs built-in actions only and refuses every script.
        #[arg(long, requires = "org")]
        trust: Option<String>,
        /// The organization id this device belongs in, also from your own notes. Required with --trust.
        #[arg(long, requires = "trust")]
        org: Option<uuid::Uuid>,
    },
    /// Pin, or show, what this agent trusts to run scripts (ADR-0015).
    Trust {
        #[command(subcommand)]
        action: TrustCmd,
    },
    /// Run the agent in the foreground.
    Run,
    /// Show enrollment and journal state.
    Status {
        /// Print the local enrollment record and agent version as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check the local terminal facilities.
    TerminalCheck {
        /// Exercise local Windows PowerShell input, output, and Ctrl+C through a pseudoconsole.
        #[cfg(windows)]
        #[arg(long)]
        powershell: bool,
        /// Require both the diagnostic and PowerShell to run in the Windows service session.
        #[cfg(windows)]
        #[arg(long, requires = "powershell")]
        require_session_zero: bool,
    },
    /// Verify a newer Windows agent candidate's signed manifest and Authenticode publisher.
    #[cfg(all(windows, target_arch = "x86_64"))]
    UpdateCheck {
        /// Use this independently supplied hex key for this check. Defaults to the local pin.
        #[arg(long)]
        public_key: Option<String>,
        /// Require a fresh allow decision from this device's enrolled server using the local pin.
        #[arg(long, conflicts_with = "public_key")]
        fleet_policy: bool,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        /// Manifest for the running version's fallback image. Requires the local release key pin.
        #[arg(long, requires = "rollback_artifact", conflicts_with = "public_key")]
        rollback_manifest: Option<PathBuf>,
        /// Original signed fallback executable for the running version.
        #[arg(long, requires = "rollback_manifest", conflicts_with = "public_key")]
        rollback_artifact: Option<PathBuf>,
    },
    /// Pin or inspect the local Windows agent release verification key.
    #[cfg(all(windows, target_arch = "x86_64"))]
    UpdateTrust {
        #[command(subcommand)]
        action: UpdateTrustCmd,
    },
    /// Inspect or change the administrator's local background terminal opt-in.
    #[cfg(windows)]
    TerminalPolicy {
        #[command(subcommand)]
        action: TerminalPolicyCmd,
    },
    /// Windows service management.
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
}

#[derive(Subcommand)]
enum TrustCmd {
    /// Pin an agent enrolled before the trust list existed. Run as Administrator, with the service stopped.
    Pin {
        /// The deployment's trust fingerprint (sha256:…), from your own notes.
        fingerprint: String,
        /// The organization id this device belongs in.
        #[arg(long)]
        org: uuid::Uuid,
    },
    /// Show the fingerprint, version, head hash and organization this agent holds.
    Status,
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Subcommand)]
enum UpdateTrustCmd {
    /// Pin the key from a trusted source. Run as Administrator after enrollment.
    Pin {
        /// The 64 hex digits printed by the offline release signer.
        #[arg(long)]
        public_key: String,
    },
    /// Show the release verification key pinned on this machine.
    Status,
}

#[cfg(windows)]
#[derive(Subcommand)]
enum TerminalPolicyCmd {
    /// Check the local policy for this enrolled device.
    Status,
    /// Enable the local policy for this enrolled device.
    Enable,
    /// Revoke the local opt-in for this enrolled device.
    Disable,
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceCmd {
    /// Install and start the agent as an automatic-start LocalSystem service.
    Install,
    /// Stop and remove the service.
    Uninstall,
    /// Entry point used by the Service Control Manager.
    Run,
}

/// Largest the service's log file grows before it is rotated (one older file is kept).
const SERVICE_LOG_BYTES: u64 = 10 * 1024 * 1024;

fn main() -> Result<()> {
    // Opened first, without delete sharing: from here on this program's file cannot be renamed or replaced, and
    // `service install` copies what this handle reads, not whatever is at the path by then.
    #[cfg(windows)]
    let own_file = {
        use std::os::windows::fs::OpenOptionsExt;
        std::env::current_exe().and_then(|p| {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(1) // FILE_SHARE_READ
                .open(p)
        })
    };
    #[cfg(all(windows, target_arch = "x86_64"))]
    flyw8t_agent::retain_windows_release_version();
    #[cfg(windows)]
    if let Some(mode) = windows_setup_mode::SetupMode::parse(std::env::args_os().skip(1)) {
        use windows_setup_mode::SetupMode;
        match mode {
            SetupMode::Interactive => return windows_setup::run(own_file, false),
            SetupMode::Elevated => return windows_setup::run(own_file, true),
            SetupMode::Quiet => std::process::exit(windows_setup::run_quiet(own_file)),
        }
    }
    let cli = Cli::parse();
    let state_dir = match cli.state_dir {
        Some(d) => d,
        None => config::default_state_dir()?,
    };
    let filter =
        || tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    #[cfg(windows)]
    let as_service = matches!(
        cli.command,
        Command::Service {
            action: ServiceCmd::Run
        }
    );
    #[cfg(not(windows))]
    let as_service = false;
    // A service has no console: log to `logs\agent.log` in the state directory, which only SYSTEM and Administrators
    // can read. If that cannot be opened, run anyway rather than fail to start.
    let log_file = as_service
        .then(|| {
            let path = state_dir.join("logs").join("agent.log");
            flyw8t_agent::logfile::RotatingFile::open(&path, SERVICE_LOG_BYTES)
                .inspect_err(|_e| {
                    #[cfg(windows)]
                    flyw8t_agent::winsec::event_log_warning(&format!(
                        "flyw8t agent: cannot open its log {}: {_e}. Running without a log.",
                        path.display()
                    ));
                })
                .ok()
        })
        .flatten();
    if let Some(file) = log_file {
        tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .init();
        tracing::info!(version = env!("CARGO_PKG_VERSION"), "service starting");
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_ansi(false)
            .init();
    }

    match cli.command {
        Command::Enroll {
            server,
            token,
            ca_cert,
            trust,
            org,
        } => {
            let pin = match (trust, org) {
                (Some(t), Some(o)) => Some(flyw8t_agent::trust::Pin::parse(&t, o)?),
                _ => None,
            };
            let ca_cert_pem = ca_cert
                .map(|p| {
                    std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))
                })
                .transpose()?;
            let cfg = AgentConfig {
                server_url: server,
                ca_cert_pem,
                device_id: None,
                enrollment_scope: None,
                state_dir,
            };
            config::ws_url(&cfg.server_url)?;
            #[cfg(windows)]
            prepare_state_dir(&cfg.state_dir)?;
            let (id, org, pinned) = runtime()?.block_on(flyw8t_agent::enroll(cfg, &token, pin))?;
            println!("Enrolled as device {id} in organization {org:?}.");
            match pinned {
                Some(p) => print_trust(&p),
                None => println!("Not pinned to a trust list: this agent will refuse every script until `flyw8t-agent trust pin`."),
            }
            Ok(())
        }
        Command::Run => {
            let agent = flyw8t_agent::Agent::new(AgentConfig::load(&state_dir)?)?;
            runtime()?.block_on(async {
                let shutdown = CancellationToken::new();
                let s = shutdown.clone();
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    s.cancel();
                });
                agent.run(shutdown).await.map_err(anyhow::Error::from)
            })
        }
        Command::Trust { action } => {
            let cfg = AgentConfig::load(&state_dir)?;
            match action {
                TrustCmd::Pin { fingerprint, org } => {
                    let pin = flyw8t_agent::trust::Pin::parse(&fingerprint, org)?;
                    let p = runtime()?.block_on(flyw8t_agent::trust_pin(cfg, pin))?;
                    println!("Pinned.");
                    print_trust(&p);
                }
                TrustCmd::Status => match flyw8t_agent::trust::Trust::load(&cfg.state_dir)?.get() {
                    Some(p) => print_trust(&p),
                    None => println!("Not pinned: this agent refuses every script."),
                },
            }
            Ok(())
        }
        Command::Status { json } => {
            let cfg = AgentConfig::load(&state_dir)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "agent_version": flyw8t_agent::AGENT_VERSION,
                        "server_url": cfg.server_url,
                        "device_id": cfg.device_id,
                        "enrollment_scope": cfg.enrollment_scope,
                    })
                );
                return Ok(());
            }
            if let Ok(key) = flyw8t_agent::identity::DeviceKey::load(&cfg.key_path()) {
                println!(
                    "device key id: {}",
                    flyw8t_protocol::trust::key_id(
                        flyw8t_protocol::trust::KeyKind::Device,
                        key.public_key()
                    )
                );
            }
            println!("server:    {}", cfg.server_url);
            println!(
                "device id: {}",
                cfg.device_id
                    .map_or("(not enrolled)".into(), |d| d.to_string())
            );
            let journal = flyw8t_agent::journal::Journal::open(&cfg.journal_dir())?;
            println!("unacknowledged job reports: {}", journal.unreported().len());
            Ok(())
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        Command::UpdateCheck {
            public_key,
            fleet_policy,
            manifest,
            artifact,
            rollback_manifest,
            rollback_artifact,
        } => {
            use flyw8t_agent::update_verify::key_pin;
            let (key, source) = match public_key {
                Some(key) => (key_pin::parse(&key)?, "explicit"),
                None => (
                    key_pin::load(&state_dir)?.context(
                        "pin the release public key with update-trust pin or supply --public-key",
                    )?,
                    "pinned",
                ),
            };
            let release = flyw8t_agent::update_verify::check(&manifest, &artifact, &key)?;
            let rollback = rollback_manifest
                .zip(rollback_artifact)
                .map(|(manifest, artifact)| {
                    flyw8t_agent::update_verify::check_rollback(&manifest, &artifact, &key)
                        .context("verifying the rollback artifact")
                })
                .transpose()?;
            if fleet_policy {
                use flyw8t_protocol::messages::AgentUpdatePolicy;
                let version = release.version.clone();
                let cfg = AgentConfig::load(&state_dir)?;
                let policy = runtime()?
                    .block_on(flyw8t_agent::connection::observe_update_policy(
                        &cfg, release,
                    ))
                    .context("cannot confirm automatic agent update eligibility")?;
                match policy {
                    AgentUpdatePolicy::Enabled => println!(
                        "Verified Windows x64 agent candidate {version} with the pinned release key. The current fleet policy allows automatic updates."
                    ),
                    AgentUpdatePolicy::OrganizationPaused => {
                        anyhow::bail!("the organization has paused automatic agent updates")
                    }
                    AgentUpdatePolicy::DeviceOptedOut => {
                        anyhow::bail!("this device has opted out of automatic agent updates")
                    }
                };
            } else {
                println!(
                    "Verified Windows x64 agent candidate {} using the {source} release key.",
                    release.version
                );
            }
            if let Some(rollback) = rollback {
                println!(
                    "Verified Windows x64 rollback artifact {} using the pinned release key.",
                    rollback.version
                );
            }
            Ok(())
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        Command::UpdateTrust { action } => {
            use flyw8t_agent::update_verify::key_pin;
            match action {
                UpdateTrustCmd::Pin { public_key } => {
                    let key = key_pin::parse(&public_key)?;
                    let created = key_pin::pin(&state_dir, &key)?;
                    println!(
                        "{} release public key {}.",
                        if created { "Pinned" } else { "Already pinned" },
                        hex::encode(key)
                    );
                }
                UpdateTrustCmd::Status => match key_pin::load(&state_dir)? {
                    Some(key) => println!("Pinned release public key {}.", hex::encode(key)),
                    None => println!("Release public key is unpinned."),
                },
            }
            Ok(())
        }
        Command::TerminalCheck {
            #[cfg(windows)]
            powershell,
            #[cfg(windows)]
            require_session_zero,
        } => {
            #[cfg(windows)]
            if powershell {
                flyw8t_agent::terminal::check_powershell(require_session_zero)?;
                println!("Local PowerShell input, output, Ctrl+C, normal exit, forced cleanup, and Windows session isolation verified.");
                return Ok(());
            }
            use flyw8t_agent::terminal::{check, Readiness};
            match runtime()?.block_on(check()) {
                Readiness::GreetingReceived => {
                    println!("Received an SSH 2.0 greeting from 127.0.0.1:22.");
                    Ok(())
                }
                Readiness::ListenerUnavailable => {
                    anyhow::bail!("The SSH service at 127.0.0.1:22 is unavailable.")
                }
                Readiness::InvalidGreeting => {
                    anyhow::bail!(
                        "The service at 127.0.0.1:22 did not send a valid SSH 2.0 greeting."
                    )
                }
                Readiness::TimedOut => anyhow::bail!("The local SSH service check timed out."),
            }
        }
        #[cfg(windows)]
        Command::TerminalPolicy { action } => {
            use flyw8t_agent::terminal::{background_policy_enabled, configure_background_policy};
            let allow = match action {
                TerminalPolicyCmd::Status => background_policy_enabled(&state_dir)?,
                TerminalPolicyCmd::Enable | TerminalPolicyCmd::Disable => {
                    let allow = matches!(action, TerminalPolicyCmd::Enable);
                    configure_background_policy(&state_dir, allow)?;
                    allow
                }
            };
            if allow {
                println!("Background terminal policy enabled locally.");
            } else {
                println!("Background terminal policy disabled locally.");
            }
            Ok(())
        }
        #[cfg(windows)]
        Command::Service { action } => match action {
            ServiceCmd::Install => {
                AgentConfig::load(&state_dir)?;
                use std::io::Read;
                let mut source = own_file.context("opening this program to copy it")?;
                let base_len =
                    flyw8t_protocol::enrollment_package::EnrollmentPackage::read(&mut source)?
                        .map_or(u64::MAX, |(length, _)| length);
                flyw8t_agent::service::install(&state_dir, source.take(base_len))?;
                println!(
                    "Service {} installed and started, running {}. Its log: {}",
                    flyw8t_agent::service::SERVICE_NAME,
                    flyw8t_agent::service::install_path()?.display(),
                    state_dir.join("logs").join("agent.log").display()
                );
                Ok(())
            }
            ServiceCmd::Uninstall => flyw8t_agent::service::uninstall(),
            ServiceCmd::Run => flyw8t_agent::service::run_dispatcher(state_dir),
        },
    }
}

fn print_trust(p: &flyw8t_agent::trust::Pinned) {
    println!("trust fingerprint: {}", p.fingerprint);
    println!("organization:      {}", p.organization_id);
    println!("deployment:        {}", p.head.list.deployment_id);
    println!("trust version:     {}", p.head.list.version);
    println!("head:              {}", p.head.hash);
    println!("Compare the version and head with `flyw8t-sign show` on your signing machine.");
}

/// Before the device key exists, make its folder: created owned by Administrators and open only to SYSTEM and
/// Administrators, in the same call, so the key is never readable by anyone else, even for a moment. An existing
/// folder must already be exactly that. This needs an elevated shell. A custom `--state-dir` is for running in the
/// foreground only: it is used as it is, unprotected (the service refuses it).
#[cfg(windows)]
fn prepare_state_dir(state_dir: &std::path::Path) -> Result<()> {
    use flyw8t_agent::winsec::{ensure_dir, PRIVATE};
    if !config::is_default_state_dir(state_dir)? {
        eprintln!(
            "warning: {} is a custom state folder: its permissions are left as they are, so the device key in it \
             is not protected, and `service install` will not use it",
            state_dir.display()
        );
        std::fs::create_dir_all(state_dir)?;
        return Ok(());
    }
    // Use Windows' own spelling of the default folder from here on.
    let state_dir = &config::default_state_dir()?;
    for dir in [
        state_dir.parent().context("state folder has no parent")?,
        state_dir,
    ] {
        anyhow::ensure!(
            ensure_dir(dir, PRIVATE)?,
            "run enroll as Administrator: {} must be created owned by Administrators",
            dir.display()
        );
    }
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Runtime::new()?)
}

#[cfg(all(test, windows, target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn rollback_paths_are_paired_and_require_the_pin() {
        let update = [
            "flyw8t-agent",
            "update-check",
            "--manifest",
            "candidate.json",
            "--artifact",
            "candidate.exe",
        ];
        let manifest = ["--rollback-manifest", "rollback.json"];
        let artifact = ["--rollback-artifact", "rollback.exe"];
        assert!(Cli::try_parse_from(update).is_ok());
        assert!(Cli::try_parse_from(update.into_iter().chain(manifest)).is_err());
        assert!(Cli::try_parse_from(update.into_iter().chain(artifact)).is_err());
        let pair = update.into_iter().chain(manifest).chain(artifact);
        assert!(Cli::try_parse_from(pair.clone()).is_ok());
        assert!(Cli::try_parse_from(pair.chain(["--public-key", "explicit"])).is_err());
    }
}
