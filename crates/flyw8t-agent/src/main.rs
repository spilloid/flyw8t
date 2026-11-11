use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use flyw8t_agent::{config, AgentConfig};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

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
    Status,
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
        Command::Status => {
            let cfg = AgentConfig::load(&state_dir)?;
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
        #[cfg(windows)]
        Command::Service { action } => match action {
            ServiceCmd::Install => {
                AgentConfig::load(&state_dir)?;
                let source = own_file.context("opening this program to copy it")?;
                flyw8t_agent::service::install(&state_dir, source)?;
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
