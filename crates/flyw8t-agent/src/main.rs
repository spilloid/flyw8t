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

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .init();
    let cli = Cli::parse();
    let state_dir = cli.state_dir.unwrap_or_else(config::default_state_dir);

    match cli.command {
        Command::Enroll {
            server,
            token,
            ca_cert,
        } => {
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
            let (id, org) = runtime()?.block_on(flyw8t_agent::enroll(cfg, &token))?;
            println!("Enrolled as device {id} in organization {org:?}.");
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
        Command::Status => {
            let cfg = AgentConfig::load(&state_dir)?;
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
                flyw8t_agent::service::install(&state_dir)?;
                println!(
                    "Service {} installed and started.",
                    flyw8t_agent::service::SERVICE_NAME
                );
                Ok(())
            }
            ServiceCmd::Uninstall => flyw8t_agent::service::uninstall(),
            ServiceCmd::Run => flyw8t_agent::service::run_dispatcher(state_dir),
        },
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Runtime::new()?)
}
