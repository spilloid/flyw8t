//! Enrollment and the long-lived agent connection.
//!
//! Jobs outlive connections. A job task reports through a channel that whichever session is
//! live drains; when no session is live, its reports are dropped and the journal (which holds
//! the latest state of every unacknowledged job) re-sends them on the next connection.

use crate::config::AgentConfig;
use crate::identity::DeviceKey;
use crate::journal::{Accept, Journal};
use anyhow::{bail, Context, Result};
use base64::Engine;
use flyw8t_protocol::messages::{
    AgentMsg, DeviceFacts, ExecOutcome, Finished, JobPhase, JobReport, NotAccepted, RefusalCode,
    ServerMsg,
};
use flyw8t_protocol::{auth, Action, MAX_MESSAGE_BYTES, PROTOCOL_VERSION};
use futures_util::{SinkExt, StreamExt};
use ring::rand::SecureRandom;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Jobs that may execute at once. Further offers are declined as `Busy`, not buffered.
const MAX_CONCURRENT_JOBS: usize = 2;
/// Reports buffered for the live session. Overflow is dropped; the journal re-sends.
const EVENT_BUFFER: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const INVENTORY_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Conditions under which the agent must stop trying rather than reconnect.
#[derive(Debug, thiserror::Error)]
pub enum Fatal {
    #[error("the server revoked this device's credential: {0}")]
    Revoked(String),
}

enum SessionError {
    Fatal(Fatal),
    Retry(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for SessionError {
    fn from(e: E) -> Self {
        SessionError::Retry(e.into())
    }
}

pub struct Agent {
    cfg: AgentConfig,
    device_id: Uuid,
    key: DeviceKey,
    tls: Arc<ClientConfig>,
    journal: Journal,
    slots: Arc<Semaphore>,
    running: Mutex<HashMap<Uuid, CancellationToken>>,
    events_tx: mpsc::Sender<AgentMsg>,
    events_rx: tokio::sync::Mutex<mpsc::Receiver<AgentMsg>>,
    started: Instant,
}

impl Agent {
    pub fn new(cfg: AgentConfig) -> Result<Arc<Self>> {
        let device_id = cfg.device_id.context("agent is not enrolled")?;
        let key = DeviceKey::load(&cfg.key_path())?;
        let tls = crate::tls::client_config(cfg.ca_cert_pem.as_deref())?;
        let journal = Journal::open(&cfg.journal_dir())?;
        let (events_tx, events_rx) = mpsc::channel(EVENT_BUFFER);
        Ok(Arc::new(Self {
            cfg,
            device_id,
            key,
            tls,
            journal,
            slots: Arc::new(Semaphore::new(MAX_CONCURRENT_JOBS)),
            running: Mutex::new(HashMap::new()),
            events_tx,
            events_rx: tokio::sync::Mutex::new(events_rx),
            started: Instant::now(),
        }))
    }

    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Stay connected until `shutdown`, reconnecting with capped, jittered backoff.
    pub async fn run(self: &Arc<Self>, shutdown: CancellationToken) -> Result<(), Fatal> {
        let mut backoff = Duration::from_secs(1);
        loop {
            let began = Instant::now();
            match self.session(&shutdown).await {
                Ok(()) => tracing::info!("session ended"),
                Err(SessionError::Fatal(f)) => return Err(f),
                Err(SessionError::Retry(e)) => {
                    tracing::warn!(error = %format!("{e:#}"), "session failed")
                }
            }
            if shutdown.is_cancelled() {
                return Ok(());
            }
            if began.elapsed() > MAX_BACKOFF {
                backoff = Duration::from_secs(1);
            }
            let delay = backoff + jitter(backoff / 2);
            tracing::info!(delay_ms = delay.as_millis() as u64, "reconnecting");
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown.cancelled() => return Ok(()),
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// One connection, from handshake until `stop`, a server close, or an error. Public so
    /// tests can drive disconnect/reconnect deterministically.
    pub async fn run_session(self: &Arc<Self>, stop: &CancellationToken) -> Result<()> {
        match self.session(stop).await {
            Ok(()) => Ok(()),
            Err(SessionError::Fatal(f)) => Err(f.into()),
            Err(SessionError::Retry(e)) => Err(e),
        }
    }

    async fn session(self: &Arc<Self>, stop: &CancellationToken) -> Result<(), SessionError> {
        let url = self.cfg.ws_url()?;
        let mut ws = connect(&url, self.tls.clone()).await?;

        let nonce = expect_challenge(&mut ws).await?;
        send(
            &mut ws,
            &AgentMsg::Authenticate {
                protocol_version: PROTOCOL_VERSION,
                device_id: self.device_id,
                signature: self
                    .key
                    .sign_b64(&auth::auth_message(&nonce, self.device_id)),
                agent_version: crate::AGENT_VERSION.to_string(),
            },
        )
        .await?;
        let heartbeat_secs = match recv(&mut ws, HANDSHAKE_TIMEOUT).await? {
            ServerMsg::Welcome { heartbeat_secs, .. } => heartbeat_secs.clamp(5, 300),
            ServerMsg::Refused { code, message } => return Err(refusal(code, message)),
            other => return Err(anyhow::anyhow!("unexpected handshake reply: {other:?}").into()),
        };
        tracing::info!(device_id = %self.device_id, "connected");

        // Exclusive use of the event stream for this session. Anything buffered while
        // disconnected is stale; the journal snapshot below supersedes it.
        let mut events = self.events_rx.lock().await;
        while events.try_recv().is_ok() {}

        let inventory = tokio::task::spawn_blocking(crate::collect::inventory).await?;
        send(&mut ws, &AgentMsg::Inventory(Box::new(inventory))).await?;
        for report in self.journal.unreported() {
            send(&mut ws, &AgentMsg::Job(report)).await?;
        }

        let heartbeat = Duration::from_secs(heartbeat_secs.into());
        let mut heartbeat_tick = tokio::time::interval(heartbeat);
        let mut inventory_tick = tokio::time::interval(INVENTORY_INTERVAL);
        inventory_tick.tick().await;
        let mut last_heard = Instant::now();

        loop {
            tokio::select! {
                _ = stop.cancelled() => {
                    let _ = ws.close(None).await;
                    return Ok(());
                }
                incoming = ws.next() => {
                    let Some(frame) = incoming else { return Err(anyhow::anyhow!("server closed the connection").into()) };
                    let frame = frame?;
                    last_heard = Instant::now();
                    let text = match frame {
                        Message::Text(t) => t,
                        Message::Close(_) => return Err(anyhow::anyhow!("server closed the connection").into()),
                        _ => continue,
                    };
                    let msg: ServerMsg = serde_json::from_str(text.as_str()).context("malformed server message")?;
                    for reply in self.handle(msg)? {
                        send(&mut ws, &reply).await?;
                    }
                }
                Some(event) = events.recv() => send(&mut ws, &event).await?,
                _ = heartbeat_tick.tick() => {
                    if last_heard.elapsed() > heartbeat * 3 {
                        return Err(anyhow::anyhow!("server silent for {:?}", last_heard.elapsed()).into());
                    }
                    let running_jobs = self.running.lock().unwrap().len() as u32;
                    send(&mut ws, &AgentMsg::Heartbeat {
                        agent_version: crate::AGENT_VERSION.to_string(),
                        uptime_secs: self.started.elapsed().as_secs(),
                        running_jobs,
                    }).await?;
                    ws.send(Message::Ping(Vec::new().into())).await?;
                    // A final report can be dropped on a live session (bounded event buffer).
                    // Re-send every unacknowledged one; the server stores each idempotently.
                    for report in self.journal.unreported() {
                        if matches!(report.phase, JobPhase::Finished(_)) {
                            send(&mut ws, &AgentMsg::Job(report)).await?;
                        }
                    }
                }
                _ = inventory_tick.tick() => {
                    let inventory = tokio::task::spawn_blocking(crate::collect::inventory).await?;
                    send(&mut ws, &AgentMsg::Inventory(Box::new(inventory))).await?;
                }
            }
        }
    }

    /// React to one server message; returns immediate replies.
    fn handle(self: &Arc<Self>, msg: ServerMsg) -> Result<Vec<AgentMsg>, SessionError> {
        Ok(match msg {
            ServerMsg::JobOffer {
                job_id,
                action,
                timeout_secs,
            } => vec![AgentMsg::Job(self.on_offer(job_id, action, timeout_secs))],
            ServerMsg::JobCancel { job_id } => self
                .on_cancel(job_id)?
                .into_iter()
                .map(AgentMsg::Job)
                .collect(),
            ServerMsg::ReportAck { job_id } => {
                self.journal.mark_acked(job_id)?;
                vec![]
            }
            ServerMsg::Refused { code, message } => return Err(refusal(code, message)),
            other => {
                tracing::warn!(?other, "ignoring unexpected server message");
                vec![]
            }
        })
    }

    fn on_offer(self: &Arc<Self>, job_id: Uuid, action: Action, timeout_secs: u32) -> JobReport {
        let not_accepted = |reason| JobReport {
            job_id,
            phase: JobPhase::NotAccepted { reason },
        };
        // Duplicate delivery: report what we already know, never run again.
        if let Some(entry) = self.journal.get(job_id) {
            tracing::info!(%job_id, "duplicate offer; re-sending known state");
            return entry.report();
        }
        if action.validate().is_err() {
            return not_accepted(NotAccepted::InvalidParams);
        }
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            return not_accepted(NotAccepted::Busy);
        };
        let timeout =
            Duration::from_secs(timeout_secs.clamp(1, action.info().max_timeout_secs).into());
        match self.journal.accept(job_id, &action, timeout_secs) {
            Ok(Accept::New) => {}
            Ok(Accept::Known(entry)) => return entry.report(),
            Err(e) => {
                tracing::error!(%job_id, error = %format!("{e:#}"), "could not journal job; declining it");
                return not_accepted(NotAccepted::StorageError);
            }
        }
        let token = CancellationToken::new();
        self.running.lock().unwrap().insert(job_id, token.clone());
        let agent = Arc::clone(self);
        tokio::spawn(async move {
            agent.run_job(job_id, action, timeout, token).await;
            drop(permit);
        });
        JobReport {
            job_id,
            phase: JobPhase::Accepted,
        }
    }

    async fn run_job(
        &self,
        job_id: Uuid,
        action: Action,
        timeout: Duration,
        token: CancellationToken,
    ) {
        let at = OffsetDateTime::now_utc();
        let report = if token.is_cancelled() {
            not_run(ExecOutcome::Cancelled { started: false })
        } else if let Err(e) = self.journal.mark_started(job_id, at) {
            // Without a durable start record a crash could hide that this ran, so it must not run.
            not_run(ExecOutcome::NotStarted {
                reason: format!("could not record start: {e:#}"),
            })
        } else {
            self.emit(JobReport {
                job_id,
                phase: JobPhase::Started { at },
            });
            tracing::info!(%job_id, action = action.name(), "running");
            crate::executor::execute(&action, timeout, token, at).await
        };
        if let Err(e) = self.journal.finish(job_id, report.clone()) {
            tracing::error!(%job_id, error = %format!("{e:#}"), "could not journal result");
        }
        self.running.lock().unwrap().remove(&job_id);
        self.emit(JobReport {
            job_id,
            phase: JobPhase::Finished(Box::new(report)),
        });
    }

    fn on_cancel(&self, job_id: Uuid) -> Result<Option<JobReport>> {
        if let Some(token) = self.running.lock().unwrap().get(&job_id) {
            token.cancel();
            return Ok(None); // the job task reports its own end
        }
        let entry = match self.journal.get(job_id) {
            Some(e) => e,
            None => self.journal.cancel_unknown(job_id)?,
        };
        Ok(Some(entry.report()))
    }

    fn emit(&self, report: JobReport) {
        // Dropped when no session is draining; the journal re-sends on reconnect.
        let _ = self.events_tx.try_send(AgentMsg::Job(report));
    }
}

fn not_run(outcome: ExecOutcome) -> Finished {
    Finished {
        outcome,
        started_at: None,
        finished_at: OffsetDateTime::now_utc(),
        stdout: None,
        stderr: None,
        structured: None,
    }
}

fn refusal(code: RefusalCode, message: String) -> SessionError {
    match code {
        RefusalCode::Revoked => SessionError::Fatal(Fatal::Revoked(message)),
        other => SessionError::Retry(anyhow::anyhow!(
            "server refused connection ({other:?}): {message}"
        )),
    }
}

/// Enroll this device with a one-time token. Generates the device key, proves possession of
/// it, and persists identity only once the server confirms.
pub async fn enroll(mut cfg: AgentConfig, token: &str) -> Result<(Uuid, String)> {
    if cfg.device_id.is_some() || cfg.key_path().exists() {
        bail!(
            "{} already holds an enrolled identity; remove it to enroll again",
            cfg.state_dir.display()
        );
    }
    let key = DeviceKey::generate()?;
    let tls = crate::tls::client_config(cfg.ca_cert_pem.as_deref())?;
    let mut ws = connect(&cfg.ws_url()?, tls).await?;
    let nonce = expect_challenge(&mut ws).await.map_err(session_err)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, token.trim().as_bytes());
    send(
        &mut ws,
        &AgentMsg::Enroll {
            protocol_version: PROTOCOL_VERSION,
            token: token.trim().to_string(),
            public_key: key.public_key_b64(),
            signature: key.sign_b64(&auth::enroll_message(
                &nonce,
                key.public_key(),
                digest.as_ref(),
            )),
            facts: DeviceFacts {
                hostname: sysinfo::System::host_name().unwrap_or_default(),
                os_family: std::env::consts::OS.to_string(),
                agent_version: crate::AGENT_VERSION.to_string(),
            },
        },
    )
    .await?;
    match recv(&mut ws, HANDSHAKE_TIMEOUT)
        .await
        .map_err(session_err)?
    {
        ServerMsg::Enrolled {
            device_id,
            organization,
        } => {
            std::fs::create_dir_all(&cfg.state_dir)?;
            key.save(&cfg.key_path())?;
            cfg.device_id = Some(device_id);
            cfg.save()?;
            let _ = ws.close(None).await;
            Ok((device_id, organization))
        }
        ServerMsg::Refused { message, .. } => bail!("enrollment refused: {message}"),
        other => bail!("unexpected enrollment reply: {other:?}"),
    }
}

fn session_err(e: SessionError) -> anyhow::Error {
    match e {
        SessionError::Fatal(f) => f.into(),
        SessionError::Retry(e) => e,
    }
}

async fn connect(url: &str, tls: Arc<ClientConfig>) -> Result<Ws> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    let (ws, _) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async_tls_with_config(
            url,
            Some(config),
            false,
            Some(tokio_tungstenite::Connector::Rustls(tls)),
        ),
    )
    .await
    .context("connect timed out")?
    .with_context(|| format!("connecting to {url}"))?;
    Ok(ws)
}

async fn expect_challenge(ws: &mut Ws) -> Result<Vec<u8>, SessionError> {
    match recv(ws, HANDSHAKE_TIMEOUT).await? {
        ServerMsg::Challenge {
            protocol_version,
            nonce,
        } => {
            if protocol_version != PROTOCOL_VERSION {
                return Err(anyhow::anyhow!(
                    "server speaks protocol {protocol_version}, this agent speaks {PROTOCOL_VERSION}"
                )
                .into());
            }
            let nonce = base64::engine::general_purpose::STANDARD.decode(nonce)?;
            if nonce.len() != auth::NONCE_LEN {
                return Err(anyhow::anyhow!("bad challenge nonce length").into());
            }
            Ok(nonce)
        }
        ServerMsg::Refused { code, message } => Err(refusal(code, message)),
        other => Err(anyhow::anyhow!("expected a challenge, got {other:?}").into()),
    }
}

async fn recv(ws: &mut Ws, timeout: Duration) -> Result<ServerMsg, SessionError> {
    loop {
        let frame = tokio::time::timeout(timeout, ws.next())
            .await
            .context("timed out waiting for the server")?
            .context("server closed the connection")??;
        match frame {
            Message::Text(t) => {
                return Ok(serde_json::from_str(t.as_str()).context("malformed server message")?)
            }
            Message::Close(_) => return Err(anyhow::anyhow!("server closed the connection").into()),
            _ => continue,
        }
    }
}

async fn send(ws: &mut Ws, msg: &AgentMsg) -> Result<()> {
    ws.send(Message::text(serde_json::to_string(msg)?)).await?;
    Ok(())
}

fn jitter(max: Duration) -> Duration {
    let mut b = [0u8; 2];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    max.mul_f64(f64::from(u16::from_le_bytes(b)) / f64::from(u16::MAX))
}
