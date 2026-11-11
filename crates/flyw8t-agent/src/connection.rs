//! Enrollment and the long-lived agent connection.
//!
//! Jobs outlive connections. A job task reports through a channel that whichever session is
//! live drains; when no session is live, its reports are dropped and the journal (which holds
//! the latest state of every unacknowledged job) re-sends them on the next connection.

use crate::config::AgentConfig;
use crate::identity::DeviceKey;
use crate::journal::{Accept, Journal, ScriptRef};
use crate::script::Policy;
use crate::spent::Spent;
use crate::trust::{Pin, Pinned, Trust};
use anyhow::{bail, Context, Result};
use base64::Engine;
use flyw8t_protocol::messages::ScriptOffer;
use flyw8t_protocol::messages::{
    AgentMsg, DeviceFacts, ExecOutcome, Finished, JobPhase, JobReport, NotAccepted, RefusalCode,
    ServerMsg,
};
use flyw8t_protocol::trust::{key_id, Hash, KeyKind};
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
    trust: Trust,
    spent: Spent,
    policy: Policy,
    device_key_id: Hash,
    slots: Arc<Semaphore>,
    running: Mutex<HashMap<Uuid, CancellationToken>>,
    events_tx: mpsc::Sender<AgentMsg>,
    events_rx: tokio::sync::Mutex<mpsc::Receiver<AgentMsg>>,
    started: Instant,
    /// Held for the agent's lifetime: one process per state directory (see `lock_state_dir`).
    _lock: std::fs::File,
}

impl Agent {
    pub fn new(cfg: AgentConfig) -> Result<Arc<Self>> {
        let device_id = cfg.device_id.context("agent is not enrolled")?;
        // Before the journal is read: two processes sharing one journal could each believe a
        // job is new and both run it (adversarial review finding 2).
        let lock = lock_state_dir(&cfg.state_dir)?;
        let key = DeviceKey::load(&cfg.key_path())?;
        let tls = crate::tls::client_config(cfg.ca_cert_pem.as_deref())?;
        let journal = Journal::open(&cfg.journal_dir())?;
        let trust = Trust::load(&cfg.state_dir)?;
        let spent = Spent::open(&cfg.state_dir)?;
        let policy = crate::script::load_policy(&cfg.state_dir)?;
        let device_key_id = key_id(KeyKind::Device, key.public_key());
        let (events_tx, events_rx) = mpsc::channel(EVENT_BUFFER);
        Ok(Arc::new(Self {
            cfg,
            device_id,
            key,
            tls,
            journal,
            trust,
            spent,
            policy,
            device_key_id,
            slots: Arc::new(Semaphore::new(MAX_CONCURRENT_JOBS)),
            running: Mutex::new(HashMap::new()),
            events_tx,
            events_rx: tokio::sync::Mutex::new(events_rx),
            started: Instant::now(),
            _lock: lock,
        }))
    }

    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    pub fn trust(&self) -> &Trust {
        &self.trust
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
                capabilities: crate::CAPABILITIES.iter().map(|c| c.to_string()).collect(),
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

        // A pinned agent asks for any trust-list versions after the one it holds.
        if let Some(p) = self.trust.get() {
            send(
                &mut ws,
                &AgentMsg::TrustRequest {
                    after: Some(p.head.list.version),
                },
            )
            .await?;
        }
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
                    if let Err(e) = self.journal.prune() {
                        tracing::warn!(error = %format!("{e:#}"), "journal prune failed");
                    }
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
            ServerMsg::ScriptOffer(offer) => vec![AgentMsg::Job(self.on_script_offer(*offer))],
            ServerMsg::JobCancel { job_id } => self
                .on_cancel(job_id)?
                .into_iter()
                .map(AgentMsg::Job)
                .collect(),
            ServerMsg::ReportAck { job_id } => {
                self.journal.mark_acked(job_id)?;
                vec![]
            }
            ServerMsg::TrustUpdate { versions } => {
                match self.trust.update(&versions) {
                    Ok(Some(v)) => tracing::info!(version = v, "trust list held"),
                    Ok(None) => {
                        tracing::warn!("trust versions offered to an agent that is not pinned")
                    }
                    // Refused and kept as it was: the server cannot extend or wind back what this agent trusts.
                    Err(e) => {
                        tracing::warn!(error = %format!("{e:#}"), "refused trust-list update")
                    }
                }
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

    fn on_script_offer(self: &Arc<Self>, offer: ScriptOffer) -> JobReport {
        let job_id = offer.job_id;
        if let Some(entry) = self.journal.get(job_id) {
            tracing::info!(%job_id, "duplicate script offer; re-sending known state");
            return entry.report();
        }
        let script = ScriptRef {
            script_id: offer.revision.script_id,
            revision: offer.revision.revision,
            content_hash: offer.revision.content_hash(),
        };
        // Checked when it arrives, so a bad job is refused at once; checked again just before it starts.
        let first = {
            let g = self.trust.lock();
            crate::script::check(
                g.as_ref(),
                &self.device_key_id,
                &self.policy,
                &offer,
                unix_now(),
                &self.spent,
            )
        };
        let refuse = |why: String| {
            tracing::warn!(%job_id, reason = %why, "script refused");
            match self
                .journal
                .accept_script(job_id, script.clone(), offer.timeout_secs)
            {
                Ok(Accept::Known(e)) => e.report(),
                Ok(Accept::New) => {
                    let report = not_run(ExecOutcome::Failed {
                        error: format!("refused, nothing ran: {why}"),
                    });
                    let _ = self.journal.finish(job_id, report.clone());
                    JobReport {
                        job_id,
                        phase: JobPhase::Finished(Box::new(report)),
                    }
                }
                Err(_) => JobReport {
                    job_id,
                    phase: JobPhase::NotAccepted {
                        reason: NotAccepted::StorageError,
                    },
                },
            }
        };
        if let Err(why) = first {
            return refuse(why);
        }
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            return JobReport {
                job_id,
                phase: JobPhase::NotAccepted {
                    reason: NotAccepted::Busy,
                },
            };
        };
        match self
            .journal
            .accept_script(job_id, script, offer.timeout_secs)
        {
            Ok(Accept::New) => {}
            Ok(Accept::Known(entry)) => return entry.report(),
            Err(e) => {
                tracing::error!(%job_id, error = %format!("{e:#}"), "could not journal script job; declining it");
                return JobReport {
                    job_id,
                    phase: JobPhase::NotAccepted {
                        reason: NotAccepted::StorageError,
                    },
                };
            }
        }
        let token = CancellationToken::new();
        self.running.lock().unwrap().insert(job_id, token.clone());
        let agent = Arc::clone(self);
        tokio::spawn(async move {
            agent.run_script(offer, token).await;
            drop(permit);
        });
        JobReport {
            job_id,
            phase: JobPhase::Accepted,
        }
    }

    /// Admission in the ADR's order, under the trust lock: check again, spend the authorization, advance the clock
    /// mark, record `Started`; then release the lock and start the interpreter.
    async fn run_script(self: &Arc<Self>, offer: ScriptOffer, token: CancellationToken) {
        let job_id = offer.job_id;
        let at = OffsetDateTime::now_utc();
        let admitted = {
            let g = self.trust.lock();
            let now = unix_now();
            match crate::script::check(
                g.as_ref(),
                &self.device_key_id,
                &self.policy,
                &offer,
                now,
                &self.spent,
            ) {
                Err(why) => Err(format!("refused, nothing ran: {why}")),
                Ok(a) => {
                    let spent = if a.class.needs_run_signature() {
                        self.spent
                            .spend(offer.deployment_id, job_id)
                            .map_err(|e| format!("refused, nothing ran: {e:#}"))
                    } else {
                        Ok(())
                    };
                    spent
                        .and_then(|_| {
                            self.spent
                                .advance(now)
                                .map_err(|e| format!("refused, nothing ran: {e:#}"))
                        })
                        .and_then(|_| {
                            if token.is_cancelled() {
                                return Err("cancelled before it started".into());
                            }
                            self.journal
                                .mark_started(job_id, at)
                                .map_err(|e| format!("could not record start: {e:#}"))
                        })
                        .map(|_| a)
                }
            }
        };
        let report = match admitted {
            Err(why) => not_run(if why.starts_with("cancelled") {
                ExecOutcome::Cancelled { started: false }
            } else if why.starts_with("could not record start") {
                ExecOutcome::NotStarted { reason: why }
            } else {
                ExecOutcome::Failed { error: why }
            }),
            Ok(a) => {
                self.emit(JobReport {
                    job_id,
                    phase: JobPhase::Started { at },
                });
                tracing::info!(%job_id, script = %offer.revision.script_id, revision = offer.revision.revision, "running script");
                let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let flag = cancel.clone();
                let watch = token.clone();
                let watcher = tokio::spawn(async move {
                    watch.cancelled().await;
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                });
                let state_dir = self.cfg.state_dir.clone();
                let source = offer.revision.source.clone();
                let report = tokio::task::spawn_blocking(move || {
                    crate::runner::run(
                        crate::runner::Run {
                            state_dir: &state_dir,
                            job_id,
                            source: &source,
                            values: a.values,
                            secrets: a.secrets,
                            timeout: Duration::from_secs(a.timeout_secs),
                            cancel,
                        },
                        at,
                    )
                })
                .await
                .unwrap_or_else(|e| {
                    not_run(ExecOutcome::Interrupted {
                        reason: format!("the runner failed: {e}"),
                    })
                });
                watcher.abort();
                report
            }
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

fn unix_now() -> u64 {
    OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
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

/// Ask for the whole trust chain before authenticating, and verify it against `pin`.
async fn fetch_chain(ws: &mut Ws, pin: &Pin) -> Result<Pinned> {
    send(ws, &AgentMsg::TrustRequest { after: None }).await?;
    match recv(ws, HANDSHAKE_TIMEOUT).await.map_err(session_err)? {
        ServerMsg::TrustUpdate { versions } => pin.verify(&versions),
        ServerMsg::Refused { message, .. } => bail!("the server refused: {message}"),
        other => bail!("expected the trust chain, got {other:?}"),
    }
}

/// Enroll this device with a one-time token. Generates the device key, proves possession of
/// it, and persists identity only once the server confirms. With `pin`, the server's trust chain must verify
/// against the fingerprint before the device key is sent, and the organization the server enrolls it into must
/// be the one given (ADR-0015 section 3); otherwise nothing is stored.
pub async fn enroll(
    mut cfg: AgentConfig,
    token: &str,
    pin: Option<Pin>,
) -> Result<(Uuid, String, Option<Pinned>)> {
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
    let pinned = match &pin {
        Some(p) => Some(fetch_chain(&mut ws, p).await?),
        None => None,
    };
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
            organization_id,
        } => {
            if let Some(p) = &pinned {
                if organization_id != Some(p.organization_id) {
                    bail!(
                        "the server enrolled this device into organization {organization:?} ({}), not {} as given: nothing was saved. Retire device {device_id} in the console.",
                        organization_id.map_or("no id".into(), |o| o.to_string()),
                        p.organization_id
                    );
                }
            }
            std::fs::create_dir_all(&cfg.state_dir)?;
            key.save(&cfg.key_path())?;
            if let Some(p) = &pinned {
                crate::trust::store(&cfg.state_dir, p)?;
            }
            cfg.device_id = Some(device_id);
            cfg.save()?;
            let _ = ws.close(None).await;
            Ok((device_id, organization, pinned))
        }
        ServerMsg::Refused { message, .. } => bail!("enrollment refused: {message}"),
        other => bail!("unexpected enrollment reply: {other:?}"),
    }
}

/// Pin an agent enrolled before ADR-0015 (`flyw8t-agent trust pin`): verify the server's chain against the
/// fingerprint, authenticate, and check the organization the server has this device in against the one given.
/// Holds the state-folder lock, so the service must be stopped.
pub async fn trust_pin(cfg: AgentConfig, pin: Pin) -> Result<Pinned> {
    let device_id = cfg.device_id.context("agent is not enrolled")?;
    let _lock = lock_state_dir(&cfg.state_dir)
        .context("stop the flyw8t-agent service first: it holds the state folder")?;
    let key = DeviceKey::load(&cfg.key_path())?;
    let tls = crate::tls::client_config(cfg.ca_cert_pem.as_deref())?;
    let mut ws = connect(&cfg.ws_url()?, tls).await?;
    let nonce = expect_challenge(&mut ws).await.map_err(session_err)?;
    let pinned = fetch_chain(&mut ws, &pin).await?;
    send(
        &mut ws,
        &AgentMsg::Authenticate {
            protocol_version: PROTOCOL_VERSION,
            device_id,
            signature: key.sign_b64(&auth::auth_message(&nonce, device_id)),
            agent_version: crate::AGENT_VERSION.to_string(),
            capabilities: vec![],
        },
    )
    .await?;
    match recv(&mut ws, HANDSHAKE_TIMEOUT)
        .await
        .map_err(session_err)?
    {
        ServerMsg::Welcome {
            organization_id, ..
        } => {
            let _ = ws.close(None).await;
            if organization_id != Some(pin.organization_id) {
                bail!(
                    "the server has this device in organization {}, not {} as given: nothing was pinned",
                    organization_id.map_or("(not said)".into(), |o| o.to_string()),
                    pin.organization_id
                );
            }
            crate::trust::store(&cfg.state_dir, &pinned)?;
            Ok(pinned)
        }
        ServerMsg::Refused { message, .. } => bail!("the server refused: {message}"),
        other => bail!("unexpected reply: {other:?}"),
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

/// How long a starting agent waits for a previous process on the same state directory to
/// exit (a service restart can overlap the old process's shutdown).
const LOCK_WAIT: Duration = Duration::from_secs(15);

pub fn lock_state_dir(state_dir: &std::path::Path) -> Result<std::fs::File> {
    lock_state_dir_within(state_dir, LOCK_WAIT)
}

/// Take an exclusive OS lock on `<state_dir>/agent.lock`. The lock is released when the
/// process exits, however it exits, so a crash never leaves a stale lock behind.
fn lock_state_dir_within(state_dir: &std::path::Path, wait: Duration) -> Result<std::fs::File> {
    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join("agent.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(std::fs::TryLockError::WouldBlock) => bail!(
                "another flyw8t agent is already running with state directory {}",
                state_dir.display()
            ),
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(e).context("locking the state directory")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_process_per_state_directory() {
        let dir = tempfile::tempdir().unwrap();
        let first = lock_state_dir_within(dir.path(), Duration::ZERO).unwrap();
        let second = lock_state_dir_within(dir.path(), Duration::from_millis(300));
        assert!(second.unwrap_err().to_string().contains("already running"));
        drop(first);
        assert!(
            lock_state_dir_within(dir.path(), Duration::ZERO).is_ok(),
            "released on drop"
        );
    }
}
