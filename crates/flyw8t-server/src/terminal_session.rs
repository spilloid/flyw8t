//! The browser attachment for one live PowerShell on an enrolled Windows agent.

use crate::audit::Audit;
use crate::auth::{self, Channel, Principal};
use crate::error::{AppError, AppResult};
use crate::web::{check_csrf, constant_time_eq, ctx, html, page, windows_observation_target, Form};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use flyw8t_domain::Permission;
use flyw8t_protocol::script::WindowsExecutionAccount;
use flyw8t_protocol::terminal::{
    TerminalCommand, TerminalEndReason, TerminalEvent, CAP_BACKGROUND_TERMINAL,
    TERMINAL_FRAME_BYTES, TERMINAL_GRACE, TERMINAL_LEASE, TERMINAL_RENEWAL,
};
use flyw8t_protocol::ServerMsg;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{self, Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const ACCOUNT: WindowsExecutionAccount = WindowsExecutionAccount::LocalSystem;
const MAX_SESSIONS: usize = 32;
const QUEUE: usize = 128;
const MAX_BROWSER_MESSAGE: usize = 6 * TERMINAL_FRAME_BYTES + 256;
const START_DEADLINE: Duration = Duration::from_secs(30);
const ATTACH_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const AUTH_TIMEOUT: Duration = Duration::from_secs(4);
// The vendored terminal renderer installs its own style elements. Only this
// page permits inline styles. Scripts and connections stay same-origin.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

#[derive(Default)]
pub(crate) struct Hub(Mutex<HashMap<Uuid, Entry>>);

#[derive(Clone)]
struct Entry {
    device: Uuid,
    organization: Uuid,
    owner: Uuid,
    browser_session: Uuid,
    cookie_digest: Vec<u8>,
    socket_limit: Arc<Semaphore>,
    browser: mpsc::Sender<BrowserMessage>,
    agent: mpsc::Sender<AgentMessage>,
    overflow: CancellationToken,
}

enum BrowserMessage {
    Attach {
        attachment: Uuid,
        offset: u64,
        frames: mpsc::Sender<BrowserFrame>,
    },
    Input {
        attachment: Uuid,
        sequence: u64,
        data: String,
    },
    Close {
        attachment: Uuid,
    },
    EndRequest,
    Disconnect {
        attachment: Uuid,
    },
}

struct AgentMessage {
    connection: Uuid,
    event: TerminalEvent,
}

enum BrowserFrame {
    Terminal(TerminalEvent),
    TerminationPending,
}

impl BrowserFrame {
    fn text(&self) -> Message {
        let body = match self {
            Self::Terminal(event) => serde_json::to_string(event)
                .expect("terminal events have a fixed JSON representation"),
            Self::TerminationPending => r#"{"type":"termination_pending"}"#.into(),
        };
        Message::Text(body.into())
    }
}

impl Hub {
    pub(crate) fn reserve(
        &self,
        state: &Shared,
        actor: &Principal,
        device: Uuid,
        organization: Uuid,
        connection: Uuid,
    ) -> AppResult<Uuid> {
        let browser_session = browser_identity(actor)?;
        let cookie_digest = actor.session_token.clone().ok_or(AppError::Unauthorized)?;
        let session_id = Uuid::new_v4();
        let (browser, browser_rx) = mpsc::channel(QUEUE);
        let (agent, agent_rx) = mpsc::channel(QUEUE);
        let overflow = CancellationToken::new();
        let mut sessions = self.0.lock().unwrap();
        if sessions.values().any(|entry| entry.device == device) {
            return Err(AppError::Conflict(
                "This device already has a background terminal session.".into(),
            ));
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(AppError::RateLimited);
        }
        sessions.insert(
            session_id,
            Entry {
                device,
                organization,
                owner: actor.user_id,
                browser_session,
                cookie_digest,
                socket_limit: Arc::new(Semaphore::new(2)),
                browser,
                agent,
                overflow: overflow.clone(),
            },
        );
        drop(sessions);
        let start_before = Instant::now() + START_DEADLINE;
        let mut terminal = Terminal {
            state: state.clone(),
            actor: actor.clone(),
            device,
            organization,
            id: session_id,
            start_connection: connection,
            start_before,
            phase: Phase::Pending,
            binding: None,
            browser: None,
            output_seen: 0,
        };
        tokio::spawn(async move {
            terminal.run(browser_rx, agent_rx, overflow).await;
            terminal
                .state
                .terminal_sessions
                .0
                .lock()
                .unwrap()
                .remove(&session_id);
        });
        Ok(session_id)
    }

    fn for_browser(&self, p: &Principal, device: Uuid, id: Uuid) -> AppResult<Entry> {
        let signed_in = browser_identity(p)?;
        let cookie = p.session_token.as_deref().ok_or(AppError::Unauthorized)?;
        self.0
            .lock()
            .unwrap()
            .get(&id)
            .filter(|e| {
                e.device == device
                    && e.owner == p.user_id
                    && e.browser_session == signed_in
                    && constant_time_eq(cookie, &e.cookie_digest)
            })
            .cloned()
            .ok_or(AppError::NotFound)
    }

    pub(crate) fn tracks(&self, device: Uuid, session: Uuid, owner: Uuid) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(&session)
            .is_some_and(|entry| entry.device == device && entry.owner == owner)
    }

    pub(crate) fn agent_event(
        &self,
        device: Uuid,
        connection: Uuid,
        id: Uuid,
        event: TerminalEvent,
    ) {
        if matches!(&event, TerminalEvent::Output { data, .. } if data.len() > TERMINAL_FRAME_BYTES)
        {
            return;
        }
        if let Some(entry) = self
            .0
            .lock()
            .unwrap()
            .get(&id)
            .filter(|entry| entry.device == device)
        {
            if matches!(
                entry.agent.try_send(AgentMessage { connection, event }),
                Err(mpsc::error::TrySendError::Full(_))
            ) {
                entry.overflow.cancel();
            }
        }
    }
}

fn browser_identity(p: &Principal) -> AppResult<Uuid> {
    if p.channel != Channel::Web || p.session_token.is_none() {
        return Err(AppError::Unauthorized);
    }
    p.require(Permission::ViewDevices)?;
    p.require(Permission::RunControlSessions)?;
    p.session_id.ok_or(AppError::Unauthorized)
}

async fn live_access(
    state: &Shared,
    p: &Principal,
    device: Uuid,
    organization: Uuid,
) -> AppResult<(sqlx::Transaction<'static, sqlx::Postgres>, String)> {
    time::timeout(AUTH_TIMEOUT, async {
        browser_identity(p)?;
        let mut tx = state.db.begin().await?;
        let (current_org, name) = windows_observation_target(&mut tx, p, device).await?;
        if current_org != organization {
            return Err(AppError::NotFound);
        }
        Ok((tx, name))
    })
    .await
    .map_err(|_| AppError::Conflict("Could not verify terminal access in time.".into()))?
}

fn access_end_reason(error: AppError) -> TerminalEndReason {
    match error {
        AppError::Unauthorized | AppError::Forbidden | AppError::NotFound => {
            TerminalEndReason::AccessRevoked
        }
        _ => TerminalEndReason::Unavailable,
    }
}

pub(crate) fn url(device: Uuid, id: Uuid) -> String {
    format!("/devices/{device}/background-terminal/sessions/{id}")
}

pub(crate) async fn session_page(
    State(state): State<Shared>,
    auth::WebUser(p): auth::WebUser,
    Path((device, id)): Path<(Uuid, Uuid)>,
) -> Response {
    page(&p, async {
        let entry = state.terminal_sessions.for_browser(&p, device, id)?;
        let (tx, name) = live_access(&state, &p, device, entry.organization).await?;
        tx.commit().await?;
        let mut response = html(flyw8t_web::background_terminal_page(
            &ctx(&p, None),
            device,
            &name,
            id,
            ACCOUNT,
        ))?;
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CONTENT_SECURITY_POLICY),
        );
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        Ok(response)
    })
    .await
}

pub(crate) async fn session_ws(
    ws: WebSocketUpgrade,
    State(state): State<Shared>,
    Path((device, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Response {
    let result = async {
        if crate::origin_is_self(&state.config, &headers) != Some(true) {
            return Err(AppError::Forbidden);
        }
        let p = auth::session_principal(&state, &headers)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let entry = state.terminal_sessions.for_browser(&p, device, id)?;
        let (tx, _) = live_access(&state, &p, device, entry.organization).await?;
        tx.commit().await?;
        let socket_slot = entry
            .socket_limit
            .try_acquire_owned()
            .map_err(|_| AppError::RateLimited)?;
        Ok(ws
            .max_message_size(MAX_BROWSER_MESSAGE)
            .max_frame_size(MAX_BROWSER_MESSAGE)
            .on_upgrade(move |socket| async move {
                let _slot = socket_slot;
                browser_socket(socket, entry.browser, p.csrf).await;
            }))
    }
    .await;
    result.unwrap_or_else(AppError::into_response)
}

/// The authenticated browser can stop its process when the agent socket is
/// reconnecting. A queue receipt says only that termination is pending.
pub(crate) async fn request_end(
    State(state): State<Shared>,
    auth::WebUser(p): auth::WebUser,
    Path((device, id)): Path<(Uuid, Uuid)>,
    body: Bytes,
) -> AppResult<Response> {
    check_csrf(&p, &Form::parse(&body))?;
    let entry = state.terminal_sessions.for_browser(&p, device, id)?;
    let (tx, _) = live_access(&state, &p, device, entry.organization).await?;
    entry
        .browser
        .try_send(BrowserMessage::EndRequest)
        .map_err(|error| match error {
            mpsc::error::TrySendError::Closed(_) => AppError::NotFound,
            mpsc::error::TrySendError::Full(_) => AppError::RateLimited,
        })?;
    drop(tx);
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "state": "termination_pending" })),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum BrowserInput {
    Attach { csrf: String, offset: u64 },
    Input { sequence: u64, data: String },
    Close,
}

async fn browser_socket(socket: WebSocket, tx: mpsc::Sender<BrowserMessage>, csrf: String) {
    let (mut send, mut recv) = socket.split();
    let opening = time::timeout(ATTACH_TIMEOUT, recv.next()).await;
    let Ok(Some(Ok(Message::Text(first)))) = opening else {
        return;
    };
    let Ok(BrowserInput::Attach {
        csrf: supplied,
        offset,
    }) = serde_json::from_str(first.as_str())
    else {
        return;
    };
    if csrf.is_empty() || !constant_time_eq(supplied.as_bytes(), csrf.as_bytes()) {
        return;
    }
    let attachment = Uuid::new_v4();
    let (frames, mut events) = mpsc::channel(QUEUE);
    if !matches!(
        time::timeout(
            IO_TIMEOUT,
            tx.send(BrowserMessage::Attach {
                attachment,
                offset,
                frames
            })
        )
        .await,
        Ok(Ok(()))
    ) {
        return;
    }
    // Browsers reply to WS Ping automatically. A quiet disconnected browser
    // must not keep the agent's maintenance lease renewed indefinitely.
    let mut last_pong = Instant::now();
    let mut keepalive = time::interval_at(last_pong + TERMINAL_RENEWAL, TERMINAL_RENEWAL);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let ping = axum::body::Bytes::copy_from_slice(attachment.as_bytes());
    loop {
        tokio::select! {
            _ = keepalive.tick() => {
                if last_pong.elapsed() >= TERMINAL_LEASE
                    || !matches!(
                        time::timeout(IO_TIMEOUT, send.send(Message::Ping(ping.clone()))).await,
                        Ok(Ok(()))
                    )
                {
                    break;
                }
            }
            frame = events.recv() => {
                let Some(frame) = frame else { break };
                if !matches!(time::timeout(IO_TIMEOUT, send.send(frame.text())).await, Ok(Ok(())))
                {
                    break;
                }
            }
            frame = recv.next() => {
                let message = match frame {
                    Some(Ok(Message::Text(frame))) => match serde_json::from_str(frame.as_str()) {
                        Ok(BrowserInput::Input { sequence, data }) if !data.is_empty() && data.len() <= TERMINAL_FRAME_BYTES => {
                            BrowserMessage::Input { attachment, sequence, data }
                        }
                        Ok(BrowserInput::Close) => BrowserMessage::Close { attachment },
                        _ => break,
                    },
                    Some(Ok(Message::Pong(value))) if value == ping => {
                        last_pong = Instant::now();
                        continue;
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    _ => break,
                };
                if !matches!(time::timeout(IO_TIMEOUT, tx.send(message)).await, Ok(Ok(())))
                {
                    break;
                }
            }
        }
    }
    drop(events);
    let _ = tx.try_send(BrowserMessage::Disconnect { attachment });
    let _ = time::timeout(IO_TIMEOUT, send.send(Message::Close(None))).await;
}

#[derive(Clone, Copy)]
struct Binding {
    attachment: Uuid,
    connection: Uuid,
}

struct BrowserAttachment {
    id: Uuid,
    frames: mpsc::Sender<BrowserFrame>,
    ready: bool,
    resume: Option<Resume>,
    requested_offset: u64,
    next_output: u64,
    next_input: u64,
    last_ack: u64,
    ready_before: Instant,
}

#[derive(Clone, Copy)]
struct Resume {
    previous: Binding,
    until: Instant,
}

enum Phase {
    Pending,
    Attached,
    Detached {
        until: Instant,
    },
    Ending {
        reason: TerminalEndReason,
        until: Instant,
        notified_connection: Option<Uuid>,
    },
    Done,
}

struct Terminal {
    state: Shared,
    actor: Principal,
    device: Uuid,
    organization: Uuid,
    id: Uuid,
    start_connection: Uuid,
    start_before: Instant,
    phase: Phase,
    binding: Option<Binding>,
    browser: Option<BrowserAttachment>,
    output_seen: u64,
}

impl Terminal {
    async fn run(
        &mut self,
        mut browser: mpsc::Receiver<BrowserMessage>,
        mut agent: mpsc::Receiver<AgentMessage>,
        overflow: CancellationToken,
    ) {
        let mut tick = time::interval(TERMINAL_RENEWAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut overflowed = false;
        while !matches!(self.phase, Phase::Done) {
            tokio::select! {
                () = overflow.cancelled(), if !overflowed => {
                    overflowed = true;
                    self.end(TerminalEndReason::Unavailable).await;
                }
                Some(message) = browser.recv() => self.on_browser(message).await,
                Some(message) = agent.recv() => self.on_agent(message).await,
                _ = tick.tick() => self.tick().await,
            }
        }
    }

    fn conn_supports_terminal(&self, conn: Uuid) -> bool {
        self.state
            .registry
            .has_capability(self.device, conn, CAP_BACKGROUND_TERMINAL)
    }

    fn send_agent(&self, connection: Uuid, command: TerminalCommand) -> bool {
        self.state.registry.send_on(
            self.device,
            connection,
            ServerMsg::BackgroundTerminal {
                session_id: self.id,
                command,
            },
        )
    }

    fn audit_event(&self, action: &'static str, reason: Option<TerminalEndReason>) -> Audit {
        Audit::user(&self.actor, action)
            .org(self.organization)
            .target("device", self.device)
            .detail(json!({
                "session_id": self.id,
                "browser_session_id": self.actor.session_id,
                "agent_account": ACCOUNT,
                "reason": reason,
            }))
    }

    async fn audit(&self, action: &'static str, reason: Option<TerminalEndReason>, ok: bool) {
        let event = self.audit_event(action, reason);
        let event = if ok { event } else { event.failed() };
        if !matches!(
            time::timeout(AUTH_TIMEOUT, event.record(&self.state.db)).await,
            Ok(Ok(()))
        ) {
            tracing::error!(session = %self.id, "could not record terminal lifecycle");
        }
    }

    async fn on_browser(&mut self, message: BrowserMessage) {
        match message {
            BrowserMessage::Attach {
                attachment,
                offset,
                frames,
            } => {
                self.attach(attachment, offset, frames).await;
            }
            BrowserMessage::Input {
                attachment,
                sequence,
                data,
            } => {
                self.input(attachment, sequence, data).await;
            }
            BrowserMessage::Close { attachment } if self.is_writer(attachment) => {
                self.end(TerminalEndReason::Closed).await;
            }
            BrowserMessage::EndRequest => self.end(TerminalEndReason::Closed).await,
            BrowserMessage::Disconnect { attachment } if self.is_writer(attachment) => {
                if matches!(self.phase, Phase::Attached) {
                    self.detach().await;
                } else {
                    self.browser = None;
                }
            }
            _ => {}
        }
    }

    fn is_writer(&self, id: Uuid) -> bool {
        self.browser
            .as_ref()
            .is_some_and(|browser| browser.id == id)
    }

    async fn attach(&mut self, attachment: Uuid, offset: u64, frames: mpsc::Sender<BrowserFrame>) {
        if offset > self.output_seen || frames.is_closed() {
            return;
        }
        if self
            .browser
            .as_ref()
            .is_some_and(|browser| browser.frames.is_closed())
            && matches!(self.phase, Phase::Attached)
        {
            self.detach().await;
        }
        let now = Instant::now();
        let resume = match self.phase {
            Phase::Pending if now < self.start_before && offset == 0 => None,
            Phase::Detached { until } if now < until => {
                let Some(previous) = self.binding else { return };
                Some(Resume { previous, until })
            }
            _ => return,
        };
        let Some(connection) = self.state.registry.current_conn(self.device) else {
            return;
        };
        if (resume.is_none() && connection != self.start_connection)
            || !self.conn_supports_terminal(connection)
        {
            return;
        }
        let (mut tx, _) =
            match live_access(&self.state, &self.actor, self.device, self.organization).await {
                Ok(access) => access,
                Err(error) => {
                    let reason = access_end_reason(error);
                    let _ = frames.try_send(BrowserFrame::Terminal(TerminalEvent::Rejected {
                        attachment,
                        reason,
                    }));
                    self.end(reason).await;
                    return;
                }
            };
        if Instant::now() >= resume.map_or(self.start_before, |r| r.until) {
            return;
        }
        let command = if resume.is_some() {
            TerminalCommand::Resume {
                attachment,
                account: ACCOUNT,
                offset,
            }
        } else {
            TerminalCommand::Open {
                attachment,
                account: ACCOUNT,
            }
        };
        if !matches!(
            time::timeout(
                AUTH_TIMEOUT,
                self.audit_event("device.background_terminal.attachment", None)
                    .record(&mut *tx)
            )
            .await,
            Ok(Ok(()))
        ) || Instant::now() >= resume.map_or(self.start_before, |r| r.until)
            || frames.is_closed()
        {
            return;
        }
        if !self.send_agent(connection, command) {
            return;
        }
        // Leave the request scoped under its current actor/device locks through the queue write.
        // No active input or success is possible until a matching, authorized agent Ready.
        let audit_committed = matches!(time::timeout(AUTH_TIMEOUT, tx.commit()).await, Ok(Ok(())));
        self.binding = Some(Binding {
            attachment,
            connection,
        });
        self.browser = Some(BrowserAttachment {
            id: attachment,
            frames,
            ready: false,
            resume,
            requested_offset: offset,
            next_output: offset,
            next_input: 1,
            last_ack: 0,
            ready_before: Instant::now() + ATTACH_TIMEOUT,
        });
        self.phase = Phase::Attached;
        if !audit_committed {
            self.end(TerminalEndReason::Unavailable).await;
        }
    }

    async fn input(&mut self, attachment: Uuid, sequence: u64, data: String) {
        if !matches!(self.phase, Phase::Attached) || !self.is_writer(attachment) {
            return;
        }
        let Some(browser) = self.browser.as_ref() else {
            return;
        };
        if !browser.ready {
            return;
        }
        if browser.frames.is_closed() {
            self.detach().await;
            return;
        }
        if sequence != browser.next_input || sequence == u64::MAX {
            self.end(TerminalEndReason::InvalidInput).await;
            return;
        }
        let Some(binding) = self.binding else { return };
        let (tx, _) =
            match live_access(&self.state, &self.actor, self.device, self.organization).await {
                Ok(access) => access,
                Err(error) => {
                    self.end(access_end_reason(error)).await;
                    return;
                }
            };
        let sent = self
            .browser
            .as_ref()
            .is_some_and(|browser| !browser.frames.is_closed())
            && self.send_agent(
                binding.connection,
                TerminalCommand::Input {
                    attachment,
                    sequence,
                    data,
                },
            );
        drop(tx);
        if sent {
            if let Some(browser) = &mut self.browser {
                browser.next_input += 1;
            }
        } else {
            self.detach().await;
        }
    }

    async fn detach(&mut self) {
        let resume =
            self.browser
                .take()
                .and_then(|browser| if browser.ready { None } else { browser.resume });
        let Some(binding) = self.binding else { return };
        self.send_agent(
            binding.connection,
            TerminalCommand::Detach {
                attachment: binding.attachment,
            },
        );
        self.phase = Phase::Detached {
            until: resume.map_or_else(|| Instant::now() + TERMINAL_GRACE, |r| r.until),
        };
        self.audit("device.background_terminal.detached", None, true)
            .await;
    }

    async fn end(&mut self, reason: TerminalEndReason) {
        if matches!(self.phase, Phase::Ending { .. } | Phase::Done) {
            return;
        }
        if self.binding.is_none() {
            self.phase = Phase::Done;
            return;
        }
        let until = match self.phase {
            Phase::Detached { until } => until + TERMINAL_LEASE,
            _ => Instant::now() + TERMINAL_LEASE + TERMINAL_GRACE,
        };
        self.phase = Phase::Ending {
            reason,
            until,
            notified_connection: None,
        };
        self.try_close();
        if let Some(browser) = &self.browser {
            let _ = browser.frames.try_send(BrowserFrame::TerminationPending);
        }
        self.audit(
            "device.background_terminal.end_requested",
            Some(reason),
            true,
        )
        .await;
    }

    fn try_close(&mut self) {
        let Phase::Ending {
            reason,
            notified_connection,
            ..
        } = self.phase
        else {
            return;
        };
        let Some(binding) = self.binding else { return };
        let Some(current) = self.state.registry.current_conn(self.device) else {
            return;
        };
        if notified_connection != Some(current)
            && self.conn_supports_terminal(current)
            && self.send_agent(
                current,
                TerminalCommand::Close {
                    attachment: binding.attachment,
                    reason,
                },
            )
        {
            if let Phase::Ending {
                notified_connection,
                ..
            } = &mut self.phase
            {
                *notified_connection = Some(current);
            }
        }
    }

    async fn tick(&mut self) {
        let now = Instant::now();
        match self.phase {
            Phase::Pending if now >= self.start_before => self.phase = Phase::Done,
            Phase::Pending | Phase::Done => {}
            Phase::Ending { reason, until, .. } => {
                if now >= until {
                    self.audit(
                        "device.background_terminal.end_unconfirmed",
                        Some(reason),
                        false,
                    )
                    .await;
                    self.phase = Phase::Done;
                } else {
                    self.try_close();
                }
            }
            Phase::Detached { until } => {
                if now >= until {
                    self.end(TerminalEndReason::Expired).await;
                } else if let Err(error) =
                    live_access(&self.state, &self.actor, self.device, self.organization).await
                {
                    self.end(access_end_reason(error)).await;
                }
            }
            Phase::Attached => {
                let Some(browser) = &self.browser else { return };
                if !browser.ready && now >= browser.ready_before {
                    self.end(TerminalEndReason::Unavailable).await;
                    return;
                }
                let Some(binding) = self.binding else { return };
                if browser.frames.is_closed()
                    || self.state.registry.current_conn(self.device) != Some(binding.connection)
                {
                    self.detach().await;
                    return;
                }
                let (tx, _) =
                    match live_access(&self.state, &self.actor, self.device, self.organization)
                        .await
                    {
                        Ok(access) => access,
                        Err(error) => {
                            self.end(access_end_reason(error)).await;
                            return;
                        }
                    };
                let sent = self.send_agent(
                    binding.connection,
                    TerminalCommand::Renew {
                        attachment: binding.attachment,
                    },
                );
                drop(tx);
                if !sent {
                    self.detach().await;
                }
            }
        }
    }

    async fn on_agent(&mut self, message: AgentMessage) {
        let Some(binding) = self.binding else { return };
        let attachment = match &message.event {
            TerminalEvent::Ready { attachment, .. }
            | TerminalEvent::Output { attachment, .. }
            | TerminalEvent::Ack { attachment, .. }
            | TerminalEvent::Ended { attachment, .. }
            | TerminalEvent::Rejected { attachment, .. } => *attachment,
        };
        if attachment != binding.attachment
            || self.state.registry.current_conn(self.device) != Some(message.connection)
        {
            return;
        }
        if let TerminalEvent::Ended { reason, .. } = &message.event {
            // A replacement connection can confirm the cleanup of a detached process.
            if matches!(self.phase, Phase::Detached { .. } | Phase::Ending { .. })
                || message.connection == binding.connection
            {
                if let Some(browser) = &self.browser {
                    let _ = browser
                        .frames
                        .try_send(BrowserFrame::Terminal(message.event.clone()));
                }
                self.audit("device.background_terminal.ended", Some(*reason), true)
                    .await;
                self.phase = Phase::Done;
            }
            return;
        }
        if !matches!(self.phase, Phase::Attached) || message.connection != binding.connection {
            return;
        }
        let Some(browser) = &self.browser else { return };
        match &message.event {
            TerminalEvent::Ready {
                account, offset, ..
            } if !browser.ready => {
                if *account != ACCOUNT || *offset < browser.requested_offset {
                    self.end(TerminalEndReason::Unavailable).await;
                    return;
                }
                let resumed = browser.resume.is_some();
                let (mut tx, _) =
                    match live_access(&self.state, &self.actor, self.device, self.organization)
                        .await
                    {
                        Ok(access) => access,
                        Err(error) => {
                            self.end(access_end_reason(error)).await;
                            return;
                        }
                    };
                let started = self.audit_event(
                    if resumed {
                        "device.background_terminal.reattached"
                    } else {
                        "device.background_terminal.started"
                    },
                    None,
                );
                let persisted = time::timeout(AUTH_TIMEOUT, async {
                    started.record(&mut *tx).await?;
                    tx.commit().await
                })
                .await;
                if !matches!(persisted, Ok(Ok(()))) {
                    self.end(TerminalEndReason::Unavailable).await;
                    return;
                }
                if let Some(browser) = &mut self.browser {
                    browser.ready = true;
                    browser.next_output = *offset;
                }
                self.output_seen = self.output_seen.max(*offset);
            }
            TerminalEvent::Output { offset, data, .. }
                if browser.ready
                    && *offset >= browser.next_output
                    && !data.is_empty()
                    && data.len() <= TERMINAL_FRAME_BYTES =>
            {
                let Some(next) = offset.checked_add(data.len() as u64) else {
                    return;
                };
                if let Some(browser) = &mut self.browser {
                    browser.next_output = next;
                }
                self.output_seen = self.output_seen.max(next);
            }
            TerminalEvent::Ack { sequence, .. }
                if browser.ready
                    && *sequence == browser.last_ack + 1
                    && *sequence < browser.next_input =>
            {
                if let Some(browser) = &mut self.browser {
                    browser.last_ack = *sequence;
                }
            }
            TerminalEvent::Rejected { reason, .. } => {
                let terminal_reason = *reason;
                // A new socket may reach the old console before the detached
                // notification or the agent's lease has taken effect.
                if terminal_reason == TerminalEndReason::Busy && !browser.ready {
                    if let Some(resume) = browser.resume {
                        self.browser = None;
                        self.binding = Some(resume.previous);
                        self.phase = Phase::Detached {
                            until: resume.until,
                        };
                        return;
                    }
                }
                let _ = browser
                    .frames
                    .try_send(BrowserFrame::Terminal(message.event));
                self.audit(
                    "device.background_terminal.rejected",
                    Some(terminal_reason),
                    false,
                )
                .await;
                self.phase = Phase::Done;
                return;
            }
            _ => return,
        }
        if let Some(browser) = &self.browser {
            if browser
                .frames
                .try_send(BrowserFrame::Terminal(message.event))
                .is_err()
            {
                self.detach().await;
            }
        }
    }
}
