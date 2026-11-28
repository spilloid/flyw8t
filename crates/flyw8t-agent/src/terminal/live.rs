//! One background terminal per running Windows agent. The worker owns the process across sockets.

use super::windows_console::{Input, InteractiveConsole, INPUT_WINDOW};
use flyw8t_protocol::messages::BackgroundTerminalPolicy;
use flyw8t_protocol::script::WindowsExecutionAccount;
use flyw8t_protocol::terminal::{
    TerminalCommand, TerminalEndReason as End, TerminalEvent, TERMINAL_FRAME_BYTES, TERMINAL_GRACE,
    TERMINAL_LEASE,
};
use flyw8t_protocol::AgentMsg;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use uuid::Uuid;

const COMMANDS: usize = 32;
const FINISHED_SESSIONS: usize = 64;
const TICK: Duration = Duration::from_millis(50);
const POLICY_TICK: Duration = Duration::from_millis(500);
// Leave headroom for job reports and heartbeats in the gateway's 100 frames/sec budget.
const STREAM_FRAMES_PER_TICK: usize = 2;
const ACCOUNT: WindowsExecutionAccount = WindowsExecutionAccount::LocalSystem;

pub(crate) struct Runtime {
    sender: Option<SyncSender<Request>>,
    stop: Arc<AtomicU8>,
    worker: Option<JoinHandle<()>>,
}

impl Runtime {
    pub fn new(state_dir: PathBuf, device: Uuid) -> std::io::Result<Self> {
        let (sender, commands) = sync_channel(COMMANDS);
        let stop = Arc::new(AtomicU8::new(0));
        let stop_requested = stop.clone();
        let worker = thread::Builder::new()
            .name("flyw8t-terminal".into())
            .spawn(move || {
                Worker {
                    state_dir,
                    device,
                    live: None,
                    finished: VecDeque::new(),
                }
                .run(commands, &stop_requested);
            })?;
        Ok(Self {
            sender: Some(sender),
            stop,
            worker: Some(worker),
        })
    }

    pub fn submit(
        &self,
        id: Uuid,
        command: TerminalCommand,
        replies: mpsc::Sender<AgentMsg>,
    ) -> bool {
        self.sender.as_ref().is_some_and(|sender| {
            sender
                .try_send(Request {
                    id,
                    command,
                    replies,
                })
                .is_ok()
        })
    }

    pub fn stop(&self, revoked: bool) {
        self.stop
            .store(if revoked { 2 } else { 1 }, Ordering::Release);
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct Request {
    id: Uuid,
    command: TerminalCommand,
    replies: mpsc::Sender<AgentMsg>,
}

struct Endpoint {
    id: Uuid,
    replies: mpsc::Sender<AgentMsg>,
}

impl Endpoint {
    fn send(&self, id: Uuid, event: TerminalEvent) -> bool {
        self.replies
            .try_send(AgentMsg::BackgroundTerminal {
                session_id: id,
                event,
            })
            .is_ok()
    }

    fn reject(&self, id: Uuid, reason: End) {
        self.send(
            id,
            TerminalEvent::Rejected {
                attachment: self.id,
                reason,
            },
        );
    }

    fn end(&self, id: Uuid, reason: End) -> bool {
        self.send(
            id,
            TerminalEvent::Ended {
                attachment: self.id,
                reason,
            },
        )
    }
}

struct Attachment {
    endpoint: Endpoint,
    lease: Instant,
    offset: u64,
    enqueued: u64,
    sent_ack: u64,
    written: VecDeque<u64>,
    next_flush: Instant,
}

enum View {
    Attached(Attachment),
    Detached { previous: Uuid, until: Instant },
}

struct Live {
    id: Uuid,
    console: InteractiveConsole,
    view: View,
    policy_checked: Instant,
}

impl Live {
    fn detach(&mut self, now: Instant) {
        if let View::Attached(attached) = &self.view {
            self.console.set_writer(None);
            self.view = View::Detached {
                previous: attached.endpoint.id,
                until: now + TERMINAL_GRACE,
            };
        }
    }

    fn attached_to(&mut self, endpoint: &Endpoint) -> Option<&mut Attachment> {
        match &mut self.view {
            View::Attached(attached)
                if attached.endpoint.id == endpoint.id
                    && attached.endpoint.replies.same_channel(&endpoint.replies) =>
            {
                Some(attached)
            }
            _ => None,
        }
    }

    fn attach(&mut self, endpoint: Endpoint, offset: u64, now: Instant) -> bool {
        let Some(offset) = self.console.replay_start(offset) else {
            endpoint.reject(self.id, End::InvalidInput);
            return false;
        };
        let ready = TerminalEvent::Ready {
            attachment: endpoint.id,
            account: ACCOUNT,
            offset,
        };
        if !endpoint.send(self.id, ready) {
            return false;
        }
        self.console.set_writer(Some(endpoint.id));
        self.view = View::Attached(Attachment {
            endpoint,
            lease: now + TERMINAL_LEASE,
            offset,
            enqueued: 0,
            sent_ack: 0,
            written: VecDeque::new(),
            next_flush: now,
        });
        true
    }

    fn flush(&mut self) -> Result<(), End> {
        // Retain only acknowledgements for the current attachment. Input is never replayed.
        while let Ok(written) = self.console.written.try_recv() {
            let (id, sequence) = written.map_err(|_| End::Unavailable)?;
            if let View::Attached(attached) = &mut self.view {
                if attached.endpoint.id == id {
                    attached.written.push_back(sequence);
                }
            }
        }
        let View::Attached(attached) = &mut self.view else {
            return Ok(());
        };
        let now = Instant::now();
        if attached.next_flush > now {
            return Ok(());
        }
        attached.next_flush = now + TICK;
        let id = attached.endpoint.id;
        for _ in 0..STREAM_FRAMES_PER_TICK {
            if let Some(&sequence) = attached.written.front() {
                if !attached.endpoint.send(
                    self.id,
                    TerminalEvent::Ack {
                        attachment: id,
                        sequence,
                    },
                ) {
                    break;
                }
                attached.sent_ack = sequence;
                attached.written.pop_front();
                continue;
            }
            let Some((offset, data)) = self.console.read_at(attached.offset) else {
                break;
            };
            let end = offset + data.len() as u64;
            if !attached.endpoint.send(
                self.id,
                TerminalEvent::Output {
                    attachment: id,
                    offset,
                    data,
                },
            ) {
                break;
            }
            attached.offset = end;
        }
        Ok(())
    }
}

struct Finished {
    id: Uuid,
    reason: End,
    pending: Option<Endpoint>,
}

struct Worker {
    state_dir: PathBuf,
    device: Uuid,
    live: Option<Live>,
    finished: VecDeque<Finished>,
}

impl Worker {
    fn run(mut self, requests: Receiver<Request>, stopped: &AtomicU8) {
        loop {
            let stop = stopped.load(Ordering::Acquire);
            if stop > 0 {
                self.finish(
                    if stop == 2 {
                        End::AccessRevoked
                    } else {
                        End::AgentStopped
                    },
                    None,
                );
                return;
            }
            let now = Instant::now();
            if let Some(reason) = self.poll(now) {
                self.finish(reason, None);
            }
            let delay =
                if self.live.is_some() || self.finished.iter().any(|end| end.pending.is_some()) {
                    TICK
                } else {
                    Duration::from_secs(1)
                };
            match requests.recv_timeout(delay) {
                Ok(request) => {
                    if stopped.load(Ordering::Acquire) == 0 {
                        self.handle(request);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.finish(End::AgentStopped, None);
                    return;
                }
            }
        }
    }

    fn poll(&mut self, now: Instant) -> Option<End> {
        for end in &mut self.finished {
            if end.pending.as_ref().is_some_and(|pending| {
                pending.replies.is_closed() || pending.end(end.id, end.reason)
            }) {
                end.pending = None;
            }
        }
        let live = self.live.as_mut()?;
        if live.console.exited() {
            return Some(End::ProcessExited);
        }
        if now.duration_since(live.policy_checked) >= POLICY_TICK {
            live.policy_checked = now;
            if !Self::enabled(&self.state_dir, self.device) {
                return Some(End::PolicyDisabled);
            }
        }
        match &live.view {
            View::Attached(attached) if attached.endpoint.replies.is_closed() => live.detach(now),
            View::Attached(attached) if attached.lease <= now => {
                // Timer delays must not extend the grace window for a lost lease.
                live.detach(attached.lease);
            }
            View::Detached { until, .. } if *until <= now => return Some(End::Expired),
            _ => {}
        }
        live.flush().err()
    }

    fn enabled(state_dir: &std::path::Path, device: Uuid) -> bool {
        super::read_background_policy(state_dir, device) == BackgroundTerminalPolicy::Enabled
    }

    fn handle(&mut self, request: Request) {
        let now = Instant::now();
        if let Some(reason) = self.poll(now) {
            self.finish(reason, None);
        }
        let Request {
            id,
            command,
            replies,
        } = request;
        if replies.is_closed() {
            return;
        }
        let attachment = match &command {
            TerminalCommand::Open { attachment, .. }
            | TerminalCommand::Resume { attachment, .. }
            | TerminalCommand::Input { attachment, .. }
            | TerminalCommand::Renew { attachment, .. }
            | TerminalCommand::Detach { attachment }
            | TerminalCommand::Close { attachment, .. } => *attachment,
        };
        let endpoint = Endpoint {
            id: attachment,
            replies,
        };
        if id.is_nil() || attachment.is_nil() {
            endpoint.reject(id, End::InvalidInput);
            return;
        }
        if let Some(finished) = self.finished.iter().find(|end| end.id == id) {
            if matches!(
                command,
                TerminalCommand::Open { .. }
                    | TerminalCommand::Resume { .. }
                    | TerminalCommand::Close { .. }
            ) {
                endpoint.end(id, finished.reason);
            }
            return;
        }
        if let TerminalCommand::Open { account, .. } = command {
            self.open(id, endpoint, account, now);
            return;
        }
        let Some(live) = self.live.as_mut().filter(|live| live.id == id) else {
            if matches!(
                command,
                TerminalCommand::Resume { .. } | TerminalCommand::Close { .. }
            ) {
                endpoint.reject(id, End::Unavailable);
            }
            return;
        };
        match command {
            TerminalCommand::Resume {
                account, offset, ..
            } => {
                if account != ACCOUNT {
                    endpoint.reject(id, End::Unavailable);
                    return;
                }
                if !matches!(live.view, View::Detached { .. }) {
                    endpoint.reject(id, End::Busy);
                    return;
                }
                if matches!(live.view, View::Detached { previous, .. } if previous == attachment) {
                    endpoint.reject(id, End::InvalidInput);
                    return;
                }
                if !Self::enabled(&self.state_dir, self.device) {
                    self.finish(End::PolicyDisabled, Some(endpoint));
                    return;
                }
                live.attach(endpoint, offset, now);
            }
            TerminalCommand::Input { sequence, data, .. } => {
                if live.attached_to(&endpoint).is_none() {
                    return;
                }
                if !Self::enabled(&self.state_dir, self.device) {
                    self.finish(End::PolicyDisabled, None);
                    return;
                }
                let attached = live.attached_to(&endpoint).unwrap();
                if data.is_empty()
                    || data.len() > TERMINAL_FRAME_BYTES
                    || attached.enqueued.checked_add(1) != Some(sequence)
                {
                    self.finish(End::InvalidInput, None);
                    return;
                }
                if sequence - attached.sent_ack > INPUT_WINDOW as u64
                    || !live.console.write(Input {
                        attachment,
                        sequence,
                        data,
                    })
                {
                    self.finish(End::Busy, None);
                    return;
                }
                live.attached_to(&endpoint).unwrap().enqueued = sequence;
            }
            TerminalCommand::Renew { check, .. } => {
                if let Some(attached) = live.attached_to(&endpoint).filter(|_| !check.is_nil()) {
                    attached.lease = now + TERMINAL_LEASE;
                    attached
                        .endpoint
                        .send(id, TerminalEvent::LeaseRenewed { attachment, check });
                }
            }
            TerminalCommand::Detach { .. } => {
                if live.attached_to(&endpoint).is_some() {
                    live.detach(now);
                }
            }
            TerminalCommand::Close {
                reason:
                    reason @ (End::Closed
                    | End::AccessRevoked
                    | End::Expired
                    | End::InvalidInput
                    | End::Unavailable),
                ..
            } => {
                // While detached, the current authenticated socket may deliver a close
                // queued for the former attachment before the network interruption.
                if live.attached_to(&endpoint).is_some()
                    || matches!(live.view, View::Detached { previous, .. } if previous == attachment)
                {
                    self.finish(reason, Some(endpoint));
                }
            }
            _ => {}
        }
    }

    fn open(
        &mut self,
        id: Uuid,
        endpoint: Endpoint,
        account: WindowsExecutionAccount,
        now: Instant,
    ) {
        if self.live.is_some() {
            endpoint.reject(id, End::Busy);
            return;
        }
        if account != ACCOUNT {
            endpoint.reject(id, End::Unavailable);
            return;
        }
        if !Self::enabled(&self.state_dir, self.device) {
            endpoint.reject(id, End::PolicyDisabled);
            return;
        }
        let console = match InteractiveConsole::start() {
            Ok(console) => console,
            Err(error) => {
                tracing::warn!(%error, "could not start background PowerShell");
                endpoint.reject(id, End::Unavailable);
                return;
            }
        };
        let mut live = Live {
            id,
            console,
            view: View::Detached {
                previous: endpoint.id,
                until: now,
            },
            policy_checked: now,
        };
        // The shell started without a command. Recheck the endpoint policy before
        // announcing that the attachment can now write to it.
        if !Self::enabled(&self.state_dir, self.device) {
            endpoint.reject(id, End::PolicyDisabled);
        } else if live.attach(endpoint, 0, Instant::now()) {
            self.live = Some(live);
        }
    }

    fn finish(&mut self, reason: End, override_endpoint: Option<Endpoint>) {
        let Some(mut live) = self.live.take() else {
            return;
        };
        let result = live.console.shutdown();
        if reason == End::ProcessExited {
            // The normal exit may have printed output since the last poll. Do not
            // send buffered bytes after a policy or access revocation.
            let _ = live.flush();
        }
        let endpoint = override_endpoint.or(match live.view {
            View::Attached(attached) => Some(attached.endpoint),
            View::Detached { .. } => None,
        });
        if !result {
            tracing::warn!(terminal_id = %live.id, "background PowerShell cleanup unconfirmed");
            return;
        }
        let pending = endpoint
            .filter(|endpoint| !endpoint.replies.is_closed() && !endpoint.end(live.id, reason));
        self.finished.push_back(Finished {
            id: live.id,
            reason,
            pending,
        });
        if self.finished.len() > FINISHED_SESSIONS {
            self.finished.pop_front();
        }
    }
}
