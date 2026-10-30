//! Attended support (Phase B): pairing, consent, and WebRTC signaling between a technician's
//! browser and a participant's browser. See `docs/attended-support.md`.
//!
//! The server never sees media. It authenticates both sides, enforces the session state
//! machine, and relays opaque signaling messages between exactly two sockets, and only after
//! the participant has consented. Only the technician who created a session can attach to it.

use crate::audit::Audit;
use crate::auth::{self, Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::web::{check_csrf, error_response, Form};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use flyw8t_domain::support::{Capability, SupportState};
use flyw8t_domain::Permission;
use flyw8t_web::model::{SupportConsentView, SupportSessionView};
use futures_util::{SinkExt, StreamExt};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgConnection;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_SIGNAL_BYTES: usize = 64 * 1024;
const PEER_BUFFER: usize = 64;
/// Concurrent live sessions per technician.
const MAX_LIVE_PER_TECHNICIAN: i64 = 5;
const AUTHORIZING_TIMEOUT_SECS: f64 = 5.0 * 60.0;
const CONNECTING_TIMEOUT_SECS: f64 = 60.0;
const SESSION_CAP_SECS: f64 = 4.0 * 60.0 * 60.0;
/// Messages a socket may send: a sustained rate and a burst (an ICE exchange is a few dozen).
const MESSAGES_PER_SEC: f64 = 20.0;
const MESSAGE_BURST: f64 = 60.0;
/// Wrong codes from everyone together before code entry pauses (links keep working).
const GLOBAL_CODE_FAILURES: u32 = 300;
const CODE_FAILURE_WINDOW: Duration = Duration::from_secs(600);
const GLOBAL_CODE_KEY: &str = "support-code-global";

/// CSP for the support pages: the console's policy plus same-origin script and WebSocket.
pub const SUPPORT_CSP: &str =
    "default-src 'none'; script-src 'self'; connect-src 'self'; media-src 'self' blob:; \
     style-src 'self'; img-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Technician,
    /// The person being helped, in their browser: consent, status and End.
    Participant,
    /// The native helper on the participant's machine (control sessions, ADR-0012). In a
    /// control session it, not the browser, is the technician's media peer.
    Helper,
}

impl Side {
    fn as_str(self) -> &'static str {
        match self {
            Side::Technician => "technician",
            Side::Participant => "participant",
            Side::Helper => "helper",
        }
    }
}

/// Who caused a change, for the session's event log and the audit log.
#[derive(Debug, Clone)]
pub enum Who {
    System,
    User(Box<Principal>),
    Participant { ip: String },
    Helper { ip: String },
}

impl Who {
    fn actor(&self) -> String {
        match self {
            Who::System => "system".into(),
            Who::User(p) => format!("user:{}", p.email),
            Who::Participant { .. } => "participant".into(),
            Who::Helper { .. } => "helper".into(),
        }
    }

    fn audit(&self, action: &'static str) -> Audit {
        match self {
            Who::System => Audit::system(action),
            Who::User(p) => Audit::user(p, action),
            Who::Participant { ip } => {
                Audit::anonymous("support", "participant", action).ip(ip.clone())
            }
            Who::Helper { ip } => Audit::anonymous("support", "helper", action).ip(ip.clone()),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Wire format (browser or helper <-> server)

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum In {
    Approve,
    Decline,
    Signal { data: Value },
    Media { state: String },
    End,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Out {
    State {
        state: &'static str,
        label: &'static str,
        peer_present: bool,
    },
    Signal {
        data: Value,
    },
    /// To the participant's browser in a control session, after its Allow: where to get the
    /// helper. The link carries the one-time launch token (ADR-0012 section 2).
    Helper {
        download: String,
        expires_in_secs: u64,
    },
    Ended {
        state: &'static str,
        label: &'static str,
    },
    Error {
        message: String,
    },
}

// ---------------------------------------------------------------------------------------
// Live sockets

struct Peer {
    conn_id: Uuid,
    tx: mpsc::Sender<Out>,
    close: CancellationToken,
    /// The final notice, set before `close` is cancelled. Kept out of `tx` so a full queue
    /// can never drop it, and so nothing queued behind it is sent after the session ended.
    last: Arc<Mutex<Option<Out>>>,
    /// The signed-in user behind a technician socket, and a signal to re-check their session
    /// now (after a sign-out or revocation) rather than at the next periodic check.
    user: Option<Uuid>,
    recheck: Arc<tokio::sync::Notify>,
}

#[derive(Default)]
struct Peers {
    technician: Option<Peer>,
    participant: Option<Peer>,
    helper: Option<Peer>,
    /// A control session: the helper is the technician's media peer, and the participant's
    /// browser carries no signaling at all.
    control: bool,
    /// Signaling flows only while this is set: opened after consent commits, never reopened
    /// once `sealed`.
    relay_open: bool,
    /// Set before an ending commits, so no signal slips through between the commit and the
    /// sockets closing.
    sealed: bool,
    /// Each end's report that media is flowing: the technician, and its media peer.
    media: [bool; 2],
}

impl Peers {
    fn side(&mut self, side: Side) -> &mut Option<Peer> {
        match side {
            Side::Technician => &mut self.technician,
            Side::Participant => &mut self.participant,
            Side::Helper => &mut self.helper,
        }
    }

    /// The technician's media peer: the helper in a control session, else the browser.
    fn media_peer(&self) -> Side {
        if self.control {
            Side::Helper
        } else {
            Side::Participant
        }
    }

    /// Where `from`'s signaling goes, if it may send any.
    fn relay_target(&self, from: Side) -> Option<Side> {
        match from {
            Side::Technician => Some(self.media_peer()),
            s if s == self.media_peer() => Some(Side::Technician),
            _ => None,
        }
    }

    fn all(self) -> impl Iterator<Item = Peer> {
        [self.technician, self.participant, self.helper]
            .into_iter()
            .flatten()
    }
}

enum Relay {
    Sent,
    NotAllowed,
    NoPeer,
}

#[derive(Default)]
pub struct SupportHub {
    sessions: Mutex<HashMap<Uuid, Peers>>,
}

impl SupportHub {
    /// Attach a socket; returns whether it replaced one already attached for that side.
    fn attach(&self, session: Uuid, side: Side, control: bool, peer: Peer) -> bool {
        let mut s = self.sessions.lock().unwrap();
        let peers = s.entry(session).or_default();
        // A session's capabilities never change; no socket can turn control off for it.
        peers.control |= control;
        match peers.side(side).replace(peer) {
            Some(old) => {
                old.close.cancel();
                true
            }
            None => false,
        }
    }

    fn detach(&self, session: Uuid, side: Side, conn_id: Uuid) {
        let mut s = self.sessions.lock().unwrap();
        if let Some(peers) = s.get_mut(&session) {
            if peers
                .side(side)
                .as_ref()
                .is_some_and(|p| p.conn_id == conn_id)
            {
                *peers.side(side) = None;
            }
            if peers.technician.is_none() && peers.participant.is_none() && peers.helper.is_none() {
                s.remove(&session);
            }
        }
    }

    fn present(&self, session: Uuid, side: Side) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get_mut(&session)
            .is_some_and(|p| p.side(side).is_some())
    }

    fn send(&self, session: Uuid, side: Side, msg: Out) -> bool {
        let tx = self
            .sessions
            .lock()
            .unwrap()
            .get_mut(&session)
            .and_then(|p| p.side(side).as_ref().map(|p| p.tx.clone()));
        tx.is_some_and(|tx| tx.try_send(msg).is_ok())
    }

    /// Relay signaling from `from` to its peer, checked and sent under one lock so it cannot
    /// race an ending. In a control session the browser has no peer: it never relays.
    fn relay(&self, session: Uuid, from: Side, data: Value) -> Relay {
        let mut s = self.sessions.lock().unwrap();
        let Some(peers) = s.get_mut(&session) else {
            return Relay::NotAllowed;
        };
        let Some(to) = peers.relay_target(from) else {
            return Relay::NotAllowed;
        };
        if !peers.relay_open || peers.sealed {
            return Relay::NotAllowed;
        }
        match peers.side(to) {
            Some(p) if p.tx.try_send(Out::Signal { data }).is_ok() => Relay::Sent,
            _ => Relay::NoPeer,
        }
    }

    /// Ask every technician socket of `user` to re-check its sign-in session now.
    pub fn recheck_user(&self, user: Uuid) {
        for peers in self.sessions.lock().unwrap().values() {
            if let Some(p) = &peers.technician {
                if p.user == Some(user) {
                    p.recheck.notify_one();
                }
            }
        }
    }

    fn open_relay(&self, session: Uuid) {
        if let Some(p) = self.sessions.lock().unwrap().get_mut(&session) {
            p.relay_open = !p.sealed;
        }
    }

    fn seal(&self, session: Uuid) {
        if let Some(p) = self.sessions.lock().unwrap().get_mut(&session) {
            p.sealed = true;
            p.relay_open = false;
        }
    }

    /// Record that `side` sees media flowing; `true` once the technician and its media peer
    /// have both said so. Anyone else's report counts for nothing.
    fn media_connected(&self, session: Uuid, side: Side) -> bool {
        let mut s = self.sessions.lock().unwrap();
        let Some(p) = s.get_mut(&session) else {
            return false;
        };
        let slot = match side {
            Side::Technician => 0,
            s if s == p.media_peer() => 1,
            _ => return false,
        };
        p.media[slot] = true;
        p.media == [true, true]
    }

    /// Tell every side the current state; on a terminal state, close every socket with a
    /// final notice that cannot be lost to a full queue.
    fn publish(&self, session: Uuid, state: SupportState) {
        if state.is_terminal() {
            let peers = self.sessions.lock().unwrap().remove(&session);
            for p in peers.into_iter().flat_map(Peers::all) {
                *p.last.lock().unwrap() = Some(Out::Ended {
                    state: state.as_str(),
                    label: state.label(),
                });
                p.close.cancel();
            }
            return;
        }
        let (media_peer, control) = {
            let s = self.sessions.lock().unwrap();
            s.get(&session)
                .map_or((Side::Participant, false), |p| (p.media_peer(), p.control))
        };
        for side in [Side::Technician, Side::Participant, Side::Helper] {
            if side == Side::Helper && !control {
                continue;
            }
            // The technician wants to know whether its media peer is there; the others,
            // whether the technician is.
            let other = if side == Side::Technician {
                media_peer
            } else {
                Side::Technician
            };
            let msg = Out::State {
                state: state.as_str(),
                label: state.label(),
                peer_present: self.present(session, other),
            };
            self.send(session, side, msg);
        }
    }
}

// ---------------------------------------------------------------------------------------
// State changes

async fn lock_state(
    tx: &mut PgConnection,
    id: Uuid,
) -> sqlx::Result<Option<(SupportState, Option<Uuid>)>> {
    let row: Option<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT state, organization_id FROM support_sessions WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(tx)
    .await?;
    Ok(row.and_then(|(s, org)| SupportState::parse(&s).map(|s| (s, org))))
}

async fn apply(
    tx: &mut PgConnection,
    id: Uuid,
    from: SupportState,
    to: SupportState,
    actor: &str,
    kind: &str,
    reason: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        from.can_transition_to(to),
        "illegal support transition {from:?} -> {to:?}"
    );
    sqlx::query(
        "UPDATE support_sessions SET
            state = $2,
            consented_at = CASE WHEN $2 = 'connecting' THEN now() ELSE consented_at END,
            connected_at = CASE WHEN $2 = 'connected' THEN now() ELSE connected_at END,
            ended_at   = CASE WHEN $5 THEN now() ELSE ended_at END,
            ended_by   = CASE WHEN $5 THEN $3 ELSE ended_by END,
            end_reason = CASE WHEN $5 THEN $4 ELSE end_reason END,
            code_hash        = CASE WHEN $5 THEN NULL ELSE code_hash END,
            invite_hash      = CASE WHEN $5 THEN NULL ELSE invite_hash END,
            participant_hash = CASE WHEN $5 THEN NULL ELSE participant_hash END
         WHERE id = $1 AND state = $6",
    )
    .bind(id)
    .bind(to.as_str())
    .bind(actor)
    .bind(reason)
    .bind(to.is_terminal())
    .bind(from.as_str())
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO support_events (session_id, kind, from_state, to_state, actor, detail) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(id)
        .bind(kind)
        .bind(from.as_str())
        .bind(to.as_str())
        .bind(actor)
        .bind(json!({ "reason": reason }))
        .execute(tx)
        .await?;
    Ok(())
}

/// Move a session from one of `from` to `to` (via `disconnecting` when ending a connected
/// session). Returns the new state, or `None` if the session was not in an accepted state.
pub async fn change(
    state: &Shared,
    id: Uuid,
    from: &[SupportState],
    to: SupportState,
    who: &Who,
    kind: &str,
    reason: &str,
) -> anyhow::Result<Option<SupportState>> {
    change_with(
        state,
        id,
        |current| from.contains(&current).then_some(to),
        who,
        kind,
        reason,
    )
    .await
}

/// Like `change`, with the target chosen from the state read under the row lock, so the
/// choice cannot go stale between reading the state and applying the transition.
async fn change_with(
    state: &Shared,
    id: Uuid,
    decide: impl FnOnce(SupportState) -> Option<SupportState>,
    who: &Who,
    kind: &str,
    reason: &str,
) -> anyhow::Result<Option<SupportState>> {
    let actor = who.actor();
    let mut tx = state.db.begin().await?;
    let Some((current, org)) = lock_state(&mut tx, id).await? else {
        return Ok(None);
    };
    let Some(to) = decide(current) else {
        tx.rollback().await?;
        return Ok(None);
    };
    if to == SupportState::Closed
        && matches!(current, SupportState::Connecting | SupportState::Connected)
    {
        apply(
            &mut tx,
            id,
            current,
            SupportState::Disconnecting,
            &actor,
            kind,
            reason,
        )
        .await?;
        apply(
            &mut tx,
            id,
            SupportState::Disconnecting,
            SupportState::Closed,
            &actor,
            kind,
            reason,
        )
        .await?;
    } else {
        apply(&mut tx, id, current, to, &actor, kind, reason).await?;
    }
    // The grants that start something (the helper's consent to control, and media actually
    // flowing) belong in the central audit log, not only in the session's own events.
    let started = match kind {
        "control_consented" => Some("support.control.helper_consent"),
        "media_connected" => Some("support.media_connected"),
        _ => None,
    };
    if let Some(action) = started {
        let mut audit = who
            .audit(action)
            .target("support_session", id)
            .detail(json!({ "state": to.as_str(), "reason": reason }));
        if let Some(org) = org {
            audit = audit.org(org);
        }
        audit.record(&mut *tx).await?;
    }
    if to.is_terminal() {
        let mut audit = who
            .audit("support.end")
            .target("support_session", id)
            .detail(json!({ "state": to.as_str(), "reason": reason }));
        if let Some(org) = org {
            audit = audit.org(org);
        }
        audit.record(&mut *tx).await?;
        // Fail closed: if the commit below fails, signaling stays stopped and the sweeper
        // ends the session.
        state.support.seal(id);
    }
    tx.commit().await?;
    if to == SupportState::Connecting {
        state.support.open_relay(id);
    }
    state.support.publish(id, to);
    Ok(Some(to))
}

/// End a session from whichever live state it is in (decided under the row lock), as `side`.
async fn end(state: &Shared, id: Uuid, side: Side, who: &Who, reason: &str) -> anyhow::Result<()> {
    use SupportState::*;
    let decide = |current| match (side, current) {
        (_, Connecting | Connected) => Some(Closed),
        (Side::Technician, Created | Waiting | Authorizing | AwaitingHelper) => Some(Revoked),
        (Side::Participant | Side::Helper, Authorizing | AwaitingHelper) => Some(Rejected),
        _ => None,
    };
    change_with(state, id, decide, who, "ended", reason).await?;
    Ok(())
}

/// End every live session a technician created: used when their sign-in is revoked, since
/// their signaling sockets authenticated only at the handshake.
pub async fn end_all_created_by(
    state: &Shared,
    user: Uuid,
    who: &Who,
    reason: &str,
) -> anyhow::Result<()> {
    let ids: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM support_sessions WHERE created_by = $1
            AND state IN ('created', 'waiting', 'authorizing', 'awaiting_helper', 'connecting', 'connected')",
    )
    .bind(user)
    .fetch_all(&state.db)
    .await?;
    for (id,) in ids {
        end(state, id, Side::Technician, who, reason).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Creation and binding

fn nine_digit_code() -> String {
    let mut b = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("system RNG");
    // Rejection-free reduction: u64 into 10^9 has a negligible (< 2^-34) modulo bias.
    format!("{:09}", u64::from_le_bytes(b) % 1_000_000_000)
}

/// Normalize what a person types: digits only.
fn normalize_code(raw: &str) -> String {
    raw.chars().filter(char::is_ascii_digit).collect()
}

/// The stored form of a 9-digit code. Argon2id (not a fast hash) because a billion codes
/// can be enumerated quickly: a database reader should not be able to recover live codes.
/// The salt is fixed so the digest can be looked up; codes are random and short-lived, so
/// per-row salts would add nothing but a scan.
async fn code_digest(code: String) -> anyhow::Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let mut out = vec![0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(code.as_bytes(), b"flyw8t-support-code-v1", &mut out)
            .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
        Ok(out)
    })
    .await?
}

/// The stored form of a link token (256 random bits; a fast hash is enough).
fn link_digest(token: &str) -> Vec<u8> {
    auth::digest(token)
}

pub struct Created {
    pub id: Uuid,
    pub code: String,
    pub invite: String,
}

pub async fn create(
    state: &Shared,
    p: &Principal,
    organization: Uuid,
    control: bool,
    note: Option<String>,
) -> AppResult<Created> {
    p.require(Permission::RunSupportSessions)?;
    if control {
        p.require(Permission::RunControlSessions)?;
    }
    let capabilities: Vec<&str> = if control {
        vec!["view_screen", "control_input"]
    } else {
        vec!["view_screen"]
    };
    if !p.can_see_org(organization) {
        return Err(AppError::NotFound);
    }
    let code = nine_digit_code();
    let code_hash = code_digest(code.clone()).await?;
    let invite = auth::random_secret(32);
    let mut tx = state.db.begin().await?;
    // One technician's creations are serialized, so the cap below holds under concurrency.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("support-create:{}", p.user_id))
        .execute(&mut *tx)
        .await?;
    let (live,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM support_sessions WHERE created_by = $1
            AND state IN ('created', 'waiting', 'authorizing', 'awaiting_helper', 'connecting', 'connected', 'disconnecting')",
    )
    .bind(p.user_id)
    .fetch_one(&mut *tx)
    .await?;
    if live >= MAX_LIVE_PER_TECHNICIAN {
        return Err(AppError::Conflict(format!(
            "You already have {live} open support sessions. End one first."
        )));
    }
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO support_sessions (created_by, organization_id, capabilities, note, state, code_hash, invite_hash, invite_expires_at)
         VALUES ($1, $2, $7, $3, 'created', $4, $5, now() + make_interval(secs => $6)) RETURNING id",
    )
    .bind(p.user_id)
    .bind(organization)
    .bind(note.as_deref().map(|n| n.chars().take(200).collect::<String>()))
    .bind(code_hash)
    .bind(link_digest(&invite))
    .bind(state.config.support_invite_ttl.as_secs_f64())
    .bind(&capabilities)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match &e {
        // Two live sessions drew the same 9-digit code (about 1 in 10^8 per pair).
        sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict("Please try again.".into()),
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => AppError::NotFound,
        _ => e.into(),
    })?;
    apply(
        &mut tx,
        id,
        SupportState::Created,
        SupportState::Waiting,
        &format!("user:{}", p.email),
        "invited",
        "",
    )
    .await?;
    Audit::user(p, "support.create")
        .org(organization)
        .target("support_session", id)
        .detail(json!({ "capabilities": capabilities }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Created { id, code, invite })
}

#[derive(Debug, Clone, Copy)]
enum Via {
    Code,
    Link,
}

/// Spend an invitation (code or link) and bind the session to this browser.
/// Returns the session id and the participant credential to set as a cookie.
async fn bind(
    state: &Shared,
    via: Via,
    digest: &[u8],
    ip: &str,
    user_agent: &str,
) -> anyhow::Result<Option<(Uuid, String)>> {
    let participant = auth::random_secret(32);
    let column = match via {
        Via::Code => "code_hash",
        Via::Link => "invite_hash",
    };
    let mut tx = state.db.begin().await?;
    let row: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(&format!(
        "SELECT id, organization_id FROM support_sessions
          WHERE {column} = $1 AND state = 'waiting' AND invite_expires_at > now()
          FOR UPDATE"
    ))
    .bind(digest)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, org)) = row else {
        return Ok(None);
    };
    // Both the code and the link are spent together: an invitation works once, in one browser.
    sqlx::query(
        "UPDATE support_sessions SET code_hash = NULL, invite_hash = NULL, participant_hash = $2,
                participant_ip = $3, participant_user_agent = $4, bound_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(auth::digest(&participant))
    .bind(ip)
    .bind(user_agent.chars().take(300).collect::<String>())
    .execute(&mut *tx)
    .await?;
    apply(
        &mut tx,
        id,
        SupportState::Waiting,
        SupportState::Authorizing,
        "participant",
        "opened",
        "",
    )
    .await?;
    let mut audit = Audit::anonymous("support", "participant", "support.open")
        .target("support_session", id)
        .ip(ip)
        .detail(json!({ "via": format!("{via:?}").to_lowercase() }));
    if let Some(org) = org {
        audit = audit.org(org);
    }
    audit.record(&mut *tx).await?;
    tx.commit().await?;
    state.support.publish(id, SupportState::Authorizing);
    Ok(Some((id, participant)))
}

/// The participant cookie: `__Host-` prefixed (host-only, path `/`, `Secure`) over HTTPS.
fn participant_cookie_name(state: &Shared) -> &'static str {
    if state.config.secure_cookies() {
        "__Host-flyw8t_support"
    } else {
        "flyw8t_support"
    }
}

async fn participant_session(
    state: &Shared,
    headers: &HeaderMap,
) -> anyhow::Result<Option<(Uuid, SupportState)>> {
    let Some(raw) = cookie(headers, participant_cookie_name(state)) else {
        return Ok(None);
    };
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, state FROM support_sessions WHERE participant_hash = $1")
            .bind(auth::digest(raw))
            .fetch_optional(&state.db)
            .await?;
    Ok(row.and_then(|(id, s)| SupportState::parse(&s).map(|s| (id, s))))
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

fn participant_cookie(state: &Shared, value: &str, max_age: u64) -> String {
    // Lax, not Strict: the participant usually arrives from a link in an email or chat (a
    // cross-site navigation), and a Strict cookie would not survive the redirect to the
    // consent page. Every state change happens over the WebSocket, which checks Origin.
    let secure = if state.config.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}",
        participant_cookie_name(state)
    )
}

// ---------------------------------------------------------------------------------------
// Pages

fn with_csp(mut resp: Response) -> Response {
    resp.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(SUPPORT_CSP),
    );
    resp
}

fn session_view(row: SessionRow, viewer: Uuid, now: OffsetDateTime) -> SupportSessionView {
    let st = SupportState::parse(&row.state).unwrap_or(SupportState::Closed);
    SupportSessionView {
        id: row.id,
        created_by: row.email,
        organization: row.organization.unwrap_or_else(|| "—".into()),
        observer: row.created_by_id != viewer,
        note: row.note,
        state: st.as_str(),
        state_label: st.label(),
        terminal: st.is_terminal(),
        capabilities: row.capabilities,
        created_at: row.created_at,
        invite_expires_at: row.invite_expires_at,
        ended_at: row.ended_at,
        end_reason: row.end_reason,
        now,
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    created_by_id: Uuid,
    email: String,
    organization: Option<String>,
    note: Option<String>,
    state: String,
    capabilities: Vec<String>,
    created_at: OffsetDateTime,
    invite_expires_at: OffsetDateTime,
    ended_at: Option<OffsetDateTime>,
    end_reason: Option<String>,
}

const SESSION_SELECT: &str = "SELECT s.id, s.created_by AS created_by_id, u.email, o.name AS organization, s.note, s.state,
                                     s.capabilities, s.created_at, s.invite_expires_at, s.ended_at, s.end_reason
                                FROM support_sessions s JOIN users u ON u.id = s.created_by
                                LEFT JOIN organizations o ON o.id = s.organization_id";

/// Administrators see every session; a technician sees the sessions they created, in
/// organizations they are still assigned to. Anything else is 404. Binds (all, user, orgs)
/// starting at parameter `first`.
fn session_scope(first: usize) -> String {
    let (a, u, o) = (first, first + 1, first + 2);
    format!("(${a} OR (s.created_by = ${u} AND s.organization_id = ANY(${o})))")
}

async fn visible_session(state: &Shared, p: &Principal, id: Uuid) -> AppResult<SessionRow> {
    p.require(Permission::RunSupportSessions)?;
    let (all, orgs) = p.scope();
    let row: Option<SessionRow> = sqlx::query_as(&format!(
        "{SESSION_SELECT} WHERE s.id = $1 AND {}",
        session_scope(2)
    ))
    .bind(id)
    .bind(all)
    .bind(p.user_id)
    .bind(&orgs)
    .fetch_optional(&state.db)
    .await?;
    row.ok_or(AppError::NotFound)
}

pub async fn list_page(State(state): State<Shared>, WebUser(p): WebUser) -> Response {
    match list(&state, &p, None).await {
        Ok(r) => r,
        Err(e) => error_response(Some(&crate::web::ctx(&p, None)), e),
    }
}

async fn list(
    state: &Shared,
    p: &Principal,
    revealed: Option<(Uuid, String, String)>,
) -> AppResult<Response> {
    p.require(Permission::RunSupportSessions)?;
    let (all, orgs) = p.scope();
    let rows: Vec<SessionRow> = sqlx::query_as(&format!(
        "{SESSION_SELECT} WHERE {} ORDER BY s.created_at DESC LIMIT 50",
        session_scope(1)
    ))
    .bind(all)
    .bind(p.user_id)
    .bind(&orgs)
    .fetch_all(&state.db)
    .await?;
    let now = OffsetDateTime::now_utc();
    let sessions = rows
        .into_iter()
        .map(|r| session_view(r, p.user_id, now))
        .collect();
    let revealed = revealed.map(|(id, code, invite)| flyw8t_web::model::SupportInvite {
        session_id: id,
        code: format!("{} {} {}", &code[..3], &code[3..6], &code[6..]),
        link: format!("{}/s/{invite}", state.config.public_url),
        entry_url: format!("{}/s", state.config.public_url),
        minutes: state.config.support_invite_ttl.as_secs() / 60,
    });
    let orgs = crate::queries::org_refs(state, p).await?;
    let mut resp = Html(flyw8t_web::support_list_page(
        &crate::web::ctx(p, None),
        sessions,
        orgs,
        revealed,
    ))
    .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

pub async fn create_handler(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    body: Bytes,
) -> Response {
    let result = async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::RunSupportSessions)?;
        if !state.limiter.allow(
            &format!("support-create:{}", p.user_id),
            20,
            Duration::from_secs(3600),
        ) {
            return Err(AppError::RateLimited);
        }
        let org = form
            .get("organization")
            .and_then(|o| o.parse::<Uuid>().ok())
            .ok_or_else(|| AppError::BadRequest("Choose an organization.".into()))?;
        let note = form
            .get("note")
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(String::from);
        // View is the default; control must be chosen on purpose.
        let control = match form.get("capability").unwrap_or("view") {
            "view" => false,
            "control" => true,
            _ => return Err(AppError::BadRequest("Unknown capability.".into())),
        };
        let c = create(&state, &p, org, control, note).await?;
        list(&state, &p, Some((c.id, c.code, c.invite))).await
    }
    .await;
    result.unwrap_or_else(|e| error_response(Some(&crate::web::ctx(&p, None)), e))
}

pub async fn session_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
) -> Response {
    match visible_session(&state, &p, id).await {
        Ok(row) => {
            let view = session_view(row, p.user_id, OffsetDateTime::now_utc());
            with_csp(
                Html(flyw8t_web::support_session_page(
                    &crate::web::ctx(&p, None),
                    view,
                    &state.config.ice_servers,
                ))
                .into_response(),
            )
        }
        Err(e) => error_response(Some(&crate::web::ctx(&p, None)), e),
    }
}

pub async fn end_handler(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    let result = async {
        check_csrf(&p, &Form::parse(&body))?;
        let row = visible_session(&state, &p, id).await?;
        let reason = if row.created_by_id == p.user_id {
            "ended by technician"
        } else {
            "ended by administrator"
        };
        end(
            &state,
            id,
            Side::Technician,
            &Who::User(Box::new(p.clone())),
            reason,
        )
        .await?;
        Ok(Redirect::to(&format!("/support/{id}")).into_response())
    }
    .await;
    result.unwrap_or_else(|e| error_response(Some(&crate::web::ctx(&p, None)), e))
}

// Participant side (no account) ---------------------------------------------------------

fn participant_error(status: StatusCode, msg: &str) -> Response {
    (
        status,
        Html(flyw8t_web::support_entry_page(Some(msg.into()))),
    )
        .into_response()
}

pub async fn entry_page() -> Response {
    Html(flyw8t_web::support_entry_page(None)).into_response()
}

async fn spend(
    state: &Shared,
    via: Via,
    credential: &str,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Response {
    let ip = peer.ip().to_string();
    if !state
        .limiter
        .allow(&format!("support-code:{ip}"), 10, Duration::from_secs(600))
    {
        return participant_error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Wait ten minutes, then try again.",
        );
    }
    // One support session per browser: binding another would silently replace it.
    match participant_session(state, headers).await {
        Ok(Some((_, st))) if !st.is_terminal() => {
            return participant_error(
                StatusCode::CONFLICT,
                "This browser is already in a support session. End or decline it on its page (/s/session) first.",
            );
        }
        Ok(_) => {}
        Err(e) => return error_response(None, AppError::Internal(e)),
    }
    // Every code attempt reserves a place in the global budget before any work is done, so
    // concurrent guesses cannot all slip under it; only a correct code gives its place back.
    let reservation = match via {
        Via::Link => None,
        Via::Code => match state.limiter.reserve(
            GLOBAL_CODE_KEY,
            GLOBAL_CODE_FAILURES,
            CODE_FAILURE_WINDOW,
        ) {
            Some(r) => Some(r),
            None => {
                return participant_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Code entry is paused because of many wrong codes. Ask your technician to send you the link instead.",
                )
            }
        },
    };
    let digest = match via {
        Via::Code => match code_digest(credential.to_string()).await {
            Ok(d) => d,
            Err(e) => return error_response(None, AppError::Internal(e)),
        },
        Via::Link => link_digest(credential),
    };
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match bind(state, via, &digest, &ip, ua).await {
        Ok(Some((_, participant))) => {
            if let Some(r) = reservation {
                state.limiter.refund(r);
            }
            let cookie = participant_cookie(state, &participant, 4 * 3600);
            ([(header::SET_COOKIE, cookie)], Redirect::to("/s/session")).into_response()
        }
        // One answer for unknown, expired and already-used: no oracle.
        Ok(None) => {
            let _ = Audit::anonymous("support", "participant", "support.open")
                .ip(&ip)
                .denied()
                .detail(json!({ "via": format!("{via:?}").to_lowercase() }))
                .record(&state.db)
                .await;
            participant_error(StatusCode::NOT_FOUND, "That code or link is not valid. It may have expired or already been used. Ask for a new one.")
        }
        Err(e) => error_response(None, AppError::Internal(e)),
    }
}

pub async fn enter_code(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = Form::parse(&body);
    let code = normalize_code(form.get("code").unwrap_or(""));
    if code.len() != 9 {
        return participant_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Enter the 9-digit code you were given.",
        );
    }
    spend(&state, Via::Code, &code, peer, &headers).await
}

/// `GET /s/{invite}`: a page with a Continue button. Opening the link spends nothing, so a
/// link preview or a page someone else makes the browser load cannot bind it.
pub async fn open_invite(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(invite): Path<String>,
) -> Response {
    if invite == "session" {
        return consent_page(&state, &headers).await;
    }
    if invite.len() > 100
        || !invite
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return participant_error(StatusCode::NOT_FOUND, "That link is not valid.");
    }
    Html(flyw8t_web::support_link_page(&invite)).into_response()
}

/// `POST /s/{invite}`: the person chose to continue; spend the link.
pub async fn spend_invite(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(invite): Path<String>,
) -> Response {
    if invite.len() > 100 {
        return participant_error(StatusCode::NOT_FOUND, "That link is not valid.");
    }
    spend(&state, Via::Link, &invite, peer, &headers).await
}

async fn consent_page(state: &Shared, headers: &HeaderMap) -> Response {
    let found = match participant_session(state, headers).await {
        Ok(f) => f,
        Err(e) => return error_response(None, AppError::Internal(e)),
    };
    let Some((id, st)) = found else {
        return participant_error(
            StatusCode::NOT_FOUND,
            "This support session has ended or this browser is not part of it.",
        );
    };
    let row: Result<(String, String, Vec<String>), _> = sqlx::query_as(
        "SELECT u.display_name, u.email, s.capabilities FROM support_sessions s JOIN users u ON u.id = s.created_by WHERE s.id = $1",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await;
    let (name, email, caps) = match row {
        Ok(r) => r,
        Err(e) => return error_response(None, e.into()),
    };
    let host = state
        .config
        .public_url
        .split_once("://")
        .map_or(state.config.public_url.as_str(), |(_, h)| h)
        .to_string();
    let view = SupportConsentView {
        session_id: id,
        control: caps.iter().any(|c| c == "control_input"),
        technician_name: name,
        technician_email: email,
        server_host: host,
        capabilities: caps
            .iter()
            .filter_map(|c| Capability::parse(c))
            .map(|c| c.consent_text().to_string())
            .collect(),
        state: st.as_str(),
        state_label: st.label(),
    };
    let mut resp = with_csp(
        Html(flyw8t_web::support_consent_page(
            view,
            &state.config.ice_servers,
        ))
        .into_response(),
    );
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

// ---------------------------------------------------------------------------------------
// Signaling sockets

/// Reject cross-site WebSocket handshakes: the Origin must be this server, scheme included.
fn same_origin(state: &Shared, headers: &HeaderMap) -> bool {
    crate::origin_is_self(&state.config, headers) == Some(true)
}

pub async fn technician_ws(
    ws: WebSocketUpgrade,
    State(state): State<Shared>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let p = match auth::session_principal(&state, &headers).await {
        Ok(Some(p)) => p,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };
    // Only the technician the participant is shown (the creator) may receive signaling.
    let control = match visible_session(&state, &p, id).await {
        Ok(row) if row.created_by_id == p.user_id => {
            row.capabilities.iter().any(|c| c == "control_input")
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let who = Who::User(Box::new(p));
    ws.max_message_size(MAX_SIGNAL_BYTES)
        .on_upgrade(move |socket| run_socket(state, socket, id, Side::Technician, control, who))
}

pub async fn participant_ws(
    ws: WebSocketUpgrade,
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match participant_session(&state, &headers).await {
        Ok(Some((id, st))) if !st.is_terminal() => {
            let who = Who::Participant {
                ip: peer.ip().to_string(),
            };
            let Ok(control) = is_control(&state, id).await else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            ws.max_message_size(MAX_SIGNAL_BYTES)
                .on_upgrade(move |socket| {
                    run_socket(state, socket, id, Side::Participant, control, who)
                })
        }
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn current(state: &Shared, id: Uuid) -> Option<SupportState> {
    let row: Option<(String,)> = sqlx::query_as("SELECT state FROM support_sessions WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()?;
    row.and_then(|(s,)| SupportState::parse(&s))
}

/// Per-socket message budget.
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn new() -> Self {
        Self {
            tokens: MESSAGE_BURST,
            at: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * MESSAGES_PER_SEC)
            .min(MESSAGE_BURST);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn text(msg: &Out) -> Message {
    Message::Text(serde_json::to_string(msg).unwrap_or_default().into())
}

/// How long one write to a socket may take before the socket is given up on.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a technician socket re-checks the sign-in session it was opened with.
const SESSION_RECHECK: Duration = Duration::from_secs(15);

async fn run_socket(
    state: Shared,
    socket: WebSocket,
    id: Uuid,
    side: Side,
    control: bool,
    who: Who,
) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Out>(PEER_BUFFER);
    let close = CancellationToken::new();
    let last = Arc::new(Mutex::new(None));
    let recheck = Arc::new(tokio::sync::Notify::new());
    let conn_id = Uuid::new_v4();
    // A technician socket stays authorized only while the browser session that opened it
    // does: sign-out, revocation and rotation (setting up or turning off MFA) all end it.
    let signed_in = match &who {
        Who::User(p) => p
            .session_id
            .zip(p.session_token.clone())
            .map(|s| (p.user_id, s)),
        _ => None,
    };
    let replaced = state.support.attach(
        id,
        side,
        control,
        Peer {
            conn_id,
            tx,
            close: close.clone(),
            last: last.clone(),
            user: signed_in.as_ref().map(|(u, _)| *u),
            recheck: recheck.clone(),
        },
    );
    let _ = who
        .audit("support.attach")
        .target("support_session", id)
        .detail(json!({ "side": side.as_str(), "replaced": replaced }))
        .record(&state.db)
        .await;
    if let Some(st) = current(&state, id).await {
        state.support.publish(id, st);
    }

    let mut bucket = Bucket::new();
    let mut every = tokio::time::interval_at(
        tokio::time::Instant::now() + SESSION_RECHECK,
        SESSION_RECHECK,
    );
    loop {
        tokio::select! {
            biased;
            _ = close.cancelled() => {
                // Anything still queued (signaling included) is dropped: once a session has
                // ended, or this socket was replaced, nothing more flows. Only the final
                // notice goes out, with a deadline.
                let final_msg = last.lock().unwrap().take();
                if let Some(m) = final_msg {
                    let _ = tokio::time::timeout(Duration::from_secs(2), sink.send(text(&m))).await;
                }
                let _ = tokio::time::timeout(Duration::from_secs(1), sink.send(Message::Close(None))).await;
                break;
            }
            _ = async { tokio::select! { _ = recheck.notified() => {}, _ = every.tick() => {} } }, if signed_in.is_some() => {
                let Some((_, (session, token))) = &signed_in else { continue };
                if !auth::session_still_valid(&state, *session, token).await {
                    let _ = end(&state, id, Side::Technician, &who, "technician signed out").await;
                    if !close.is_cancelled() {
                        break;
                    }
                }
            }
            Some(msg) = rx.recv() => {
                // A peer that stops reading must not keep this task from noticing the end.
                tokio::select! {
                    biased;
                    _ = close.cancelled() => {}
                    r = tokio::time::timeout(WRITE_TIMEOUT, sink.send(text(&msg))) => {
                        if !matches!(r, Ok(Ok(()))) {
                            break;
                        }
                    }
                }
            }
            frame = stream.next() => {
                if !bucket.take() {
                    // Say why, close cleanly, and drain what the client already sent: dropping
                    // a socket with unread input resets it, and the reset can discard the
                    // explanation before the client reads it.
                    let _ = tokio::time::timeout(Duration::from_secs(1), sink.send(text(&Out::Error { message: "too many messages".into() }))).await;
                    let _ = tokio::time::timeout(Duration::from_secs(1), sink.send(Message::Close(None))).await;
                    let _ = tokio::time::timeout(Duration::from_secs(2), async {
                        while let Some(Ok(_)) = stream.next().await {}
                    })
                    .await;
                    break;
                }
                let text = match frame {
                    Some(Ok(Message::Text(t))) => t,
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => continue,
                };
                let Ok(msg) = serde_json::from_str::<In>(text.as_str()) else {
                    state.support.send(id, side, Out::Error { message: "malformed message".into() });
                    continue;
                };
                if let Err(e) = on_message(&state, id, side, &who, msg).await {
                    tracing::warn!(session = %id, error = %format!("{e:#}"), "support message failed");
                    break;
                }
            }
        }
    }
    state.support.detach(id, side, conn_id);
    // Leaving mid-session ends it: the safe default for screen sharing. A helper that
    // goes away after attaching ends the session too; it cannot come back (its token is spent).
    if let Some(st) = current(&state, id).await {
        let live = matches!(st, SupportState::Connecting | SupportState::Connected)
            || (side == Side::Helper && st == SupportState::AwaitingHelper);
        if live {
            let reason = match side {
                Side::Technician => "technician left",
                Side::Participant => "participant left",
                Side::Helper => "helper closed",
            };
            let _ = end(&state, id, side, &who, reason).await;
        } else if !st.is_terminal() {
            state.support.publish(id, st);
        }
    }
}

async fn on_message(
    state: &Shared,
    id: Uuid,
    side: Side,
    who: &Who,
    msg: In,
) -> anyhow::Result<()> {
    use SupportState::*;
    let nothing = |state: &Shared, message: &str| {
        state.support.send(
            id,
            side,
            Out::Error {
                message: message.into(),
            },
        );
    };
    match (side, msg) {
        // The browser's Allow: straight to media for a view session; for a control session,
        // to the helper step, which still needs the helper's own Allow.
        (Side::Participant, In::Approve) => {
            if !browser_allow(state, id, who).await? {
                nothing(state, "nothing to approve");
            }
        }
        (Side::Participant, In::Decline) => {
            change(
                state,
                id,
                &[Authorizing, AwaitingHelper],
                Rejected,
                who,
                "declined",
                "participant declined",
            )
            .await?;
        }
        // The second consent, given in the helper's own window (ADR-0012 section 4).
        (Side::Helper, In::Approve) => {
            if change(
                state,
                id,
                &[AwaitingHelper],
                Connecting,
                who,
                "control_consented",
                "participant allowed control_input in the helper",
            )
            .await?
            .is_none()
            {
                nothing(state, "nothing to approve");
            }
        }
        (Side::Helper, In::Decline) => {
            change(
                state,
                id,
                &[AwaitingHelper],
                Rejected,
                who,
                "declined",
                "participant declined in the helper",
            )
            .await?;
        }
        (_, In::Signal { data }) => {
            // Nothing reaches the other side before consent or after the end, and a control
            // session's browser page has nothing to relay at all.
            let message = match state.support.relay(id, side, data) {
                Relay::Sent => None,
                Relay::NotAllowed => Some("not allowed before consent"),
                Relay::NoPeer => Some("the other person is not connected"),
            };
            if let Some(m) = message {
                nothing(state, m);
            }
        }
        (_, In::Media { state: media }) => match media.as_str() {
            // Connected only when the technician and its media peer both say media flows.
            "connected" if state.support.media_connected(id, side) => {
                change(
                    state,
                    id,
                    &[Connecting],
                    Connected,
                    who,
                    "media_connected",
                    "",
                )
                .await?;
            }
            "failed" => {
                change(
                    state,
                    id,
                    &[Connecting, Connected],
                    ConnectionFailed,
                    who,
                    "media_failed",
                    "WebRTC connection failed",
                )
                .await?;
            }
            _ => {}
        },
        (_, In::End) => {
            let reason = match side {
                Side::Technician => "ended by technician",
                Side::Participant => "ended by participant",
                Side::Helper => "ended in the helper",
            };
            end(state, id, side, who, reason).await?;
        }
        (Side::Technician, In::Approve | In::Decline) => {
            nothing(state, "only the person being helped can allow or decline");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Control sessions: the helper (ADR-0012)

/// How long a helper launch token works after it is issued by a download.
const HELPER_TOKEN_TTL_SECS: u64 = 120;
/// How long a session waits in `awaiting_helper` before it expires.
const AWAITING_HELPER_TIMEOUT_SECS: f64 = 5.0 * 60.0;
/// Where the participant's browser fetches the helper. It carries no secret: the launch token
/// is minted when the bound browser downloads, and travels only in the file's name.
const HELPER_DOWNLOAD: &str = "/s/helper/download";

/// Whether a session requests control. Errors are errors: a failed lookup must never be read
/// as "view only", which would let the browser page signal or skip the helper's consent.
async fn is_control(state: &Shared, id: Uuid) -> anyhow::Result<bool> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT 'control_input' = ANY (capabilities) FROM support_sessions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    row.map(|r| r.0)
        .ok_or_else(|| anyhow::anyhow!("support session {id} not found"))
}

/// The browser's Allow. The session's capabilities and state are read under one row lock, so
/// the choice between "media now" (view) and "the helper next" (control) cannot go stale.
async fn browser_allow(state: &Shared, id: Uuid, who: &Who) -> anyhow::Result<bool> {
    let mut tx = state.db.begin().await?;
    let row: Option<(String, Option<Uuid>, bool)> = sqlx::query_as(
        "SELECT state, organization_id, 'control_input' = ANY (capabilities)
           FROM support_sessions WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((current, org, control)) = row else {
        return Ok(false);
    };
    if SupportState::parse(&current) != Some(SupportState::Authorizing) {
        tx.rollback().await?;
        return Ok(false);
    }
    let to = SupportState::after_browser_consent(control);
    if control {
        sqlx::query("UPDATE support_sessions SET awaiting_helper_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    let reason = if control {
        "participant allowed control_input in the browser"
    } else {
        "participant allowed view_screen"
    };
    apply(
        &mut tx,
        id,
        SupportState::Authorizing,
        to,
        &who.actor(),
        "consented",
        reason,
    )
    .await?;
    let mut audit = who
        .audit(if control {
            "support.control.browser_consent"
        } else {
            "support.consented"
        })
        .target("support_session", id);
    if let Some(org) = org {
        audit = audit.org(org);
    }
    audit.record(&mut *tx).await?;
    tx.commit().await?;
    if to == SupportState::Connecting {
        state.support.open_relay(id);
    }
    state.support.publish(id, to);
    if control {
        state.support.send(
            id,
            Side::Participant,
            Out::Helper {
                download: HELPER_DOWNLOAD.into(),
                expires_in_secs: HELPER_TOKEN_TTL_SECS,
            },
        );
    }
    Ok(true)
}

/// Spend a launch token: once, before it expires, only while the session awaits its helper.
async fn spend_helper_token(state: &Shared, token: &str, ip: &str) -> anyhow::Result<Option<Uuid>> {
    let mut tx = state.db.begin().await?;
    let row: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, organization_id FROM support_sessions
          WHERE helper_token_hash = $1 AND state = 'awaiting_helper' AND helper_token_expires_at > now()
          FOR UPDATE",
    )
    .bind(auth::digest(token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, org)) = row else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE support_sessions SET helper_token_hash = NULL, helper_attached_at = now() WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO support_events (session_id, kind, actor, detail) VALUES ($1, 'helper_attached', 'helper', $2)")
        .bind(id)
        .bind(json!({ "ip": ip }))
        .execute(&mut *tx)
        .await?;
    let mut audit = Audit::anonymous("support", "helper", "support.helper.attach")
        .ip(ip)
        .target("support_session", id);
    if let Some(org) = org {
        audit = audit.org(org);
    }
    audit.record(&mut *tx).await?;
    tx.commit().await?;
    Ok(Some(id))
}

/// `GET /api/support/helper/ws` with `Authorization: Bearer <launch token>`. A browser page
/// cannot set that header on a WebSocket, so only a native program can attach here.
pub async fn helper_ws(
    ws: WebSocketUpgrade,
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if crate::origin_is_self(&state.config, &headers) == Some(false) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let ip = peer.ip().to_string();
    if !state.limiter.allow(
        &format!("support-helper:{ip}"),
        10,
        Duration::from_secs(600),
    ) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.len() <= 100)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match spend_helper_token(&state, token, &ip).await {
        Ok(Some(id)) => {
            let who = Who::Helper { ip };
            ws.max_message_size(MAX_SIGNAL_BYTES)
                .on_upgrade(move |socket| run_socket(state, socket, id, Side::Helper, true, who))
        }
        Ok(None) => {
            let _ = Audit::anonymous("support", "helper", "support.helper.attach")
                .ip(&ip)
                .denied()
                .record(&state.db)
                .await;
            StatusCode::UNAUTHORIZED.into_response()
        }
        Err(e) => error_response(None, AppError::Internal(e)),
    }
}

/// `GET /s/helper/download`: the helper, for the browser bound to a session that awaits its
/// helper. The launch token is minted here, under the row lock, and travels only in the
/// attachment's file name (ADR-0012 section 2), never in a URL a proxy might log. Each
/// download replaces the previous token. Downloading spends nothing; attaching does.
pub async fn helper_download(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(file): Path<String>,
) -> Response {
    let not_here = |msg: &str| participant_error(StatusCode::NOT_FOUND, msg);
    if format!("/s/helper/{file}") != HELPER_DOWNLOAD {
        return not_here("That download is not valid.");
    }
    let Some(path) = &state.config.helper_path else {
        return not_here("This server does not offer the flyw8t helper yet, so remote control is not available. Screen viewing still works.");
    };
    let session = match participant_session(&state, &headers).await {
        Ok(Some((id, SupportState::AwaitingHelper))) => id,
        Ok(_) => {
            return not_here("This download is not for this browser, or the session is no longer waiting for the helper.")
        }
        Err(e) => return error_response(None, AppError::Internal(e)),
    };
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) => return error_response(None, AppError::Internal(e.into())),
    };
    let token = auth::random_secret(32);
    let minted = sqlx::query(
        "UPDATE support_sessions SET helper_token_hash = $2,
                helper_token_expires_at = now() + make_interval(secs => $3)
          WHERE id = $1 AND state = 'awaiting_helper'",
    )
    .bind(session)
    .bind(auth::digest(&token))
    .bind(HELPER_TOKEN_TTL_SECS as f64)
    .execute(&state.db)
    .await;
    match minted {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => return not_here("The session is no longer waiting for the helper."),
        Err(e) => return error_response(None, AppError::Internal(e.into())),
    }
    let name = format!("flyw8t-helper-{token}.exe");
    (
        [
            (
                header::CONTENT_TYPE,
                "application/vnd.microsoft.portable-executable".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        bytes,
    )
        .into_response()
}

// ---------------------------------------------------------------------------------------
// Deadlines

pub async fn sweep(state: &Shared) -> anyhow::Result<()> {
    use SupportState::*;
    let rules: [(&str, f64, SupportState, SupportState, &str); 5] = [
        (
            "state = 'awaiting_helper' AND awaiting_helper_at + make_interval(secs => $1) <= now()",
            AWAITING_HELPER_TIMEOUT_SECS,
            AwaitingHelper,
            Expired,
            "the helper was not started",
        ),
        (
            "state = 'waiting' AND invite_expires_at <= now()",
            0.0,
            Waiting,
            Expired,
            "invitation expired",
        ),
        (
            "state = 'authorizing' AND bound_at + make_interval(secs => $1) <= now()",
            AUTHORIZING_TIMEOUT_SECS,
            Authorizing,
            Expired,
            "no decision",
        ),
        (
            "state = 'connecting' AND consented_at + make_interval(secs => $1) <= now()",
            CONNECTING_TIMEOUT_SECS,
            Connecting,
            ConnectionFailed,
            "could not establish media",
        ),
        (
            "state = 'connected' AND connected_at + make_interval(secs => $1) <= now()",
            SESSION_CAP_SECS,
            Connected,
            Closed,
            "session time limit reached",
        ),
    ];
    for (cond, secs, from, to, reason) in rules {
        let ids: Vec<(Uuid,)> =
            sqlx::query_as(&format!("SELECT id FROM support_sessions WHERE {cond}"))
                .bind(secs)
                .fetch_all(&state.db)
                .await?;
        for (id,) in ids {
            change(state, id, &[from], to, &Who::System, "timeout", reason).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_nine_digits() {
        for _ in 0..1000 {
            let c = nine_digit_code();
            assert_eq!(c.len(), 9);
            assert!(c.bytes().all(|b| b.is_ascii_digit()));
        }
        assert_eq!(normalize_code("123 456-789"), "123456789");
    }

    #[tokio::test]
    async fn code_digest_is_deterministic_and_not_sha256() {
        let a = code_digest("123456789".into()).await.unwrap();
        assert_eq!(a, code_digest("123456789".into()).await.unwrap());
        assert_ne!(a, code_digest("123456780".into()).await.unwrap());
        assert_ne!(a, auth::digest("123456789"));
        assert_eq!(a.len(), 32);
    }

    fn peer() -> (Peer, mpsc::Receiver<Out>, Arc<Mutex<Option<Out>>>) {
        let (tx, rx) = mpsc::channel(PEER_BUFFER);
        let last = Arc::new(Mutex::new(None));
        (
            Peer {
                conn_id: Uuid::new_v4(),
                tx,
                close: CancellationToken::new(),
                last: last.clone(),
                user: None,
                recheck: Arc::default(),
            },
            rx,
            last,
        )
    }

    #[test]
    fn relay_needs_consent_and_stops_at_seal() {
        let hub = SupportHub::default();
        let id = Uuid::new_v4();
        let (t, _trx, _) = peer();
        let (p, mut prx, _) = peer();
        hub.attach(id, Side::Technician, false, t);
        hub.attach(id, Side::Participant, false, p);
        assert!(matches!(
            hub.relay(id, Side::Technician, json!(1)),
            Relay::NotAllowed
        ));
        hub.open_relay(id);
        assert!(matches!(
            hub.relay(id, Side::Technician, json!(2)),
            Relay::Sent
        ));
        assert!(matches!(prx.try_recv(), Ok(Out::Signal { .. })));
        hub.seal(id);
        assert!(matches!(
            hub.relay(id, Side::Technician, json!(3)),
            Relay::NotAllowed
        ));
        hub.open_relay(id);
        assert!(
            matches!(hub.relay(id, Side::Technician, json!(4)), Relay::NotAllowed),
            "a sealed session never reopens"
        );
    }

    #[test]
    fn final_notice_survives_a_full_queue() {
        let hub = SupportHub::default();
        let id = Uuid::new_v4();
        let (p, _rx, last) = peer();
        let close = p.close.clone();
        hub.attach(id, Side::Participant, false, p);
        while hub.send(
            id,
            Side::Participant,
            Out::Error {
                message: "x".into(),
            },
        ) {}
        hub.publish(id, SupportState::Closed);
        assert!(close.is_cancelled());
        assert!(matches!(
            *last.lock().unwrap(),
            Some(Out::Ended {
                state: "closed",
                ..
            })
        ));
    }

    #[test]
    fn media_needs_both_sides() {
        let hub = SupportHub::default();
        let id = Uuid::new_v4();
        let (t, _a, _) = peer();
        hub.attach(id, Side::Technician, false, t);
        assert!(!hub.media_connected(id, Side::Technician));
        assert!(
            !hub.media_connected(id, Side::Technician),
            "one side twice is still one side"
        );
        assert!(hub.media_connected(id, Side::Participant));
    }

    #[test]
    fn bucket_allows_a_burst_then_throttles() {
        let mut b = Bucket::new();
        let allowed = (0..200).filter(|_| b.take()).count();
        assert!(
            (MESSAGE_BURST as usize..MESSAGE_BURST as usize + 3).contains(&allowed),
            "{allowed}"
        );
    }
}
