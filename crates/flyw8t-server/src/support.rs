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

/// CSP for the support pages: the console's policy plus same-origin script and WebSocket.
pub const SUPPORT_CSP: &str =
    "default-src 'none'; script-src 'self'; connect-src 'self'; media-src 'self' blob:; \
     style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Technician,
    Participant,
}

impl Side {
    fn other(self) -> Side {
        match self {
            Side::Technician => Side::Participant,
            Side::Participant => Side::Technician,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Side::Technician => "technician",
            Side::Participant => "participant",
        }
    }
}

/// Who caused a change, for the session's event log and the audit log.
#[derive(Debug, Clone)]
pub enum Who {
    System,
    User(Box<Principal>),
    Participant { ip: String },
}

impl Who {
    fn actor(&self) -> String {
        match self {
            Who::System => "system".into(),
            Who::User(p) => format!("user:{}", p.email),
            Who::Participant { .. } => "participant".into(),
        }
    }

    fn audit(&self, action: &'static str) -> Audit {
        match self {
            Who::System => Audit::system(action),
            Who::User(p) => Audit::user(p, action),
            Who::Participant { ip } => {
                Audit::anonymous("support", "participant", action).ip(ip.clone())
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Wire format (browser <-> server)

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
}

#[derive(Default)]
struct Peers {
    technician: Option<Peer>,
    participant: Option<Peer>,
    /// Signaling flows only while this is set: opened after consent commits, never reopened
    /// once `sealed`.
    relay_open: bool,
    /// Set before an ending commits, so no signal slips through between the commit and the
    /// sockets closing.
    sealed: bool,
    /// Each side's report that media is flowing (technician, participant).
    media: [bool; 2],
}

impl Peers {
    fn side(&mut self, side: Side) -> &mut Option<Peer> {
        match side {
            Side::Technician => &mut self.technician,
            Side::Participant => &mut self.participant,
        }
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
    fn attach(&self, session: Uuid, side: Side, peer: Peer) -> bool {
        let mut s = self.sessions.lock().unwrap();
        match s.entry(session).or_default().side(side).replace(peer) {
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
            if peers.technician.is_none() && peers.participant.is_none() {
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

    /// Relay signaling to `to`, checked and sent under one lock so it cannot race an ending.
    fn relay(&self, session: Uuid, to: Side, data: Value) -> Relay {
        let mut s = self.sessions.lock().unwrap();
        let Some(peers) = s.get_mut(&session) else {
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

    /// Record that `side` sees media flowing; `true` once both sides have said so.
    fn media_connected(&self, session: Uuid, side: Side) -> bool {
        let mut s = self.sessions.lock().unwrap();
        let Some(p) = s.get_mut(&session) else {
            return false;
        };
        p.media[side as usize] = true;
        p.media == [true, true]
    }

    /// Tell both sides the current state; on a terminal state, close both sockets with a
    /// final notice that cannot be lost to a full queue.
    fn publish(&self, session: Uuid, state: SupportState) {
        if state.is_terminal() {
            let peers = self.sessions.lock().unwrap().remove(&session);
            if let Some(peers) = peers {
                for p in [peers.technician, peers.participant].into_iter().flatten() {
                    *p.last.lock().unwrap() = Some(Out::Ended {
                        state: state.as_str(),
                        label: state.label(),
                    });
                    p.close.cancel();
                }
            }
            return;
        }
        for side in [Side::Technician, Side::Participant] {
            let msg = Out::State {
                state: state.as_str(),
                label: state.label(),
                peer_present: self.present(session, side.other()),
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
    let actor = who.actor();
    let mut tx = state.db.begin().await?;
    let Some((current, org)) = lock_state(&mut tx, id).await? else {
        return Ok(None);
    };
    if !from.contains(&current) {
        tx.rollback().await?;
        return Ok(None);
    }
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

/// End a session from whichever live state it is in, as `side`.
async fn end(state: &Shared, id: Uuid, side: Side, who: &Who, reason: &str) -> anyhow::Result<()> {
    use SupportState::*;
    let Some(current) = current(state, id).await else {
        return Ok(());
    };
    let to = match (side, current) {
        (_, Connecting | Connected) => Closed,
        (Side::Technician, Created | Waiting | Authorizing) => Revoked,
        (Side::Participant, Authorizing) => Rejected,
        _ => return Ok(()),
    };
    change(state, id, &[current], to, who, "ended", reason).await?;
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
            AND state IN ('created', 'waiting', 'authorizing', 'connecting', 'connected')",
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
    note: Option<String>,
) -> AppResult<Created> {
    p.require(Permission::RunSupportSessions)?;
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
            AND state IN ('created', 'waiting', 'authorizing', 'connecting', 'connected', 'disconnecting')",
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
         VALUES ($1, $2, ARRAY['view_screen'], $3, 'created', $4, $5, now() + make_interval(secs => $6)) RETURNING id",
    )
    .bind(p.user_id)
    .bind(organization)
    .bind(note.as_deref().map(|n| n.chars().take(200).collect::<String>()))
    .bind(code_hash)
    .bind(link_digest(&invite))
    .bind(state.config.support_invite_ttl.as_secs_f64())
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
        .detail(json!({ "capabilities": ["view_screen"] }))
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
        let c = create(&state, &p, org, note).await?;
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
    if matches!(via, Via::Code)
        && !state.limiter.under(
            "support-code-failures",
            GLOBAL_CODE_FAILURES,
            CODE_FAILURE_WINDOW,
        )
    {
        return participant_error(
            StatusCode::TOO_MANY_REQUESTS,
            "Code entry is paused because of many wrong codes. Ask your technician to send you the link instead.",
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
            let cookie = participant_cookie(state, &participant, 4 * 3600);
            ([(header::SET_COOKIE, cookie)], Redirect::to("/s/session")).into_response()
        }
        // One answer for unknown, expired and already-used: no oracle.
        Ok(None) => {
            if matches!(via, Via::Code) {
                state.limiter.allow(
                    "support-code-failures",
                    GLOBAL_CODE_FAILURES,
                    CODE_FAILURE_WINDOW,
                );
            }
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
    match visible_session(&state, &p, id).await {
        Ok(row) if row.created_by_id == p.user_id => {}
        _ => return StatusCode::NOT_FOUND.into_response(),
    }
    let who = Who::User(Box::new(p));
    ws.max_message_size(MAX_SIGNAL_BYTES)
        .on_upgrade(move |socket| run_socket(state, socket, id, Side::Technician, who))
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
            ws.max_message_size(MAX_SIGNAL_BYTES)
                .on_upgrade(move |socket| run_socket(state, socket, id, Side::Participant, who))
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

async fn run_socket(state: Shared, socket: WebSocket, id: Uuid, side: Side, who: Who) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Out>(PEER_BUFFER);
    let close = CancellationToken::new();
    let last = Arc::new(Mutex::new(None));
    let conn_id = Uuid::new_v4();
    let replaced = state.support.attach(
        id,
        side,
        Peer {
            conn_id,
            tx,
            close: close.clone(),
            last: last.clone(),
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
            Some(msg) = rx.recv() => {
                if sink.send(text(&msg)).await.is_err() {
                    break;
                }
            }
            frame = stream.next() => {
                if !bucket.take() {
                    let _ = sink.send(text(&Out::Error { message: "too many messages".into() })).await;
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
    // Leaving mid-session ends it: the safe default for screen sharing.
    if let Some(st) = current(&state, id).await {
        if matches!(st, SupportState::Connecting | SupportState::Connected) {
            let reason = if side == Side::Technician {
                "technician left"
            } else {
                "participant left"
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
    match (side, msg) {
        (Side::Participant, In::Approve) => {
            if change(
                state,
                id,
                &[Authorizing],
                Connecting,
                who,
                "consented",
                "participant allowed view_screen",
            )
            .await?
            .is_none()
            {
                state.support.send(
                    id,
                    side,
                    Out::Error {
                        message: "nothing to approve".into(),
                    },
                );
            }
        }
        (Side::Participant, In::Decline) => {
            change(
                state,
                id,
                &[Authorizing],
                Rejected,
                who,
                "declined",
                "participant declined",
            )
            .await?;
        }
        (_, In::Signal { data }) => {
            // Nothing reaches the other side before consent or after the end.
            let message = match state.support.relay(id, side.other(), data) {
                Relay::Sent => None,
                Relay::NotAllowed => Some("not allowed before consent"),
                Relay::NoPeer => Some("the other person is not connected"),
            };
            if let Some(m) = message {
                state
                    .support
                    .send(id, side, Out::Error { message: m.into() });
            }
        }
        (_, In::Media { state: media }) => match media.as_str() {
            // Connected only when both browsers say media is flowing.
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
            let reason = if side == Side::Technician {
                "ended by technician"
            } else {
                "ended by participant"
            };
            end(state, id, side, who, reason).await?;
        }
        (Side::Technician, In::Approve | In::Decline) => {
            state.support.send(
                id,
                side,
                Out::Error {
                    message: "only the person being helped can allow or decline".into(),
                },
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Deadlines

pub async fn sweep(state: &Shared) -> anyhow::Result<()> {
    use SupportState::*;
    let rules: [(&str, f64, SupportState, SupportState, &str); 4] = [
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
        hub.attach(id, Side::Technician, t);
        hub.attach(id, Side::Participant, p);
        assert!(matches!(
            hub.relay(id, Side::Participant, json!(1)),
            Relay::NotAllowed
        ));
        hub.open_relay(id);
        assert!(matches!(
            hub.relay(id, Side::Participant, json!(2)),
            Relay::Sent
        ));
        assert!(matches!(prx.try_recv(), Ok(Out::Signal { .. })));
        hub.seal(id);
        assert!(matches!(
            hub.relay(id, Side::Participant, json!(3)),
            Relay::NotAllowed
        ));
        hub.open_relay(id);
        assert!(
            matches!(
                hub.relay(id, Side::Participant, json!(4)),
                Relay::NotAllowed
            ),
            "a sealed session never reopens"
        );
    }

    #[test]
    fn final_notice_survives_a_full_queue() {
        let hub = SupportHub::default();
        let id = Uuid::new_v4();
        let (p, _rx, last) = peer();
        let close = p.close.clone();
        hub.attach(id, Side::Participant, p);
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
        hub.attach(id, Side::Technician, t);
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
