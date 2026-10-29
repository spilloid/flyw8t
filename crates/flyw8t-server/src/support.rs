//! Attended support (Phase B): pairing, consent, and WebRTC signaling between a technician's
//! browser and a participant's browser. See `docs/attended-support.md`.
//!
//! The server never sees media. It authenticates both sides, enforces the session state
//! machine, and relays opaque signaling messages between exactly two sockets, and only after
//! the participant has consented.

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
use flyw8t_domain::{Permission, Role};
use flyw8t_web::model::{SupportConsentView, SupportSessionView};
use futures_util::{SinkExt, StreamExt};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgConnection;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const PARTICIPANT_COOKIE: &str = "flyw8t_support";
const MAX_SIGNAL_BYTES: usize = 64 * 1024;
const PEER_BUFFER: usize = 64;
/// Concurrent live sessions per technician.
const MAX_LIVE_PER_TECHNICIAN: i64 = 5;
const AUTHORIZING_TIMEOUT_SECS: f64 = 5.0 * 60.0;
const CONNECTING_TIMEOUT_SECS: f64 = 60.0;
const SESSION_CAP_SECS: f64 = 4.0 * 60.0 * 60.0;

/// CSP for the support pages: the console's policy plus same-origin script and WebSocket.
pub const SUPPORT_CSP: &str =
    "default-src 'none'; script-src 'self'; connect-src 'self'; media-src 'self' blob:; \
     style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Technician,
    Participant,
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
}

#[derive(Default)]
struct Peers {
    technician: Option<Peer>,
    participant: Option<Peer>,
}

impl Peers {
    fn side(&mut self, side: Side) -> &mut Option<Peer> {
        match side {
            Side::Technician => &mut self.technician,
            Side::Participant => &mut self.participant,
        }
    }
}

#[derive(Default)]
pub struct SupportHub {
    sessions: Mutex<HashMap<Uuid, Peers>>,
}

impl SupportHub {
    fn attach(&self, session: Uuid, side: Side, peer: Peer) {
        let mut s = self.sessions.lock().unwrap();
        if let Some(old) = s.entry(session).or_default().side(side).replace(peer) {
            old.close.cancel();
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

    /// Tell both sides the current state; on a terminal state, close both sockets.
    fn publish(&self, session: Uuid, state: SupportState) {
        for side in [Side::Technician, Side::Participant] {
            let other = if side == Side::Technician {
                Side::Participant
            } else {
                Side::Technician
            };
            let msg = if state.is_terminal() {
                Out::Ended {
                    state: state.as_str(),
                    label: state.label(),
                }
            } else {
                Out::State {
                    state: state.as_str(),
                    label: state.label(),
                    peer_present: self.present(session, other),
                }
            };
            self.send(session, side, msg);
        }
        if state.is_terminal() {
            let mut s = self.sessions.lock().unwrap();
            if let Some(peers) = s.remove(&session) {
                for p in [peers.technician, peers.participant].into_iter().flatten() {
                    p.close.cancel();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// State changes

async fn lock_state(tx: &mut PgConnection, id: Uuid) -> sqlx::Result<Option<SupportState>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT state FROM support_sessions WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(tx)
            .await?;
    Ok(row.and_then(|(s,)| SupportState::parse(&s)))
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
    actor: &str,
    kind: &str,
    reason: &str,
) -> anyhow::Result<Option<SupportState>> {
    let mut tx = state.db.begin().await?;
    let Some(current) = lock_state(&mut tx, id).await? else {
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
            actor,
            kind,
            reason,
        )
        .await?;
        apply(
            &mut tx,
            id,
            SupportState::Disconnecting,
            SupportState::Closed,
            actor,
            kind,
            reason,
        )
        .await?;
    } else {
        apply(&mut tx, id, current, to, actor, kind, reason).await?;
    }
    if to.is_terminal() {
        Audit::system("support.end")
            .target("support_session", id)
            .detail(json!({ "state": to.as_str(), "by": actor, "reason": reason }))
            .record(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    state.support.publish(id, to);
    Ok(Some(to))
}

/// End a session from whichever live state it is in, as `side`.
async fn end(
    state: &Shared,
    id: Uuid,
    side: Side,
    actor: &str,
    reason: &str,
) -> anyhow::Result<()> {
    use SupportState::*;
    let current: Option<(String,)> =
        sqlx::query_as("SELECT state FROM support_sessions WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let Some(current) = current.and_then(|(s,)| SupportState::parse(&s)) else {
        return Ok(());
    };
    let to = match (side, current) {
        (_, Connecting | Connected) => Closed,
        (Side::Technician, Created | Waiting | Authorizing) => Revoked,
        (Side::Participant, Authorizing) => Rejected,
        _ => return Ok(()),
    };
    change(state, id, &[current], to, actor, "ended", reason).await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Creation and binding

fn hash(s: &str) -> Vec<u8> {
    auth::digest(s)
}

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

pub struct Created {
    pub id: Uuid,
    pub code: String,
    pub invite: String,
}

pub async fn create(state: &Shared, p: &Principal, note: Option<String>) -> AppResult<Created> {
    p.require(Permission::RunSupportSessions)?;
    let (live,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM support_sessions WHERE created_by = $1
            AND state IN ('created', 'waiting', 'authorizing', 'connecting', 'connected', 'disconnecting')",
    )
    .bind(p.user_id)
    .fetch_one(&state.db)
    .await?;
    if live >= MAX_LIVE_PER_TECHNICIAN {
        return Err(AppError::Conflict(format!(
            "You already have {live} open support sessions. End one first."
        )));
    }
    let code = nine_digit_code();
    let invite = auth::random_secret(32);
    let mut tx = state.db.begin().await?;
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO support_sessions (created_by, capabilities, note, state, code_hash, invite_hash, invite_expires_at)
         VALUES ($1, ARRAY['view_screen'], $2, 'created', $3, $4, now() + make_interval(secs => $5)) RETURNING id",
    )
    .bind(p.user_id)
    .bind(note.as_deref().map(|n| n.chars().take(200).collect::<String>()))
    .bind(hash(&code))
    .bind(hash(&invite))
    .bind(state.config.support_invite_ttl.as_secs_f64())
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match &e {
        // Two live sessions drew the same 9-digit code (about 1 in 10^8 per pair).
        sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict("Please try again.".into()),
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
        .target("support_session", id)
        .detail(json!({ "capabilities": ["view_screen"] }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Created { id, code, invite })
}

/// Spend an invitation (code or link) and bind the session to this browser.
/// Returns the session id and the participant credential to set as a cookie.
async fn bind(
    state: &Shared,
    credential: &str,
    ip: &str,
    user_agent: &str,
) -> anyhow::Result<Option<(Uuid, String)>> {
    let participant = auth::random_secret(32);
    let h = hash(credential);
    let mut tx = state.db.begin().await?;
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM support_sessions
          WHERE (code_hash = $1 OR invite_hash = $1) AND state = 'waiting' AND invite_expires_at > now()
          FOR UPDATE",
    )
    .bind(&h)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id,)) = row else {
        return Ok(None);
    };
    // Both the code and the link are spent together: an invitation works once, in one browser.
    sqlx::query(
        "UPDATE support_sessions SET code_hash = NULL, invite_hash = NULL, participant_hash = $2,
                participant_ip = $3, participant_user_agent = $4, bound_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(hash(&participant))
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
    Audit::anonymous("support", "participant", "support.open")
        .target("support_session", id)
        .ip(ip)
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    state.support.publish(id, SupportState::Authorizing);
    Ok(Some((id, participant)))
}

async fn participant_session(
    state: &Shared,
    headers: &HeaderMap,
) -> anyhow::Result<Option<(Uuid, SupportState)>> {
    let Some(raw) = cookie(headers, PARTICIPANT_COOKIE) else {
        return Ok(None);
    };
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, state FROM support_sessions WHERE participant_hash = $1")
            .bind(hash(raw))
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
        "{PARTICIPANT_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
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

fn session_view(row: SessionRow, now: OffsetDateTime) -> SupportSessionView {
    let st = SupportState::parse(&row.state).unwrap_or(SupportState::Closed);
    SupportSessionView {
        id: row.id,
        created_by: row.email,
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
    email: String,
    note: Option<String>,
    state: String,
    capabilities: Vec<String>,
    created_at: OffsetDateTime,
    invite_expires_at: OffsetDateTime,
    ended_at: Option<OffsetDateTime>,
    end_reason: Option<String>,
}

const SESSION_SELECT: &str = "SELECT s.id, u.email, s.note, s.state, s.capabilities, s.created_at, s.invite_expires_at, s.ended_at, s.end_reason
                                FROM support_sessions s JOIN users u ON u.id = s.created_by";

async fn visible_session(state: &Shared, p: &Principal, id: Uuid) -> AppResult<SessionRow> {
    p.require(Permission::RunSupportSessions)?;
    let row: Option<SessionRow> = sqlx::query_as(&format!(
        "{SESSION_SELECT} WHERE s.id = $1 AND ($2 OR s.created_by = $3)"
    ))
    .bind(id)
    .bind(p.role == Role::Admin)
    .bind(p.user_id)
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
    let rows: Vec<SessionRow> = sqlx::query_as(&format!(
        "{SESSION_SELECT} WHERE ($1 OR s.created_by = $2) ORDER BY s.created_at DESC LIMIT 50"
    ))
    .bind(p.role == Role::Admin)
    .bind(p.user_id)
    .fetch_all(&state.db)
    .await?;
    let now = OffsetDateTime::now_utc();
    let sessions = rows.into_iter().map(|r| session_view(r, now)).collect();
    let revealed = revealed.map(|(id, code, invite)| flyw8t_web::model::SupportInvite {
        session_id: id,
        code: format!("{} {} {}", &code[..3], &code[3..6], &code[6..]),
        link: format!("{}/s/{invite}", state.config.public_url),
        entry_url: format!("{}/s", state.config.public_url),
        minutes: state.config.support_invite_ttl.as_secs() / 60,
    });
    let mut resp = Html(flyw8t_web::support_list_page(
        &crate::web::ctx(p, None),
        sessions,
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
        if !state.limiter.allow(
            &format!("support-create:{}", p.user_id),
            20,
            Duration::from_secs(3600),
        ) {
            return Err(AppError::RateLimited);
        }
        let note = form
            .get("note")
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(String::from);
        let c = create(&state, &p, note).await?;
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
            let view = session_view(row, OffsetDateTime::now_utc());
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
        visible_session(&state, &p, id).await?;
        end(
            &state,
            id,
            Side::Technician,
            &format!("user:{}", p.email),
            "ended by technician",
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
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match bind(state, credential, &ip, ua).await {
        Ok(Some((_, participant))) => {
            let cookie = participant_cookie(state, &participant, 4 * 3600);
            ([(header::SET_COOKIE, cookie)], Redirect::to("/s/session")).into_response()
        }
        // One answer for unknown, expired and already-used: no oracle.
        Ok(None) => participant_error(StatusCode::NOT_FOUND, "That code or link is not valid. It may have expired or already been used. Ask for a new one."),
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
    spend(&state, &code, peer, &headers).await
}

pub async fn open_invite(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(invite): Path<String>,
) -> Response {
    if invite == "session" {
        return consent_page(&state, &headers).await;
    }
    if invite.len() > 100 {
        return participant_error(StatusCode::NOT_FOUND, "That link is not valid.");
    }
    spend(&state, &invite, peer, &headers).await
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

/// Reject cross-site WebSocket handshakes: the Origin must be this server.
fn same_origin(headers: &HeaderMap) -> bool {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    match (host, origin) {
        (Some(h), Some(o)) => o
            .split_once("://")
            .is_some_and(|(_, authority)| authority.eq_ignore_ascii_case(h)),
        _ => false,
    }
}

pub async fn technician_ws(
    ws: WebSocketUpgrade,
    State(state): State<Shared>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let p = match auth::session_principal(&state, &headers).await {
        Ok(Some(p)) => p,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if visible_session(&state, &p, id).await.is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let actor = format!("user:{}", p.email);
    ws.max_message_size(MAX_SIGNAL_BYTES)
        .on_upgrade(move |socket| run_socket(state, socket, id, Side::Technician, actor))
}

pub async fn participant_ws(
    ws: WebSocketUpgrade,
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match participant_session(&state, &headers).await {
        Ok(Some((id, st))) if !st.is_terminal() => ws
            .max_message_size(MAX_SIGNAL_BYTES)
            .on_upgrade(move |socket| {
                run_socket(state, socket, id, Side::Participant, "participant".into())
            }),
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

async fn run_socket(state: Shared, socket: WebSocket, id: Uuid, side: Side, actor: String) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Out>(PEER_BUFFER);
    let close = CancellationToken::new();
    let conn_id = Uuid::new_v4();
    state.support.attach(
        id,
        side,
        Peer {
            conn_id,
            tx,
            close: close.clone(),
        },
    );
    if let Some(st) = current(&state, id).await {
        state.support.publish(id, st);
    }
    let other = if side == Side::Technician {
        Side::Participant
    } else {
        Side::Technician
    };

    loop {
        tokio::select! {
            _ = close.cancelled() => {
                // Deliver anything queued (the final "ended" message) before closing.
                while let Ok(msg) = rx.try_recv() {
                    let _ = sink.send(Message::Text(serde_json::to_string(&msg).unwrap_or_default().into())).await;
                }
                break;
            }
            Some(msg) = rx.recv() => {
                if sink.send(Message::Text(serde_json::to_string(&msg).unwrap_or_default().into())).await.is_err() {
                    break;
                }
            }
            frame = stream.next() => {
                let text = match frame {
                    Some(Ok(Message::Text(t))) => t,
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => continue,
                };
                let Ok(msg) = serde_json::from_str::<In>(text.as_str()) else {
                    state.support.send(id, side, Out::Error { message: "malformed message".into() });
                    continue;
                };
                if let Err(e) = on_message(&state, id, side, other, &actor, msg).await {
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
            let _ = end(&state, id, side, &actor, reason).await;
        } else if !st.is_terminal() {
            state.support.publish(id, st);
        }
    }
}

async fn on_message(
    state: &Shared,
    id: Uuid,
    side: Side,
    other: Side,
    actor: &str,
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
                actor,
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
                actor,
                "declined",
                "participant declined",
            )
            .await?;
        }
        (_, In::Signal { data }) => {
            // Nothing reaches the other side before consent.
            match current(state, id).await {
                Some(st) if st.may_relay_signaling() => {
                    state.support.send(id, other, Out::Signal { data });
                }
                _ => {
                    state.support.send(
                        id,
                        side,
                        Out::Error {
                            message: "not allowed before consent".into(),
                        },
                    );
                }
            }
        }
        (_, In::Media { state: media }) => match media.as_str() {
            "connected" => {
                change(
                    state,
                    id,
                    &[Connecting],
                    Connected,
                    actor,
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
                    actor,
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
            end(state, id, side, actor, reason).await?;
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
            change(state, id, &[from], to, "system", "timeout", reason).await?;
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

    #[test]
    fn origin_check() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "rmm.example.com".parse().unwrap());
        h.insert(header::ORIGIN, "https://rmm.example.com".parse().unwrap());
        assert!(same_origin(&h));
        h.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(!same_origin(&h));
        h.remove(header::ORIGIN);
        assert!(!same_origin(&h));
    }
}
