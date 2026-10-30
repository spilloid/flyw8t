//! The agent WebSocket endpoint: challenge, enrollment or authentication, then the live
//! connection that carries offers, cancels, heartbeats, inventory and job reports.

use crate::audit::Audit;
use crate::auth::{digest, ENROLL_PREFIX};
use crate::jobs::{self, ReportResult};
use crate::registry::Conn;
use crate::Shared;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::response::Response;
use base64::Engine;
use flyw8t_protocol::messages::{AgentMsg, DeviceFacts, RefusalCode};
use flyw8t_protocol::{auth, InventoryReport, ServerMsg, MAX_MESSAGE_BYTES, PROTOCOL_VERSION};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use ring::rand::SecureRandom;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Outbound messages buffered per connection. A full buffer means the device is not keeping
/// up; offers that do not fit are not sent and stay queued.
const OUTBOUND_BUFFER: usize = 64;
/// Inbound messages per second on one authenticated connection before it is closed.
const MAX_MESSAGES_PER_SECOND: u32 = 100;

pub async fn agent_ws(
    ws: WebSocketUpgrade,
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    ws.max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            let (mut sink, mut stream) = socket.split();
            if let Err(e) = handle(&state, &mut sink, &mut stream, peer).await {
                tracing::info!(%peer, error = %format!("{e:#}"), "agent connection ended");
            }
            let _ = sink.close().await;
        })
}

type Sink = SplitSink<WebSocket, Message>;
type Stream = SplitStream<WebSocket>;

async fn send(sink: &mut Sink, msg: &ServerMsg) -> anyhow::Result<()> {
    sink.send(Message::Text(serde_json::to_string(msg)?.into()))
        .await?;
    Ok(())
}

async fn refuse(sink: &mut Sink, code: RefusalCode, message: &str) -> anyhow::Result<()> {
    send(
        sink,
        &ServerMsg::Refused {
            code,
            message: message.into(),
        },
    )
    .await
}

/// Next text frame as an agent message, or an error on close, garbage or timeout. The
/// deadline is absolute: pings or other non-text frames do not extend it.
async fn recv(stream: &mut Stream, timeout: Duration) -> anyhow::Result<AgentMsg> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let frame = tokio::time::timeout_at(deadline, stream.next())
            .await
            .map_err(|_| anyhow::anyhow!("agent silent for {timeout:?}"))?
            .ok_or_else(|| anyhow::anyhow!("agent closed the connection"))??;
        match frame {
            Message::Text(t) => return Ok(serde_json::from_str(t.as_str())?),
            Message::Close(_) => anyhow::bail!("agent closed the connection"),
            _ => continue,
        }
    }
}

async fn handle(
    state: &Shared,
    sink: &mut Sink,
    stream: &mut Stream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let ip = peer.ip().to_string();
    if !state.limiter.allow(
        &format!("agent-handshake:{ip}"),
        60,
        Duration::from_secs(60),
    ) {
        refuse(
            sink,
            RefusalCode::RateLimited,
            "too many connection attempts",
        )
        .await?;
        anyhow::bail!("rate limited");
    }
    let mut nonce = [0u8; auth::NONCE_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("RNG failure"))?;
    send(
        sink,
        &ServerMsg::Challenge {
            protocol_version: PROTOCOL_VERSION,
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
        },
    )
    .await?;

    let first = match recv(stream, HANDSHAKE_TIMEOUT).await {
        Ok(m) => m,
        Err(e) => {
            let _ = refuse(
                sink,
                RefusalCode::BadMessage,
                "expected enroll or authenticate",
            )
            .await;
            return Err(e);
        }
    };
    match first {
        AgentMsg::Enroll {
            protocol_version,
            token,
            public_key,
            signature,
            facts,
        } => {
            if protocol_version != PROTOCOL_VERSION {
                return refuse(
                    sink,
                    RefusalCode::ProtocolVersion,
                    "unsupported protocol version",
                )
                .await;
            }
            if !state
                .limiter
                .allow(&format!("enroll:{ip}"), 10, Duration::from_secs(60))
            {
                return refuse(
                    sink,
                    RefusalCode::RateLimited,
                    "too many enrollment attempts",
                )
                .await;
            }
            match enroll(state, &nonce, &token, &public_key, &signature, &facts, &ip).await {
                Ok((device_id, organization)) => {
                    send(
                        sink,
                        &ServerMsg::Enrolled {
                            device_id,
                            organization,
                        },
                    )
                    .await
                }
                Err(reason) => {
                    tracing::info!(%peer, %reason, "enrollment refused");
                    Audit::anonymous(
                        "agent",
                        facts.hostname.chars().take(100).collect::<String>(),
                        "device.enroll",
                    )
                    .denied()
                    .ip(ip)
                    .detail(json!({ "reason": reason }))
                    .record(&state.db)
                    .await?;
                    // One message for every failure: no oracle for which tokens exist.
                    refuse(
                        sink,
                        RefusalCode::EnrollmentFailed,
                        "enrollment token is invalid, expired, revoked or used up",
                    )
                    .await
                }
            }
        }
        AgentMsg::Authenticate {
            protocol_version,
            device_id,
            signature,
            agent_version,
        } => {
            if protocol_version != PROTOCOL_VERSION {
                return refuse(
                    sink,
                    RefusalCode::ProtocolVersion,
                    "unsupported protocol version",
                )
                .await;
            }
            match authenticate(state, &nonce, device_id, &signature).await? {
                AuthResult::Ok { hostname, key } => {
                    connected(
                        state,
                        sink,
                        stream,
                        device_id,
                        hostname,
                        key,
                        agent_version,
                        ip,
                    )
                    .await
                }
                AuthResult::Revoked => {
                    Audit::anonymous("agent", device_id.to_string(), "device.authenticate")
                        .target("device", device_id)
                        .denied()
                        .ip(ip)
                        .detail(json!({ "reason": "credential revoked" }))
                        .record(&state.db)
                        .await?;
                    refuse(
                        sink,
                        RefusalCode::Revoked,
                        "this device's credential has been revoked",
                    )
                    .await
                }
                AuthResult::Failed => {
                    if !state
                        .limiter
                        .allow(&format!("auth-fail:{ip}"), 10, Duration::from_secs(60))
                    {
                        tracing::warn!(%peer, "repeated agent authentication failures");
                    }
                    Audit::anonymous("agent", device_id.to_string(), "device.authenticate")
                        .denied()
                        .ip(ip)
                        .detail(json!({ "reason": "signature did not verify" }))
                        .record(&state.db)
                        .await?;
                    refuse(sink, RefusalCode::AuthFailed, "authentication failed").await
                }
            }
        }
        _ => {
            refuse(
                sink,
                RefusalCode::BadMessage,
                "expected enroll or authenticate",
            )
            .await
        }
    }
}

/// Validate and consume an enrollment token, register the device and its key.
/// Errors are internal reasons for the audit log, never shown to the caller.
async fn enroll(
    state: &Shared,
    nonce: &[u8],
    token: &str,
    public_key_b64: &str,
    signature_b64: &str,
    facts: &DeviceFacts,
    ip: &str,
) -> Result<(Uuid, String), String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let public_key = b64
        .decode(public_key_b64)
        .map_err(|_| "public key is not base64")?;
    if public_key.len() != 32 {
        return Err("public key is not a 32-byte Ed25519 key".into());
    }
    let signature = b64
        .decode(signature_b64)
        .map_err(|_| "signature is not base64")?;
    let token = token.trim();
    if !token.starts_with(ENROLL_PREFIX) || token.len() > 200 {
        return Err("not an enrollment token".into());
    }
    let token_digest = digest(token);
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(
            &auth::enroll_message(nonce, &public_key, &token_digest),
            &signature,
        )
        .map_err(|_| "proof of key possession failed")?;
    let hostname: String = facts.hostname.trim().chars().take(255).collect();
    let hostname = if hostname.is_empty() {
        "unnamed-device".to_string()
    } else {
        hostname
    };
    let os_family: String = facts.os_family.chars().take(32).collect();

    let result: anyhow::Result<Result<(Uuid, String), String>> = async {
        let mut tx = state.db.begin().await?;
        let row: Option<(Uuid, Uuid, Option<Uuid>, String, bool)> = sqlx::query_as(
            "SELECT t.id, t.organization_id, t.site_id, o.name,
                    (t.revoked_at IS NULL AND t.expires_at > now() AND t.uses < t.max_uses)
               FROM enrollment_tokens t JOIN organizations o ON o.id = t.organization_id
              WHERE t.token_hash = $1 FOR UPDATE OF t",
        )
        .bind(&token_digest)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((token_id, org_id, site_id, org_name, usable)) = row else {
            return Ok(Err("unknown token".into()));
        };
        if !usable {
            return Ok(Err("token expired, revoked or used up".into()));
        }
        let key_in_use: (bool,) = sqlx::query_as("SELECT EXISTS (SELECT 1 FROM device_credentials WHERE public_key = $1)")
            .bind(&public_key)
            .fetch_one(&mut *tx)
            .await?;
        if key_in_use.0 {
            return Ok(Err("public key already registered".into()));
        }
        sqlx::query("UPDATE enrollment_tokens SET uses = uses + 1 WHERE id = $1")
            .bind(token_id)
            .execute(&mut *tx)
            .await?;
        let (device_id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO devices (organization_id, site_id, hostname, os_family, agent_version, enrolled_via)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(org_id)
        .bind(site_id)
        .bind(&hostname)
        .bind(&os_family)
        .bind(facts.agent_version.chars().take(50).collect::<String>())
        .bind(token_id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO device_credentials (device_id, algorithm, public_key) VALUES ($1, 'ed25519', $2)")
            .bind(device_id)
            .bind(&public_key)
            .execute(&mut *tx)
            .await?;
        Audit::device(device_id, &hostname, "device.enroll")
            .org(org_id)
            .target("device", device_id)
            .ip(ip)
            .detail(json!({ "enrollment_token": token_id, "key_fingerprint": fingerprint(&public_key) }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Ok((device_id, org_name)))
    }
    .await;
    result.map_err(|e| format!("internal error: {e:#}"))?
}

pub fn fingerprint(public_key: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, public_key);
    format!("SHA256:{}", &hex::encode(d.as_ref())[..16])
}

enum AuthResult {
    Ok { hostname: String, key: Vec<u8> },
    Revoked,
    Failed,
}

async fn authenticate(
    state: &Shared,
    nonce: &[u8],
    device_id: Uuid,
    signature_b64: &str,
) -> anyhow::Result<AuthResult> {
    let Ok(signature) = base64::engine::general_purpose::STANDARD.decode(signature_b64) else {
        return Ok(AuthResult::Failed);
    };
    let creds: Vec<(Vec<u8>, bool, String)> = sqlx::query_as(
        "SELECT c.public_key, c.revoked_at IS NULL AND d.retired_at IS NULL, d.hostname
           FROM device_credentials c JOIN devices d ON d.id = c.device_id
          WHERE c.device_id = $1",
    )
    .bind(device_id)
    .fetch_all(&state.db)
    .await?;
    let message = auth::auth_message(nonce, device_id);
    // Only a key that actually signed this nonce decides the answer, so "revoked" is never
    // disclosed to someone who cannot prove possession of that key.
    for (key, active, hostname) in creds {
        if UnparsedPublicKey::new(&ED25519, &key)
            .verify(&message, &signature)
            .is_ok()
        {
            return Ok(if active {
                AuthResult::Ok { hostname, key }
            } else {
                AuthResult::Revoked
            });
        }
    }
    Ok(AuthResult::Failed)
}

#[allow(clippy::too_many_arguments)]
async fn connected(
    state: &Shared,
    sink: &mut Sink,
    stream: &mut Stream,
    device_id: Uuid,
    hostname: String,
    key: Vec<u8>,
    agent_version: String,
    ip: String,
) -> anyhow::Result<()> {
    // Ordered before any await: if this device connects again while this connection is
    // still setting up, the newer one must win however the registrations interleave.
    let seq = crate::registry::Registry::next_seq();
    let agent_version: String = agent_version.chars().take(50).collect();
    let (tx, mut rx) = mpsc::channel::<ServerMsg>(OUTBOUND_BUFFER);
    let close = CancellationToken::new();
    let conn_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    send(
        sink,
        &ServerMsg::Welcome {
            device_id,
            heartbeat_secs: state.config.heartbeat_secs,
        },
    )
    .await?;
    sqlx::query("UPDATE devices SET last_connected_at = now(), last_seen_at = now(), agent_version = $2 WHERE id = $1")
        .bind(device_id)
        .bind(&agent_version)
        .execute(&state.db)
        .await?;
    Audit::device(device_id, &hostname, "device.connect")
        .target("device", device_id)
        .ip(&ip)
        .detail(json!({ "agent_version": agent_version, "connection": conn_id }))
        .record(&state.db)
        .await?;
    let registered = state.registry.register(
        device_id,
        Conn {
            conn_id,
            seq,
            since: now,
            tx,
            close: close.clone(),
        },
    );
    if !registered {
        return refuse(
            sink,
            RefusalCode::Superseded,
            "a newer connection for this device exists",
        )
        .await;
    }
    // A revocation that committed between authentication and registration would otherwise be
    // missed: its kick found nothing registered. Re-check now that the connection is visible
    // to future kicks (adversarial review finding 3).
    let (still_active,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM device_credentials c JOIN devices d ON d.id = c.device_id
                         WHERE c.device_id = $1 AND c.public_key = $2 AND c.revoked_at IS NULL AND d.retired_at IS NULL)",
    )
    .bind(device_id)
    .bind(&key)
    .fetch_one(&state.db)
    .await?;
    if !still_active {
        state.registry.unregister(device_id, conn_id);
        return refuse(
            sink,
            RefusalCode::Revoked,
            "this device's credential has been revoked",
        )
        .await;
    }
    crate::metrics::CONNECTS.inc();
    tracing::info!(%device_id, %hostname, %conn_id, "agent connected");

    let result = connected_loop(state, sink, stream, &mut rx, &close, device_id, &hostname).await;

    state.registry.unregister(device_id, conn_id);
    let _ = sqlx::query("UPDATE devices SET last_disconnected_at = now() WHERE id = $1")
        .bind(device_id)
        .execute(&state.db)
        .await;
    let reason = match &result {
        Ok(()) => "closed".to_string(),
        Err(e) => format!("{e:#}"),
    };
    let _ = Audit::device(device_id, &hostname, "device.disconnect")
        .target("device", device_id)
        .detail(json!({ "connection": conn_id, "reason": reason }))
        .record(&state.db)
        .await;
    tracing::info!(%device_id, %conn_id, %reason, "agent disconnected");
    result
}

async fn connected_loop(
    state: &Shared,
    sink: &mut Sink,
    stream: &mut Stream,
    rx: &mut mpsc::Receiver<ServerMsg>,
    close: &CancellationToken,
    device_id: Uuid,
    hostname: &str,
) -> anyhow::Result<()> {
    if let Err(e) = jobs::dispatch_pending(state, device_id, jobs::Pass::NewConnection).await {
        tracing::error!(%device_id, error = %format!("{e:#}"), "initial dispatch failed");
    }
    let idle = Duration::from_secs(u64::from(state.config.heartbeat_secs) * 3);
    // A healthy agent sends a handful of messages a minute; a burst beyond this is a fault
    // or an attack, and every message costs a database write.
    let mut window = (tokio::time::Instant::now(), 0u32);
    loop {
        tokio::select! {
            _ = close.cancelled() => {
                let _ = refuse(sink, RefusalCode::Superseded, "connection closed by server").await;
                return Ok(());
            }
            Some(msg) = rx.recv() => send(sink, &msg).await?,
            frame = tokio::time::timeout(idle, stream.next()) => {
                let frame = frame
                    .map_err(|_| anyhow::anyhow!("no message for {idle:?}"))?
                    .ok_or_else(|| anyhow::anyhow!("agent closed the connection"))??;
                if window.0.elapsed() >= Duration::from_secs(1) {
                    window = (tokio::time::Instant::now(), 0);
                }
                window.1 += 1;
                if window.1 > MAX_MESSAGES_PER_SECOND {
                    let _ = refuse(sink, RefusalCode::RateLimited, "too many messages").await;
                    anyhow::bail!("agent exceeded {MAX_MESSAGES_PER_SECOND} messages per second");
                }
                let text = match frame {
                    Message::Text(t) => t,
                    Message::Close(_) => return Ok(()),
                    _ => continue,
                };
                let msg: AgentMsg = match serde_json::from_str(text.as_str()) {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = refuse(sink, RefusalCode::BadMessage, "malformed message").await;
                        anyhow::bail!("malformed agent message: {e}");
                    }
                };
                on_message(state, sink, device_id, hostname, msg).await?;
            }
        }
    }
}

async fn on_message(
    state: &Shared,
    sink: &mut Sink,
    device_id: Uuid,
    hostname: &str,
    msg: AgentMsg,
) -> anyhow::Result<()> {
    match msg {
        AgentMsg::Heartbeat { agent_version, .. } => {
            sqlx::query(
                "UPDATE devices SET last_seen_at = now(), agent_version = $2 WHERE id = $1",
            )
            .bind(device_id)
            .bind(agent_version.chars().take(50).collect::<String>())
            .execute(&state.db)
            .await?;
        }
        AgentMsg::Inventory(report) => store_inventory(state, device_id, *report).await?,
        AgentMsg::Job(report) => {
            let job_id = report.job_id;
            // Any storage failure propagates and drops the connection without an ack; the
            // agent keeps the report and re-sends it on reconnect.
            match jobs::apply_report(state, device_id, hostname, report).await? {
                ReportResult::AckFinal => send(sink, &ServerMsg::ReportAck { job_id }).await?,
                ReportResult::Stored | ReportResult::Foreign => {}
            }
            sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1")
                .bind(device_id)
                .execute(&state.db)
                .await?;
        }
        AgentMsg::Enroll { .. } | AgentMsg::Authenticate { .. } => {
            let _ = refuse(sink, RefusalCode::BadMessage, "already authenticated").await;
            anyhow::bail!("handshake message on an authenticated connection");
        }
    }
    Ok(())
}

async fn store_inventory(
    state: &Shared,
    device_id: Uuid,
    report: InventoryReport,
) -> anyhow::Result<()> {
    let hostname: String = report.hostname.trim().chars().take(255).collect();
    let mut tx = state.db.begin().await?;
    sqlx::query("INSERT INTO inventory_snapshots (device_id, collected_at, source, data) VALUES ($1, $2, 'periodic', $3)")
        .bind(device_id)
        .bind(report.collected_at)
        .bind(serde_json::to_value(&report)?)
        .execute(&mut *tx)
        .await?;
    // Display facts only; organization and identity never come from the device.
    sqlx::query("UPDATE devices SET hostname = CASE WHEN $2 = '' THEN hostname ELSE $2 END, os_family = $3, last_seen_at = now() WHERE id = $1")
        .bind(device_id)
        .bind(&hostname)
        .bind(report.os.family.chars().take(32).collect::<String>())
        .execute(&mut *tx)
        .await?;
    // Bounded history: keep the newest 50 snapshots per device.
    sqlx::query(
        "DELETE FROM inventory_snapshots WHERE device_id = $1 AND id NOT IN
           (SELECT id FROM inventory_snapshots WHERE device_id = $1 ORDER BY received_at DESC LIMIT 50)",
    )
    .bind(device_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
