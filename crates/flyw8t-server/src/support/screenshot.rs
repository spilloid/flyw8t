//! A participant may separately authorize one named API credential to receive screenshots.
//! Only the owning technician's live browser holds the video. The server forwards an
//! encrypted one-shot reply and stores a metadata receipt to prevent repeat captures.

use super::*;
use crate::auth::ApiUser;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::oneshot;

pub(crate) const BODY_LIMIT: usize = 704 * 1024;
const MAX_CIPHERTEXT: usize = 512 * 1024 + 32;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(12);

fn unavailable(code: &'static str) -> AppError {
    AppError::Conflict(code.into())
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Crop {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

impl Crop {
    fn valid(self) -> bool {
        self.x >= 0.0
            && self.y >= 0.0
            && self.width > 0.0
            && self.height > 0.0
            && self.x + self.width <= 1.0
            && self.y + self.height <= 1.0
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Capture {
    request_id: Uuid,
    public_key: String,
    crop: Option<Crop>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    public_key: String,
    iv: String,
    ciphertext: String,
}

fn valid_public_key(encoded: &str) -> bool {
    encoded.len() == 88
        && STANDARD.decode(encoded).is_ok_and(|key| {
            key.len() == 65 && key[0] == 4 && p256::PublicKey::from_sec1_bytes(&key).is_ok()
        })
}

impl Envelope {
    fn valid(&self) -> bool {
        valid_public_key(&self.public_key)
            && self.iv.len() == 16
            && STANDARD.decode(&self.iv).is_ok_and(|v| v.len() == 12)
            && self.ciphertext.len() <= MAX_CIPHERTEXT.div_ceil(3) * 4
            && STANDARD
                .decode(&self.ciphertext)
                .is_ok_and(|v| (33..=MAX_CIPHERTEXT).contains(&v.len()))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Submission {
    csrf: String,
    grant_id: Uuid,
    envelope: Option<Envelope>,
    error: Option<String>,
}

type Shot = Result<Envelope, &'static str>;

struct Pending {
    id: Uuid,
    tx: Option<oneshot::Sender<Shot>>,
}

#[derive(PartialEq, Eq)]
enum Decision {
    Waiting,
    Allowed,
    Revoked,
}

struct Grant {
    id: Uuid,
    token_id: Uuid,
    recipient: String,
    decision: Decision,
}

#[derive(Default)]
pub(super) struct Grants {
    grant: Option<Grant>,
    pending: Option<Pending>,
}

impl Peers {
    fn usable(&self) -> bool {
        !self.control
            && !self.sealed
            && self.relay_open
            && self.media == [true, true]
            && self.technician.is_some()
            && self.participant.is_some()
    }

    pub(super) fn revoke_screenshots(&mut self) {
        self.screenshots.pending = None; // Close any HTTP rendezvous before notifying the UI.
        if let Some(grant) = &mut self.screenshots.grant {
            grant.decision = Decision::Revoked;
            for peer in [&self.participant, &self.technician].into_iter().flatten() {
                let _ = peer
                    .tx
                    .try_send(Out::ScreenshotRevoked { grant_id: grant.id });
            }
        }
    }

    fn approved(&self, token: Uuid, grant_id: Uuid) -> bool {
        self.usable()
            && self.screenshots.grant.as_ref().is_some_and(|g| {
                g.token_id == token && g.id == grant_id && g.decision == Decision::Allowed
            })
    }

    fn ask(&mut self, token_id: Uuid, recipient: &str) -> AppResult<Uuid> {
        if !self.usable() {
            return Err(unavailable("session_unavailable"));
        }
        match &self.screenshots.grant {
            Some(g) if g.token_id != token_id => Err(unavailable("another_recipient")),
            Some(g) if g.decision == Decision::Allowed => Ok(g.id),
            Some(g) if g.decision == Decision::Revoked => Err(unavailable("screenshot_declined")),
            Some(_) => Err(unavailable("consent_required")),
            None => {
                let id = Uuid::new_v4();
                self.participant
                    .as_ref()
                    .ok_or_else(|| unavailable("session_unavailable"))?
                    .tx
                    .try_send(Out::ScreenshotConsent {
                        recipient: recipient.into(),
                        grant_id: id,
                    })
                    .map_err(|_| unavailable("session_unavailable"))?;
                self.screenshots.grant = Some(Grant {
                    id,
                    token_id,
                    recipient: recipient.into(),
                    decision: Decision::Waiting,
                });
                Err(unavailable("consent_required"))
            }
        }
    }

    fn permission(&mut self, side: Side, conn: Uuid, id: Uuid, allow: bool) -> bool {
        if !self.usable()
            || side == Side::Helper
            || (allow && side != Side::Participant)
            || !self.side(side).as_ref().is_some_and(|p| p.conn_id == conn)
        {
            return false;
        }
        let Some(g) = self.screenshots.grant.as_mut().filter(|g| g.id == id) else {
            return false;
        };
        if !allow && g.decision != Decision::Revoked {
            self.revoke_screenshots();
            return true;
        }
        if allow && g.decision == Decision::Waiting {
            g.decision = Decision::Allowed;
            let msg = Out::ScreenshotAllowed {
                grant_id: id,
                recipient: g.recipient.clone(),
            };
            if [&self.participant, &self.technician]
                .into_iter()
                .flatten()
                .all(|p| p.tx.try_send(msg.clone()).is_ok())
            {
                return true;
            }
            self.revoke_screenshots();
        }
        false
    }
}

pub(super) async fn permission(
    state: &Shared,
    id: Uuid,
    side: Side,
    conn: Uuid,
    who: &Who,
    grant: Uuid,
    allow: bool,
) -> anyhow::Result<()> {
    let changed = state
        .support
        .sessions
        .lock()
        .unwrap()
        .get_mut(&id)
        .is_some_and(|peers| peers.permission(side, conn, grant, allow));
    if changed {
        who.audit("support.screenshot.permission")
            .target("support_session", id)
            .detail(json!({"grant_id": grant, "allow": allow}))
            .record(&state.db)
            .await?;
    }
    Ok(())
}

fn permitted(p: &Principal) -> bool {
    p.role.allows(Permission::RunSupportSessions)
        && p.scopes
            .as_ref()
            .is_some_and(|v| v.iter().any(|s| s == "support:screenshot"))
}

pub(crate) async fn capabilities(ApiUser(p): ApiUser) -> Json<Value> {
    let allowed = permitted(&p);
    Json(json!({ "support_screenshot": allowed, "support_session_status": allowed }))
}

async fn owner_session(state: &Shared, p: &Principal, id: Uuid) -> AppResult<(Uuid, String, bool)> {
    // Both browser and API callers must own this support session and still see its organization.
    let (all, orgs) = p.scope();
    let row: Option<(Uuid, String, bool)> = sqlx::query_as(
        "SELECT organization_id, state, capabilities = ARRAY['view_screen']::text[]
         FROM support_sessions WHERE id = $1 AND created_by = $2 AND organization_id IS NOT NULL
         AND ($3 OR organization_id = ANY($4))",
    )
    .bind(id)
    .bind(p.user_id)
    .bind(all)
    .bind(orgs)
    .fetch_optional(&state.db)
    .await?;
    row.ok_or(AppError::NotFound)
}

async fn owner_org(state: &Shared, p: &Principal, id: Uuid) -> AppResult<Uuid> {
    let (org, status, view_only) = owner_session(state, p, id).await?;
    if status == "connected" && view_only {
        Ok(org)
    } else {
        Err(unavailable("session_unavailable"))
    }
}

pub(crate) async fn session_status(
    State(state): State<Shared>,
    Path(session): Path<Uuid>,
    ApiUser(p): ApiUser,
) -> AppResult<impl IntoResponse> {
    let (token, _) = authorized(&p)?;
    if !state.limiter.allow(
        &format!("support-status:{token}"),
        120,
        Duration::from_secs(60),
    ) {
        return Err(AppError::RateLimited);
    }
    let (_, status, view_only) = owner_session(&state, &p, session).await?;
    let screenshot_access = {
        let sessions = state.support.sessions.lock().unwrap();
        match sessions
            .get(&session)
            .filter(|peers| status == "connected" && view_only && peers.usable())
        {
            None => "unavailable",
            Some(peers) => match &peers.screenshots.grant {
                None => "consent_required",
                Some(g) if g.token_id != token => "unavailable",
                Some(g) => match g.decision {
                    Decision::Waiting => "consent_pending",
                    Decision::Allowed => "allowed",
                    Decision::Revoked => "revoked",
                },
            },
        }
    };
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "session_id": session,
            "state": status,
            "screenshot_access": screenshot_access,
        })),
    ))
}

// Dropping the waiting HTTP future (including a revoked/slow request) frees the single slot.
struct Waiting {
    state: Shared,
    session: Uuid,
    id: Uuid,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut sessions = self.state.support.sessions.lock().unwrap();
        if let Some(peers) = sessions.get_mut(&self.session) {
            if peers
                .screenshots
                .pending
                .as_ref()
                .is_some_and(|p| p.id == self.id)
            {
                peers.screenshots.pending = None;
            }
        }
    }
}

fn authorized(p: &Principal) -> AppResult<(Uuid, &str)> {
    if !permitted(p) {
        return Err(AppError::Forbidden);
    }
    p.api_token
        .as_ref()
        .map(|(id, name)| (*id, name.as_str()))
        .ok_or(AppError::Forbidden)
}

pub(crate) async fn request(
    State(state): State<Shared>,
    Path(session): Path<Uuid>,
    ApiUser(p): ApiUser,
    headers: HeaderMap,
    Json(req): Json<Capture>,
) -> AppResult<Json<Envelope>> {
    if req.request_id.is_nil()
        || !valid_public_key(&req.public_key)
        || req.crop.is_some_and(|c| !c.valid())
    {
        return Err(AppError::BadRequest("invalid_capture_request".into()));
    }
    let (token, recipient) = authorized(&p)?;
    let org = owner_org(&state, &p, session).await?;
    if !state.limiter.allow(
        &format!("support-screenshot:{token}"),
        120,
        Duration::from_secs(60),
    ) {
        return Err(AppError::RateLimited);
    }
    let id = req.request_id;
    let grant = {
        let mut sessions = state.support.sessions.lock().unwrap();
        let peers = sessions
            .get_mut(&session)
            .ok_or_else(|| unavailable("session_unavailable"))?;
        let grant = peers.ask(token, recipient)?;
        if let Some(pending) = &peers.screenshots.pending {
            return Err(unavailable(if pending.id == id {
                "already_requested"
            } else {
                "capture_in_progress"
            }));
        }
        peers.screenshots.pending = Some(Pending { id, tx: None });
        grant
    };
    let _waiting = Waiting {
        state: state.clone(),
        session,
        id,
    };
    // Commit the request ID before publishing to the viewer. Later requests cannot
    // issue another capture, even if this connection or this process disappears.
    let mut tx = state.db.begin().await?;
    let claimed = sqlx::query("INSERT INTO support_screenshot_receipts (session_id, request_id) VALUES ($1,$2) ON CONFLICT DO NOTHING")
        .bind(session).bind(id).execute(&mut *tx).await?.rows_affected();
    if claimed == 0 {
        return Err(unavailable("already_requested"));
    }
    Audit::mcp(&p, "support.screenshot.request")
        .org(org)
        .target("support_session", session)
        .detail(json!({"request_id":id,"grant_id":grant,"tool":"support_screenshot","version":1}))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;

    let (tx, rx) = oneshot::channel();
    {
        let mut sessions = state.support.sessions.lock().unwrap();
        let peers = sessions
            .get_mut(&session)
            .ok_or_else(|| unavailable("session_unavailable"))?;
        if !peers.approved(token, grant) {
            return Err(unavailable("screenshot_revoked"));
        }
        peers
            .technician
            .as_ref()
            .ok_or_else(|| unavailable("session_unavailable"))?
            .tx
            .try_send(Out::ScreenshotCapture {
                request_id: id,
                grant_id: grant,
                public_key: req.public_key,
                crop: req.crop,
            })
            .map_err(|_| unavailable("session_unavailable"))?;
        peers.screenshots.pending = Some(Pending { id, tx: Some(tx) });
    }
    let envelope = tokio::time::timeout(RESPONSE_TIMEOUT, rx)
        .await
        .map_err(|_| unavailable("capture_expired"))?
        .map_err(|_| unavailable("screenshot_revoked"))?
        .map_err(unavailable)?;

    // A credential, tenancy assignment or browser session may have been revoked during capture.
    let fresh = auth::token_principal(&state, &headers)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if authorized(&fresh)?.0 != token || owner_org(&state, &fresh, session).await? != org {
        return Err(AppError::Forbidden);
    }
    let (login, cookie_digest) = state
        .support
        .sessions
        .lock()
        .unwrap()
        .get(&session)
        .filter(|peers| peers.approved(token, grant))
        .and_then(|peers| peers.technician.as_ref()?.browser_session.clone())
        .ok_or_else(|| unavailable("screenshot_revoked"))?;
    if !auth::session_still_valid(&state, login, &cookie_digest).await {
        return Err(unavailable("screenshot_revoked"));
    }
    Audit::mcp(&fresh, "support.screenshot.release_authorized")
        .org(org)
        .target("support_session", session)
        .detail(json!({"request_id":id,"grant_id":grant,"tool":"support_screenshot","version":1}))
        .record(&state.db)
        .await?;
    if !state
        .support
        .sessions
        .lock()
        .unwrap()
        .get(&session)
        .is_some_and(|peers| peers.approved(token, grant))
    {
        return Err(unavailable("screenshot_revoked"));
    }
    Ok(Json(envelope))
}

pub(crate) async fn submit(
    State(state): State<Shared>,
    Path((session, id)): Path<(Uuid, Uuid)>,
    WebUser(p): WebUser,
    headers: HeaderMap,
    Json(s): Json<Submission>,
) -> AppResult<StatusCode> {
    p.require(Permission::RunSupportSessions)?;
    if !same_origin(&state, &headers)
        || p.csrf.is_empty()
        || !crate::web::constant_time_eq(s.csrf.as_bytes(), p.csrf.as_bytes())
    {
        return Err(AppError::Forbidden);
    }
    owner_org(&state, &p, session).await?;
    let reply = match (s.envelope, s.error.as_deref()) {
        (Some(e), None) if e.valid() => Ok(e),
        (None, Some(error)) => Err(match error {
            "no_fresh_frame" => "no_fresh_frame",
            "source_changed" => "source_changed",
            "screenshot_revoked" => "screenshot_revoked",
            "image_too_large" => "image_too_large",
            _ => "capture_failed",
        }),
        _ => return Err(AppError::BadRequest("invalid_screenshot_reply".into())),
    };
    let mut sessions = state.support.sessions.lock().unwrap();
    let peers = sessions
        .get_mut(&session)
        .ok_or_else(|| unavailable("session_unavailable"))?;
    if !peers.usable()
        || p.session_id.is_none()
        || !peers
            .technician
            .as_ref()
            .and_then(|t| t.browser_session.as_ref())
            .is_some_and(|(sid, digest)| {
                Some(*sid) == p.session_id && Some(digest) == p.session_token.as_ref()
            })
        || !peers
            .screenshots
            .grant
            .as_ref()
            .is_some_and(|g| g.id == s.grant_id && g.decision == Decision::Allowed)
    {
        return Err(unavailable("screenshot_revoked"));
    }
    let tx = peers
        .screenshots
        .pending
        .as_mut()
        .filter(|pending| pending.id == id)
        .and_then(|pending| pending.tx.take())
        .ok_or_else(|| unavailable("capture_expired"))?;
    tx.send(reply).map_err(|_| unavailable("capture_expired"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected() -> (Peers, mpsc::Receiver<Out>, mpsc::Receiver<Out>) {
        let (tech, chef, _) = super::super::tests::peer();
        let (part, user, _) = super::super::tests::peer();
        let peers = Peers {
            technician: Some(tech),
            participant: Some(part),
            media: [true, true],
            relay_open: true,
            ..Peers::default()
        };
        (peers, chef, user)
    }

    #[test]
    fn only_the_live_participant_can_grant_a_specific_recipient() {
        let (mut p, mut technician, mut participant) = connected();
        let token = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert!(p.ask(token, "My client").is_err());
        let grant = match participant.try_recv().unwrap() {
            Out::ScreenshotConsent {
                grant_id,
                recipient,
            } => {
                assert_eq!(recipient, "My client");
                grant_id
            }
            _ => panic!("expected consent prompt"),
        };
        assert!(p.ask(token, "My client").is_err());
        assert!(participant.try_recv().is_err());
        let tech = p.technician.as_ref().unwrap().conn_id;
        let user = p.participant.as_ref().unwrap().conn_id;
        assert!(!p.permission(Side::Technician, tech, grant, true));
        assert!(!p.permission(Side::Participant, Uuid::new_v4(), grant, true));
        assert!(!p.permission(Side::Participant, user, Uuid::new_v4(), true));
        assert!(p.permission(Side::Participant, user, grant, true));
        assert!(matches!(
            technician.try_recv(),
            Ok(Out::ScreenshotAllowed { .. })
        ));
        assert!(matches!(
            participant.try_recv(),
            Ok(Out::ScreenshotAllowed { .. })
        ));
        assert_eq!(p.ask(token, "My client").unwrap(), grant);
        assert!(p.ask(other, "My client").is_err());
        let (tx, mut rx) = oneshot::channel();
        p.screenshots.pending = Some(Pending {
            id: Uuid::new_v4(),
            tx: Some(tx),
        });
        assert!(p.permission(Side::Participant, user, grant, false));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(!p.approved(token, grant));
        assert!(!p.permission(Side::Participant, user, grant, true));
        assert!(matches!(
            technician.try_recv(),
            Ok(Out::ScreenshotRevoked { .. })
        ));
        assert!(matches!(
            participant.try_recv(),
            Ok(Out::ScreenshotRevoked { .. })
        ));
        assert!(p.ask(token, "My client").is_err());
        assert!(participant.try_recv().is_err());
    }

    #[test]
    fn control_sealed_disconnected_and_stale_sockets_cannot_establish_a_grant() {
        for state in ["control", "sealed", "no relay", "no peer", "no frames"] {
            let (mut p, _t, mut r) = connected();
            match state {
                "control" => p.control = true,
                "sealed" => p.sealed = true,
                "no relay" => p.relay_open = false,
                "no peer" => p.technician = None,
                _ => p.media[0] = false,
            }
            assert!(p.ask(Uuid::new_v4(), "client").is_err());
            assert!(r.try_recv().is_err());
        }
    }

    #[test]
    fn payload_and_crop_have_bounds() {
        let key = STANDARD.encode(hex::decode("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap());
        assert!(valid_public_key(&key));
        assert!(!valid_public_key(&STANDARD.encode([4; 65])));
        assert!(!valid_public_key(&STANDARD.encode([3; 65])));
        let good = Crop {
            x: 0.25,
            y: 0.25,
            width: 0.75,
            height: 0.5,
        };
        assert!(good.valid());
        assert!(!Crop { width: 0.9, ..good }.valid());
        assert!(!Crop { height: 0., ..good }.valid());
        let mut envelope = Envelope {
            public_key: key,
            iv: STANDARD.encode([0; 12]),
            ciphertext: STANDARD.encode([0; 48]),
        };
        assert!(envelope.valid());
        envelope.ciphertext = STANDARD.encode(vec![0; MAX_CIPHERTEXT + 1]);
        assert!(!envelope.valid());
    }
}
