# Changelog

All notable changes to flyw8t. Dates are UTC.

## Unreleased

### Added
- Running behind Cloudflare Tunnel or a reverse proxy: `FLYW8T_TRUSTED_PROXIES` and `FLYW8T_CLIENT_IP_HEADER` make rate limits and the audit log use each client's real address, believed only from the configured proxies. The Compose file gains an optional `tunnel` profile (cloudflared 2026.9.3, pinned) on a fixed internal network.
- Windows release binaries are Authenticode-signed (Azure Artifact Signing) and verified before publishing; a dry-run **Signing check** workflow; `scripts/verify-signature.ps1` for anyone checking a download. Needs the one-time `scripts/setup-signing.ps1` before the next tag.
- Remote control, server side (ADR-0012 step 1): sessions can request `control_input` (new `RunControlSessions` permission). The browser's Allow moves to `awaiting_helper`; downloading the helper (`/s/helper/download`, bound browser only) mints a single-use, 2-minute launch token carried only in the file name. The helper attaches with that token (`/api/support/helper/ws`) and must be allowed in its own window before anything is relayed. In a control session the helper, not the browser, is the technician's media peer, and `connected` needs both of them. Migration 0005. No helper binary yet.

### Fixed
- When an administrator's reset and a technician socket's own sign-in recheck raced to end the same support session, the losing socket could close without the "ended" notice (seen once in Linux CI). It now waits briefly for that notice.

## 0.1.1 — 2026-10-30 (pre-release)

### Added
- The console installs to a phone's home screen as a standalone app (ADR-0011, accepted): web app manifest, regular and maskable icons, an Apple touch icon and a theme colour. `manifest-src 'self'` added to the content security policy. No script and no offline data.

### Fixed
- Review round 4 (dev-process row 16): support sockets end when their technician's account is disabled; the global wrong-code budget refunds only the window a place was taken from; origins are compared in canonical form, so a public URL with `:443` or `:80` works.
- The attended-support security code no longer falls back to "not available" when the browser reports the DTLS certificate a moment after the connection (seen intermittently on Linux CI).
- A device that reconnected while its previous connection was still being set up could lose its new connection to the old one, leaving it on a stale connection. Connections are now ordered by authentication, and the newest always wins (found by Linux CI; this was the protocol-suite flake open since 0.1 development).

## 0.1.0 — 2026-10-30 (pre-release)

First vertical slice. **Not production-ready:** no OIDC or WebAuthn, no signed binaries; two cross-family review rounds on attended support and MFA are fixed, but the second round's fixes are not yet reviewed. See `docs/threat-model.md` § Open items.

### Added
- Decisions (2026-10-30): flyw8t stands alone and will later be a first-class AnchorDesk RMM provider; attended remote control (Phase C) approved (ADR-0010 accepted); mobile administration accepted as a goal (ADR-0011, approach proposed).
- Attended support hardening after cross-family review: only the session's creator can attach (administrators observe and end); sessions belong to an organization; pages stop capture themselves when the server connection is lost, on End, on leaving the page, or when the picker is answered after the end; signaling sealed before an ending commits, with a final notice a full queue cannot drop; `connected` needs both sides; per-socket message limit; race-free per-technician cap; Argon2id-hashed codes and a global wrong-code budget; opening a link spends nothing; one live session per browser; failed attempts, attaches and endings audited by who caused them. Migration 0004.
- Two-step verification (TOTP, RFC 6238), required by default (`FLYW8T_REQUIRE_MFA`): partial sessions until the code is given, session rotation, replay refusal, ten single-use recovery codes, attempt limits, account page, administrator reset. Every existing session is signed out by migration 0003.
- Rust workspace: `flyw8t-protocol`, `flyw8t-domain`, `flyw8t-web`, `flyw8t-server`, `flyw8t-agent`.
- Windows agent: Ed25519 device identity, signed-challenge authentication over WSS, durable job journal (at-most-once execution across duplicates, reconnects and crashes), bounded executor, read-only action catalog (`system.info`, `process.top`, `net.ipconfig`, `net.ping`), periodic inventory, Windows service install with restricted state directory, one process per state directory.
- Server: organizations and sites, enrollment tokens, two-dimension job lifecycle (execution + verification) with `outcome_unknown`, bounded redelivery, deadline sweeper, append-only `job_events` and `audit_events`, roles and organization scoping, bearer-token JSON API with idempotency keys, native TLS, `/healthz` `/readyz` `/metrics`.
- Web console (server-rendered Leptos): overview, devices, device detail with live/cached labelling, jobs with full lifecycle, organizations and enrollment, audit, administration.
- Attended support (browser screen view): pairing code and single-use link, explicit consent, WebRTC between browsers, signaling only after consent, committed security code over the DTLS certificates in use, instant end from either side.
- Tests: unit, exhaustive state-machine, model-based property test, PostgreSQL end-to-end and adversarial protocol tests, native TLS, STD-008 UI capture, two-browser WebRTC run.
- Docs: architecture, threat model, agent protocol, job lifecycle, reliability, monitoring model, AnchorDesk integration, deployment, roadmap, attended support, ADR-0001 to ADR-0010, TLA+ spec (not yet model-checked).

### Fixed
- Linux CI: a support socket cut off for flooding now closes cleanly, so the client always receives the reason (it could be lost to a connection reset).
- Second-round review fixes: the security code is bound to the single transport carrying the shown video; support sockets end when the browser session that opened them is signed out, revoked or rotated; reset and endings decide their transition under the row lock; the global code budget is reserved before work; late asynchronous WebRTC steps cannot act after an ending; socket writes are bounded; turning MFA off rotates the session; the configured public origin is accepted behind a proxy that rewrites `Host`.
- Every console form post from a real browser was refused as cross-origin: `Referrer-Policy: no-referrer` makes browsers send `Origin: null`, which the cross-origin check refuses. The policy is now `same-origin`, and the Chrome test signs in through the real form.
- Two-step verification hardening after cross-family review: factor checks lock the user and the presented session in the same transaction; setting up or turning off the second factor rotates this session and signs out every other; an administrator's reset also ends the user's live support sessions.
