# Changelog

All notable changes to flyw8t. Dates are UTC.

## 0.1.0 (unreleased)

First vertical slice. **Not production-ready:** no OIDC or WebAuthn, no signed binaries; the attended-support and MFA fixes from cross-family review have not been re-reviewed. See `docs/threat-model.md` § Open items.

### Added
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
- Every console form post from a real browser was refused as cross-origin: `Referrer-Policy: no-referrer` makes browsers send `Origin: null`, which the cross-origin check refuses. The policy is now `same-origin`, and the Chrome test signs in through the real form.
- Two-step verification hardening after cross-family review: factor checks lock the user and the presented session in the same transaction; setting up or turning off the second factor rotates this session and signs out every other; an administrator's reset also ends the user's live support sessions.
