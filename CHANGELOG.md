# Changelog

All notable changes to flyw8t. Dates are UTC.

## 0.1.0 (unreleased)

First vertical slice. **Not production-ready:** no OIDC or WebAuthn, no signed binaries, attended support not yet cross-family reviewed. See `docs/threat-model.md` § Open items.

### Added
- Two-step verification (TOTP, RFC 6238), required by default (`FLYW8T_REQUIRE_MFA`): partial sessions until the code is given, session rotation, replay refusal, ten single-use recovery codes, attempt limits, account page, administrator reset. Every existing session is signed out by migration 0003.
- Rust workspace: `flyw8t-protocol`, `flyw8t-domain`, `flyw8t-web`, `flyw8t-server`, `flyw8t-agent`.
- Windows agent: Ed25519 device identity, signed-challenge authentication over WSS, durable job journal (at-most-once execution across duplicates, reconnects and crashes), bounded executor, read-only action catalog (`system.info`, `process.top`, `net.ipconfig`, `net.ping`), periodic inventory, Windows service install with restricted state directory, one process per state directory.
- Server: organizations and sites, enrollment tokens, two-dimension job lifecycle (execution + verification) with `outcome_unknown`, bounded redelivery, deadline sweeper, append-only `job_events` and `audit_events`, roles and organization scoping, bearer-token JSON API with idempotency keys, native TLS, `/healthz` `/readyz` `/metrics`.
- Web console (server-rendered Leptos): overview, devices, device detail with live/cached labelling, jobs with full lifecycle, organizations and enrollment, audit, administration.
- Attended support (browser screen view): pairing code and single-use link, explicit consent, WebRTC between browsers, signaling only after consent, short authentication string, instant end from either side.
- Tests: unit, exhaustive state-machine, model-based property test, PostgreSQL end-to-end and adversarial protocol tests, native TLS, STD-008 UI capture, two-browser WebRTC run.
- Docs: architecture, threat model, agent protocol, job lifecycle, reliability, monitoring model, AnchorDesk integration, deployment, roadmap, attended support, ADR-0001 to ADR-0010, TLA+ spec (not yet model-checked).
