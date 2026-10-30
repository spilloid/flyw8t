# ADR-0010: Attended support

**Status:** proposed (Phase B direction accepted for implementation; Phase C needs the operator's decision) · **Date:** 2026-10-29

## Context

A later operator brief asks for zero-configuration attended support: a technician sends a code, the user consents in a browser, and the technician sees (and eventually controls) the screen, with no VPS, port forwarding or persistent install. The founding brief says MeshCentral is the preferred remote-access backend and not to build remote desktop from scratch.

## Decision

1. **Phase B (browser screen view) is consistent with both briefs.** It adds no remote-control capability, uses the browser's own capture APIs and consent, and needs no agent. It reuses flyw8t's auth, audit, rate limiting and console. The flyw8t server is the signaling and pairing service; media is WebRTC (DTLS-SRTP, end-to-end), with optional STUN/TURN configured by the operator. Default: no third-party servers.
2. **The console's no-script rule ([ADR-0003](ADR-0003-web-ui-ssr-first.md)) gets one scoped exception:** the support pages load a same-origin script (`/static/support.js`), because WebRTC and `getDisplayMedia` exist only as browser JavaScript APIs. The CSP for those pages adds `script-src 'self'` and `connect-src 'self'`, still with no inline script and no third-party origins.
3. **Signaling tampering is detected, not assumed away:** both pages show a security code derived from the DTLS certificates actually in use, with the technician committing to its certificate before the participant offers (amended 2026-10-29 after cross-family review: the first version hashed SDP fingerprints, which a relay could pad). It cannot protect against a compromised flyw8t server, which serves the page script; see attended-support.md § Security code.
4. **Phase C (native helper with input injection) is deferred** pending an operator decision. It conflicts with "don't build remote desktop from scratch". The alternatives are MeshCentral's own attended-session features through the provider seam ([ADR-0006](ADR-0006-remote-access-provider.md)), or building a narrow, consent-first helper as a distinct product. That choice affects scope and cost and is the operator's to make.

## Consequences

- One more WebSocket surface on the server: signaling for support sessions, separate from the agent gateway and sharing no credentials with it.
- Browser screen view works LAN-direct with no configuration; across NATs it needs STUN, and on restrictive networks TURN. Without TURN, some sessions will fail with `connection_failed`, and the UI must say why, not hang.
