# ADR-0002: Device identity

**Status:** accepted · **Date:** 2026-10-29

## Context

Each endpoint needs a unique, unforgeable, revocable identity that survives network interruptions and works through common MSP deployments: native TLS, a TLS-terminating reverse proxy, or a private CA.

## Options

| Option | For | Against |
|---|---|---|
| **A. mTLS client certificates** issued by a flyw8t CA | Standard; authentication happens in TLS | Breaks behind TLS-terminating proxies (the most common self-hosted setup) unless the proxy forwards certificates; certificate lifecycle and CRL/OCSP to build; the server would hold a CA key |
| **B. Bearer device secret** issued at enrollment | Simple | A long-lived bearer secret: replayable if captured from logs or a proxy; the server stores something an attacker could use |
| **C. Device-generated Ed25519 key + signed per-connection nonce** | Private key never leaves the device; nothing replayable crosses the wire; works through any proxy that passes WebSockets; the server stores only public keys | Authentication is an application-protocol step, so it needs its own tests |

## Decision

**C.** The agent generates an Ed25519 key at enrollment and proves possession by signing the server's nonce together with a hash of the enrollment token. Every connection begins with a fresh 32-byte nonce, and the agent signs a domain-separated message binding nonce and device id. The server tries each credential on record for the device: an active match succeeds, a revoked match gets `Revoked`, anything else gets `AuthFailed`. TLS (rustls, ring provider) protects confidentiality and authenticates the server; plaintext is permitted only to loopback, as a code rule.

## Consequences

- Revocation is a database update plus closing the live connection; there is no CRL to distribute.
- Key rotation means enrolling a new credential while the old one is still active (the "one active credential" index allows a revoke-then-insert in one transaction). Not built yet.
- A server compromise does not reveal device keys (T10).
- Server identity beyond TLS is not pinned yet (T4 residual).
- Evidence: `replayed_authentication_is_refused`, `enrollment_and_device_revocation`, `agent_enrolls_and_runs_jobs_over_native_tls`.
