# flyw8t architecture

flyw8t is a self-hosted RMM: a small Rust agent on each endpoint and one Rust control plane backed by PostgreSQL. This document describes what exists in **0.1.0** and the seams for what comes next. Status words: **implemented** (exists and is tested), **designed** (decided, not built), **proposed** (open).

## Shape

```text
 Technician browser ──HTTPS──┐                         ┌── AnchorDesk / other integrations
  (server-rendered pages)    │                         │   (Bearer fw8_… tokens, /api/v1)
                             ▼                         ▼
                ┌────────────────────────────────────────────────┐
                │ flyw8t-server (one process)                    │
                │  web console · JSON API · agent gateway        │
                │  job orchestrator · deadline sweeper · /metrics│
                │  in-memory: live connection registry,          │
                │             rate-limit windows (safe to lose)  │
                └──────────────┬─────────────────────────────────┘
                               │ SQL (sqlx, embedded migrations)
                               ▼
                ┌────────────────────────────────────────────────┐
                │ PostgreSQL: the record of truth                │
                │ orgs · users · sessions · tokens · devices ·   │
                │ credentials · inventory · jobs · job_events*   │
                │ audit_events*            (* append-only)       │
                └────────────────────────────────────────────────┘
                               ▲
           WSS, outbound from the endpoint; Ed25519 challenge per connection
                               │
                ┌──────────────┴─────────────────────────────────┐
                │ flyw8t-agent (Windows service; Linux/macOS later)│
                │  connection loop · durable job journal ·       │
                │  bounded executor · compiled-in action catalog │
                └────────────────────────────────────────────────┘
```

No Redis, no queue broker, no Kubernetes requirement, no SaaS dependency. The only stateful dependency is PostgreSQL ([ADR-0004](decisions/ADR-0004-postgres-only-state.md)).

## Workspace

| Crate | Responsibility | Depends on |
|---|---|---|
| `flyw8t-protocol` | Wire messages, the allowlisted action catalog and its validation, inventory types, the exact bytes devices sign. Shared by both ends; no I/O. | serde, uuid, time |
| `flyw8t-domain` | Rules without I/O: the job state machine and report decision, success contracts (evidence), roles and permissions, freshness and the monitoring finding model. | protocol |
| `flyw8t-web` | Server-rendered Leptos views and their view models. Takes plain data, returns HTML; no database. | domain, protocol, leptos (ssr) |
| `flyw8t-server` | Axum app: configuration, authentication, the agent gateway, job orchestration, read queries, web and API handlers, metrics. | all of the above, sqlx, axum |
| `flyw8t-agent` | The endpoint agent: enrollment, identity, journal, executor, collectors, connection loop, Windows service. | protocol |
| `flyw8t-helper` | Native attended-support pairing and consent. Capture/input are still release work. | protocol, TLS/WebSocket libraries |
| `flyw8t-sign` | Offline script-trust statements, approvals and run authorization; the signing key stays outside the server. | protocol, cryptography, CLI |

The founding brief suggested separate `storage` and `integrations` crates. They were folded into server modules ([ADR-0001](decisions/ADR-0001-workspace-shape.md)): storage is a thin layer of SQL next to the code that needs it, and the one integration seam (remote access) is a trait. Splitting them now would add indirection with no second user.

## Trust boundaries

| Boundary | Crossing | Control |
|---|---|---|
| Browser → server | HTTPS (TLS natively or at a proxy; plaintext only for a loopback public URL) | Session cookie (HttpOnly, SameSite=Strict, `__Host-` + Secure when HTTPS), per-session CSRF token on every POST, CSP `default-src 'none'`, no inline script. |
| Integration → server | HTTPS | Bearer `fw8_…` token: SHA-256 at rest, revocable, expiring, scopes that only narrow the owner's role. API accepts bearer tokens only, never cookies. |
| Agent → server | WSS, outbound from the endpoint | Per-connection nonce signed by the device's Ed25519 key; 1 MiB message cap; every report checked against the device that owns the job. Tenancy comes from the enrollment token, never from the device. |
| Server → agent | Same connection | The agent validates every action against its own compiled-in catalog and rejects anything else; there is no shell and no arbitrary command. |
| Server → database | Local network / Compose network | Credentials from the environment; append-only triggers on history tables. |

See [threat-model.md](threat-model.md) for what each control is defending against and what is not yet defended.

## Identity and tenancy (implemented)

- **People:** local accounts (Argon2id), roles `admin` (all organizations), `technician` (assigned organizations: view, run diagnostics, cancel, enroll), `readonly` (assigned organizations: view). No first-visitor setup: the first admin comes only from `FLYW8T_BOOTSTRAP_ADMIN_*`, and only while no users exist. **Two-step verification (TOTP, RFC 6238) is required by default** (`FLYW8T_REQUIRE_MFA`): a correct password yields only a partial session that can reach the code or set-up pages, and finishing the second factor rotates the session secret. Accepted time steps are recorded so a code cannot be replayed; ten single-use recovery codes are stored hashed; an administrator can reset a user's second factor (audited, signs them out). Passkeys (WebAuthn, ES256, user verification required) gate **sudo mode**, a 5-minute per-session step-up required for field definitions, users, API tokens and second-factor resets (`passkeys.rs`, ADR-0014). Passkeys also sign in (`/login/passkey`, usernameless; a passkey that verifies its user is both factors and does not grant sudo mode). Each person lists and signs out their own sessions, and an administrator can sign anyone out everywhere (`sessions.rs`). OIDC is designed, not built (STD-004 three-plane shape; [roadmap](roadmap.md)).
- **Integrations:** personal access tokens acting as their creator, scopes `read` and `jobs:run`. Administration is browser-only.
- **Devices:** an Ed25519 key generated on the device at enrollment; the private half never leaves it. One active credential per device (a unique partial index). Revocation is immediate: the live connection is closed and future handshakes get `Revoked`.
- **Tenancy:** organization → sites. Every read query takes the caller's scope (`$1 OR organization_id = ANY($2)`); anything outside it is a 404, never a 403, so existence does not leak. The database ties each job's organization to its device's organization with a composite foreign key.

## Job execution (implemented)

The center of the product. Summary here; the contract is [job-lifecycle.md](job-lifecycle.md) and the wire format is [agent-protocol.md](agent-protocol.md).

1. **Create:** authorize (scope → role → token scope), validate parameters against the catalog, record `created → authorized → queued` with events and an audit row in one transaction.
2. **Dispatch:** commit `dispatched`, *then* write the offer to the live connection. If the write fails, compensate back to `queued`. The database never says "queued" about a job a device may hold.
3. **Agent:** journal check, then validate, then capacity check, then **journal `Accepted`**, then ack, then journal `Started`, then execute, then journal the result, then report. At most once, across duplicates, reconnects and crashes.
4. **Report:** `domain::job::decide(current_state, report)` returns a legal path; the server applies it under a row lock, evaluates evidence for completions, and acknowledges final reports.
5. **Sweep** (every 5 s): queued past `deliver_by` → `expired`; dispatched past `deliver_by` → `outcome_unknown`; acknowledged or running past `timeout + grace` → `outcome_unknown`; re-offer stale unacknowledged offers and re-send pending cancels.

## Agent (implemented, Windows x64 first)

- Single binary: `enroll`, `run` (foreground), `status`, `service install|uninstall|run`.
- Windows service: automatic start, LocalSystem, restart-on-failure actions (also for a non-crash failure). `enroll` creates the state folders (which hold the private key) owned by Administrators and open only to SYSTEM and Administrators, in the same call that creates them (`winsec.rs`); `service install` copies the agent to Program Files and registers that copy. Existing folders are checked and refused, never repaired. The service logs to `logs\agent.log` in the state folder. Run for real once on Windows 11 ([deployment.md](deployment.md), dev-process row 36); a reboot is not yet checked.
- Bounded everywhere: 2 concurrent jobs, a 256-entry report buffer, 256 KiB per output stream, 1 MiB per message, 30 s connect and handshake deadlines, backoff from 1 s capped at 60 s with jitter.
- Actions are compiled Rust. Child processes are fixed absolute paths (`%SystemRoot%\System32\…`) with argument vectors built from validated parameters, `CREATE_NO_WINDOW`, stdin closed, kill on timeout or cancel or drop. No shell anywhere.
- Endpoint support remains Windows-first today. Linux collector/action paths are exercised in CI but do not constitute a supported Linux endpoint release. The accepted [1.0 contract](roadmap.md) requires macOS alongside Windows, with Mac permission/session experiments starting at 0.2; Linux endpoint delivery is deferred. Mac packaging and native capture/input still need implementation and physical-machine evidence.

## Web console (implemented)

Server-rendered Leptos (SSR only, no WASM yet: [ADR-0003](decisions/ADR-0003-web-ui-ssr-first.md)). Every page is complete HTML that works without JavaScript; in-flight job pages refresh themselves with a meta refresh until the job is final. Live data and cached data are labelled differently: a connection badge comes from the live registry, and inventory says "reported by the device, collected …, cached, not live" with a freshness badge. Navigation shows only what exists: Overview, Devices, Organizations, Jobs, Support (technicians and admins), plus Audit and Administration for admins. Monitoring, Scripts and Automations from the founding brief are on the [roadmap](roadmap.md) rather than shown as empty pages.

Validated by `tests/ui_capture.rs` (STD-008): 16 pages × 3 widths × 2 color schemes in headless Chrome, failing on horizontal overflow or any browser error.

## Attended support (implemented: browser screen view)

`support.rs` pairs a technician's browser with a participant's browser through a 9-digit code or single-use link, records consent, and relays WebRTC signaling between exactly two sockets, and only after consent. Media flows browser to browser (DTLS-SRTP); the server never sees it. Sessions have their own state machine (`domain::support`) and append-only `support_events`. The support pages are the console's only pages with script (`/static/support.js`, same-origin, no inline script; [ADR-0010](decisions/ADR-0010-attended-support.md)). Details and the threat analysis: [attended-support.md](attended-support.md).

## Remote access (seam only)

`remote_access::RemoteAccessProvider` is an optional external-provider seam with a `NotConfigured` default that plainly reports that control is unavailable in this build. The MeshCentral-first plan is superseded: [ADR-0013](decisions/ADR-0013-unattended-access.md) requires our shared native engine for attended and unattended control. That engine is release work, not an implemented property of this trait. Providers never supply device identity or tenancy. Browser screen view and native helper pairing are described in [attended-support.md](attended-support.md).

## Observability (implemented, minimal)

- `/healthz` (process alive), `/readyz` (database answers), `/metrics` (Prometheus text: jobs by state and verification, enrolled devices, connected agents, process start time, connects, sweep successes and failures).
- `tracing` structured logs; secrets are never logged (tokens are logged only as prefixes in audit rows).
- Reliability targets and how they are measured: [reliability.md](reliability.md).

## What one instance can and cannot do

The registry and rate limiter are in memory, so **one server process serves all agents**. Running two would split connections between registries, and a job created on instance A for a device connected to B would wait for the sweeper on B. The fix (Postgres `LISTEN/NOTIFY` to wake the owning instance, plus a shared rate-limit store) is designed in [ADR-0009](decisions/ADR-0009-availability-and-scale-out.md). That ADR also explains why a single instance cannot honestly promise 99.99 % availability.
