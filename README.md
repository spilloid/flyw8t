# flyw8t

**Lightweight agents. Heavyweight control.** *(pronounced "flyweight")*

flyw8t is a self-hosted remote monitoring and management (RMM) platform for MSP technicians, written in Rust. Its defining rule:

> An operation either succeeds **with evidence**, fails **with an explanation**, or explicitly reports that its outcome is **unknown**. Never pretend otherwise.

**Version 0.1.0, pre-release. Not production-ready.** No OIDC or WebAuthn yet (TOTP two-step verification is built and required by default), binaries are unsigned, and the attended-support code has not had an independent security review. See [docs/threat-model.md](docs/threat-model.md#open-items-before-production).

## What works today

- **Windows agent** (Rust, Windows service). One outbound TLS WebSocket; a device key that never leaves the device; a durable journal that makes job execution **at most once** across duplicate deliveries, reconnects, server restarts and agent crashes.
- **Read-only diagnostics** from a compiled-in catalog (`system.info`, `process.top`, `net.ipconfig`, `net.ping`). No shell and no arbitrary commands; the agent enforces the catalog itself.
- **Honest job outcomes.** Execution state and verification are separate. "Succeeded" means the device ran it *and* its evidence satisfied the action's success contract. A device that goes silent produces `outcome_unknown`, never a guess.
- **Web console** (server-rendered Leptos, works without JavaScript): devices with live-vs-cached labelling, jobs with their full lifecycle, organizations and enrollment, audit history, administration.
- **Attended support:** send a code, the person consents in their browser, and you see the tab or screen they choose, with no install. Screen view only; no control.
- **JSON API** with scoped bearer tokens and idempotency keys, for integrations such as AnchorDesk.
- **Self-hosted:** one binary plus PostgreSQL. No Redis, no broker, no SaaS.

## How it is checked

```sh
cargo test --workspace                                   # unit, state machine, model-based property test
export FLYW8T_TEST_DATABASE_URL=postgres://user:pass@127.0.0.1:5432/postgres
cargo test --workspace -- --include-ignored              # + PostgreSQL end-to-end, protocol, TLS, UI capture, two-browser WebRTC
```

The suite includes real agents running real Windows commands against a real server, deliberate crashes mid-job, a model-based test that drives the real journal and the real state machine through thousands of random sequences of lost, duplicated and reordered messages, and headless-Chrome checks of every page at three widths in light and dark. How each reliability claim is backed is in [docs/reliability.md](docs/reliability.md), and what the tests found is in [docs/dev-process.md](docs/dev-process.md).

## Try it

```sh
# Server (PostgreSQL required)
export FLYW8T_DATABASE_URL=postgres://flyw8t:secret@127.0.0.1:5432/flyw8t
export FLYW8T_PUBLIC_URL=http://localhost:8080
export FLYW8T_BOOTSTRAP_ADMIN_EMAIL=admin@example.com FLYW8T_BOOTSTRAP_ADMIN_PASSWORD='a-long-password'
cargo run -p flyw8t-server
# Sign in at http://localhost:8080 → Organizations → create one → Create enrollment token

# Agent, on the same Windows machine (foreground)
cargo run -p flyw8t-agent -- --state-dir .\agent-state enroll --server http://localhost:8080 --token fw8e_…
cargo run -p flyw8t-agent -- --state-dir .\agent-state run
```

Docker Compose and production notes (TLS, backups, Windows service): [docs/deployment.md](docs/deployment.md).

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | Components, trust boundaries, what one instance can and cannot do |
| [Job lifecycle](docs/job-lifecycle.md) | The state machine and every failure behavior |
| [Agent protocol](docs/agent-protocol.md) | Wire format, authentication, delivery guarantees |
| [Threat model](docs/threat-model.md) | Threats, controls, evidence, open items |
| [Reliability](docs/reliability.md) | Correctness properties, availability targets, measurement |
| [Attended support](docs/attended-support.md) | Consent model, WebRTC design, status, two-browser demo |
| [AnchorDesk integration](docs/anchordesk-integration.md) | Using flyw8t as an AnchorDesk RMM provider |
| [Roadmap](docs/roadmap.md) · [Decisions](docs/decisions/) · [Acceptance tests](docs/acceptance-tests.md) | |

## License

MIT. See [LICENSE](LICENSE).
