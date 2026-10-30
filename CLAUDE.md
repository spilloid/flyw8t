# flyw8t: guidance for AI agents

flyw8t is a self-hosted Rust RMM. Its rule: an operation succeeds **with evidence**, fails **with an explanation**, or reports its outcome as **unknown**. Company memory lives in `../corporate-strategy` (standards, decision log, `state/products/flyw8t.md`).

Read [`docs/architecture.md`](docs/architecture.md), [`docs/job-lifecycle.md`](docs/job-lifecycle.md) and [`docs/threat-model.md`](docs/threat-model.md) before any unit of work.

## Product rules that override convenience

- **No arbitrary execution.** Endpoints run only catalog actions (`flyw8t-protocol::catalog`), validated on the server *and* the agent. Never add a shell, a "run command" action, or a parameter that reaches a command line unvalidated.
- **Never invent success.** Only `domain::job::outcome` decides labels. `completed` comes only from a device report; "Succeeded" needs `verified`. Silence is `outcome_unknown`, never `failed` or `timed_out`.
- **Never "did not run" about something that may have run.** `expired`, pre-dispatch `cancelled` and `NotStarted` must imply zero executions. Retryable declines never re-queue.
- **Never retry automatically.** A person creates a new job.
- **Every job state change goes through `jobs::transition`** under a row lock, and every device report through `domain::job::decide`. Extend the domain table and its exhaustive tests first.
- **Every read query takes the caller's organization scope.** Out of scope is 404, not 403.
- **Tenancy never comes from the device.**
- **Secrets are write-only:** stored hashed, shown once, never logged, never in URLs (except the single-use support invitation, which is spent on first use).
- **Live is not cached.** Connection badges come only from the registry; device-reported data shows its age.
- **Attended support never grants more than consented**, never relays signaling before consent, and never installs anything. Remote control (Phase C) needs the operator's decision first (ADR-0010).
- **Don't build remote desktop from scratch or port MeshAgent** (founding brief; ADR-0006).

## Routing (STD-001)

| Work | Implementer | Reviewer |
|---|---|---|
| Docs, config, boilerplate mirroring a pattern | `codex-luna` or Claude Haiku | Sonnet / Terra |
| Console pages, CLI, collectors | Claude Sonnet / `codex-terra` | the other family |
| Job lifecycle, journal, gateway, auth, tenancy, support signaling, migrations | `codex-sol` (gpt-6.1-sol, high) or Claude Opus | the other family at the top tier, regardless of diff size |
| Release-gate review | — | `codex-astra` (gpt-6-astra, ultra): scarce, review only |

If one family is unavailable, substitute the other's matching tier and log it as same-family. Log every round in [`docs/dev-process.md`](docs/dev-process.md).

## Conventions

- `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace -- --include-ignored` (with `FLYW8T_TEST_DATABASE_URL`), Chrome and Node.js 18+ on PATH before every commit. The default build target is MSVC (`.cargo/config.toml`); pass `--target x86_64-unknown-linux-gnu` for Linux.
- Console changes: run `ui_capture` and **look at the screenshots** in `target/ui-capture/`.
- Prove new checks can fail (mutation check) before trusting them.
- Behavior changes update docs and `CHANGELOG.md` in the same commit (STD-003).
- Commits: no AI attribution lines. Author `Joseph Spillers <jdspille@gmail.com>`.
- Never push, merge, tag or release without the operator's explicit go-ahead.

## Things to re-verify before trusting them

Dated claims that no automated check covers (STD-003 rule 4):

- **2026-10-29**: Docker Compose and the Dockerfile have never been run (no Docker on the development machine). CI builds the image; nobody has signed in to a Compose deployment.
- **2026-10-29**: `flyw8t-agent service install` has never been run (needs an elevated shell). All agent tests run it in-process or in the foreground.
- **2026-10-29**: CI (`.github/workflows/ci.yml`) has never run; nothing has been pushed. The Linux job's assumptions (ping to TEST-NET-1 times out; `ip addr` exists; Chrome at `/usr/bin/google-chrome`) are unverified.
- **2026-10-29**: `docs/spec/JobDelivery.tla` has not been model-checked with TLC.
- **2026-10-29**: Attended support was exercised with headless Chrome's fake screen source on one machine. No NAT, STUN or TURN path, and no second physical machine, has been tried. The security code relies on `RTCDtlsTransport.getRemoteCertificates()`, verified only in Chrome; Firefox and Safari are untested.
- **2026-10-29**: The second-round fixes (dev-process row 15) have not been reviewed. Open from that review: two link posts racing in one browser can bind two support sessions.
- **2026-10-29**: Windows journal-rename durability across power loss is assumed from NTFS journaling, not proven (review finding 10).
- **2026-10-29**: One unidentified protocol-suite failure in six full parallel runs (dev-process row 9).
- **2026-10-29**: Console screenshots are not in the repository. `ui_capture` renders the test machine's real hostname, IP and MAC addresses, so `docs/img/` is git-ignored until captures come from a synthetic device (a fake agent with fabricated inventory).
