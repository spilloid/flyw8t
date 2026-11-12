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
- **Attended support never grants more than consented**, never relays signaling before consent, and never installs anything. Remote control (Phase C) is approved (ADR-0010) and needs its own, separate consent for input.
- **Build remote control on our shared engine**, not MeshCentral or a MeshAgent port (ADR-0012/0013). Operator-approved release scope (2026-11-12): Windows and macOS endpoints, native attended/unattended control, Windows UAC and sign-in screens at 1.0; Linux hosts the server/console. Android endpoints and mobile technician administration gate 1.5; iOS is conditional. Linux endpoints are outside 1.0. Follow the evidence gates in `docs/roadmap.md`; consent and endpoint policy remain mandatory.

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

- **2026-11-12**: Compose startup, real password/TOTP sign-in, organization creation and dump/restore into an empty database passed in CI at `a48f7e6` (run 43171178365). Docker is still unavailable on this Windows host. Physical Windows enrollment against that deployment, off-host recovery and encryption/root-key recovery remain open gates; the CI round-trip does not prove them.
- **2026-11-07**: `flyw8t-agent enroll` and `service install` have been run for real (Windows 11, elevated through Windows `sudo` in Inline mode; each elevated step is one UAC prompt the operator must click, so batch them in one script and ask first; dev-process row 36): refusals, uninstall from the installed copy, restart after a kill, owners and permissions, the log, DLL planting. **Not** checked yet: surviving a reboot, and the clean exit-1 path (revoked credential) now that restart-on-non-crash-failure is set. The file `install` copies is not authenticated against the running image until releases are signed.
- **2026-11-12**: Main CI ran successfully at `ff67d58` (GitHub run 43048263310, 2026-11-11). Earlier "CI has never run" notes were stale. New branches still need their own exact-ref results; a green main run does not validate unmerged script execution.
- **2026-10-29**: `docs/spec/JobDelivery.tla` has not been model-checked with TLC.
- **2026-10-29**: Attended support was exercised with headless Chrome's fake screen source on one machine. No NAT, STUN or TURN path, and no second physical machine, has been tried. The security code relies on `RTCDtlsTransport.getRemoteCertificates()`, verified only in Chrome; Firefox and Safari are untested.
- **2026-10-30**: The round-4 fixes (dev-process row 16) have not been reviewed. Still open from row 15: two link posts racing in one browser can bind two support sessions.
- **2026-11-12**: Journal regressions inject temporary-file creation failures and a Windows rename sharing violation, checking unchanged memory/disk, repeat failure and recovery. Corrupt/mismatched/legacy-quarantined history now blocks startup and remains preserved. Actual disk exhaustion and Windows power-loss durability remain unproven (G02-DURABILITY); error injection does not close those drills.
- **2026-10-30**: The protocol-suite flake (dev-process row 9) was identified and fixed; watch CI for any recurrence.
- **2026-11-04**: Passkeys were exercised only with Chrome's DevTools virtual authenticator and a software key in the router tests. No hardware security key, Windows Hello, Touch ID, synced passkey, Firefox or Safari has been tried.
- **2026-11-06**: Passkey sign-in (usernameless, `allowCredentials` empty) was exercised with the software key in the router tests and in Chrome with DevTools' virtual authenticator (a discoverable key). It needs a discoverable credential; whether a given security key or platform stored one at registration (`residentKey: "preferred"`) has not been checked on real hardware.
- **2026-10-29**: Console screenshots are not in the repository. `ui_capture` renders the test machine's real hostname, IP and MAC addresses, so `docs/img/` is git-ignored until captures come from a synthetic device (a fake agent with fabricated inventory).
