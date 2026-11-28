# flyw8t: guidance for AI agents

flyw8t is a self-hosted Rust RMM. Its rule: an operation succeeds **with evidence**, fails **with an explanation**, or reports its outcome as **unknown**. Company memory lives in `../corporate-strategy` (standards, decision log, `state/products/flyw8t.md`).

Read [`docs/architecture.md`](docs/architecture.md), [`docs/job-lifecycle.md`](docs/job-lifecycle.md) and [`docs/threat-model.md`](docs/threat-model.md) before any unit of work.

## AnchorDesk work tracking

Use the configured AnchorDesk MCP at `https://tickets.spillerstech.us/mcp/sse` for ongoing Flyw8t work. Look up the relevant ticket when resuming and record decisions, blockers, and verification evidence there as work progresses. The 0.3.0 release checklist lives on ticket **#10207** in [AnchorDesk](https://tickets.spillerstech.us/).

Log actual work through the MCP `log_time` tool using measured start and stop times. Leave idle gaps out of the time entry. Mark a checklist item complete when its acceptance evidence is available, and record partial results on the ticket.

## Product rules that override convenience

- **Validate job execution on the server and agent.** Built-in jobs use typed catalog actions (`flyw8t-protocol::catalog`). Script jobs follow the signed-script trust rules. The interactive background terminal may accept ordinary PowerShell input from a technician in a live, authorized session on an opted-in device. See [Background terminal](docs/background-terminal.md#authorization-and-audit).
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

- **2026-11-15**: Dev-process row 45. The CSV formula guard in the audit export follows OWASP's advice and was not tried in a spreadsheet program. The real-NetViz-probe test (`tests/network.rs`) runs only where `FLYW8T_NETVIZ_PROBE` points at a built probe; CI has none, so there it prints SKIPPED and checks nothing. `FLYW8T_FAMILY_LINKS` is read once per process (the first server started), which only tests can notice. The network sprint (row 44) has had one reader from the other family, not an adversarial review.
- **2026-11-16 update to 2026-11-14**: The release workflow's `image` job first ran for `v0.1.2` (dev-process row 43); `v0.1.3` was later published with pinned image digest `ef35d845e3dc068c15a6a3c40b63370ee09c62be0175ed217996d13c1095694f`, and the beta is running at `https://flyw8t.spillerstech.us`. A physical Windows 0.1.3 agent has enrolled and reported one check-in and inventory. This does not establish a real job or reboot pass. Downloaded 0.1.3 Windows binaries verified with timestamped Authenticode signatures and reported `--version` 0.1.3 (dev-process row 47); install-time publisher verification remains open. The 0.1.2 review fixes (row 41) and two test fixes (row 42) have not been reviewed. The 50,000-device scan was tested with 2,001 rows, not at that size.
- **2026-11-16**: The 0.1.4 pre-release and deployment checks are recorded in rows 52/53. That staging previously returned HTTP 422 for a valid-HTTPS OIDC provider because of the Rustls root-store bug. The 0.1.5 hotfix is published and deployed; pre-auth OIDC redirect checks now pass, but no interactive user SSO/MFA login is verified. Release workflow 43798720717 passed all four jobs. All five assets were downloaded and four binary checksums match; both Windows signatures are valid and both binaries report 0.1.5. Linux downloads were not executed here; the published image is unsigned (`sha256:8b38f6969737e0931a0eadb5c2a5924b2a8579fd9534df297a79ec3dfc578877`). A disposable strict-HTTPS client passed public provider discovery/JWKS, which proves compatibility only, not login. Normal updater run 43800647759 completed successfully and reported `already on 0.1.5`, with no redundant commit (row 56). SCIM has three users, two groups and two inactive synthetic tombstones; no human credentials or MFA were changed. The post-upgrade backup completed, but no restore or offsite recovery is claimed. Interactive user SSO/MFA has no response yet; hardware passkey, reboot and real-job checks remain open. Claude Opus cross-family review returned weekly-limit HTTP 429 with no usable findings; Astra is the explicit same-family substitute.
- **2026-11-12, updated 2026-11-16**: Compose startup, real password/TOTP sign-in, organization creation and dump/restore into an empty database passed in CI at `a48f7e6` (run 43171178365). Docker is still unavailable on this Windows host. A physical Windows 0.1.3 agent has since enrolled and reported one check-in and inventory; enrollment against the Compose deployment, reboot and real-job checks remain unproven. Off-host recovery and encryption/root-key recovery remain open; the CI round-trip does not prove them. A fresh CNPG backup completed on 2026-11-16; no offsite backup or restore drill is claimed.
- **2026-11-07, updated 2026-11-16**: `flyw8t-agent enroll` and `service install` have been run for real (Windows 11; dev-process row 36): refusals, uninstall from the installed copy, restart after a kill, owners and permissions, the log, and DLL planting. The physical Windows 0.1.3 agent has also enrolled and reported a check-in plus inventory. Reboot survival, a real job, and the clean exit-1 path (revoked credential) remain unverified. Downloaded 0.1.3 Windows binaries were Authenticode-verified and ran `--version` successfully (row 47); install-time publisher verification is still open.
- **2026-11-12**: Main CI ran successfully at `ff67d58` (GitHub run 43048263310, 2026-11-11). Earlier "CI has never run" notes were stale. New branches still need their own exact-ref results; a green main run does not validate unmerged script execution.
- **2026-10-29**: `docs/spec/JobDelivery.tla` has not been model-checked with TLC.
- **2026-10-29**: Attended support was exercised with headless Chrome's fake screen source on one machine. No NAT, STUN or TURN path, and no second physical machine, has been tried. The security code relies on `RTCDtlsTransport.getRemoteCertificates()`, verified only in Chrome; Firefox and Safari are untested.
- **2026-10-30**: The round-4 fixes (dev-process row 16) have not been reviewed. Still open from row 15: two link posts racing in one browser can bind two support sessions.
- **2026-11-12**: Journal regressions inject temporary-file creation failures and a Windows rename sharing violation, checking unchanged memory/disk, repeat failure and recovery. Corrupt/mismatched/legacy-quarantined history now blocks startup and remains preserved. Actual disk exhaustion and Windows power-loss durability remain unproven (G02-DURABILITY); error injection does not close those drills.
- **2026-10-30**: The protocol-suite flake (dev-process row 9) was identified and fixed; watch CI for any recurrence.
- **2026-11-04**: Passkeys were exercised only with Chrome's DevTools virtual authenticator and a software key in the router tests. No hardware security key, Windows Hello, Touch ID, synced passkey, Firefox or Safari has been tried.
- **2026-11-06**: Passkey sign-in (usernameless, `allowCredentials` empty) was exercised with the software key in the router tests and in Chrome with DevTools' virtual authenticator (a discoverable key). It needs a discoverable credential; whether a given security key or platform stored one at registration (`residentKey: "preferred"`) has not been checked on real hardware.
- **2026-10-29**: Console screenshots are not in the repository. `ui_capture` renders the test machine's real hostname, IP and MAC addresses, so `docs/img/` is git-ignored until captures come from a synthetic device (a fake agent with fabricated inventory).
