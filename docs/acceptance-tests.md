# Acceptance tests

The founding milestone, as executable checks. **Automated** means a test in this repository runs it against a real PostgreSQL and a real agent executing real Windows commands. Run:

```sh
# PostgreSQL reachable by a role that may CREATE DATABASE
export FLYW8T_TEST_DATABASE_URL=postgres://flyw8t:devpass@127.0.0.1:55432/postgres
cargo test --workspace -- --include-ignored
```

Status as of 2026-10-29, on Windows 11 x64 with PostgreSQL 18.6:

| ID | Milestone step | How | Status |
|---|---|---|---|
| AT-01 | Start PostgreSQL and the server with Docker Compose | `deploy/compose/` | **Not verified.** No Docker on the development machine; the Compose file and Dockerfile are written but have never run. CI builds the image. |
| AT-02 | Serve the Rust web UI | `vertical_slice`, `ui_capture` | Automated |
| AT-03 | Authenticate as an administrator | `vertical_slice` (bootstrap admin, sign-in) | Automated |
| AT-04 | Create an organization | `vertical_slice` | Automated |
| AT-05 | Generate a short-lived enrollment credential | `vertical_slice`, `enrollment_and_device_revocation` | Automated |
| AT-06 | Enroll one Windows x64 endpoint | `vertical_slice` (agent library, same machine) | Automated, **in-process.** The installed Windows service path (`service install`) has not been run; it needs an elevated shell. |
| AT-07 | Authenticated agent connection | `vertical_slice`, `replayed_authentication_is_refused` | Automated |
| AT-08 | Endpoint shown in device inventory | `vertical_slice` | Automated |
| AT-09 | Hardware and OS information | `vertical_slice` (periodic inventory + `system.info` job) | Automated |
| AT-10 | Submit an allowlisted read-only diagnostic | `vertical_slice` (`net.ipconfig`, `system.info`) | Automated |
| AT-11 | Collect output and lifecycle events | `vertical_slice` asserts the event sequence and real ipconfig output | Automated |
| AT-12 | Persist results | `vertical_slice`, `server_restart_preserves_queued_work` | Automated |
| AT-13 | Disconnect and reconnect | `reconnect_and_duplicate_delivery_never_reexecutes`, `disconnected_device_is_not_shown_as_live` | Automated |
| AT-14 | Duplicate delivery cannot silently re-execute | `reconnect_and_duplicate_delivery_never_reexecutes`; model test | Automated |
| AT-15 | Show the actual outcome and audit history | `vertical_slice` (job page "Succeeded", audit page, append-only enforced) | Automated |

Beyond the milestone:

| ID | Behavior | Test |
|---|---|---|
| AT-16 | Agent crash mid-job → `outcome_unknown`, never re-run | `agent_crash_mid_job_is_outcome_unknown_and_not_rerun` |
| AT-17 | Server restart preserves queued work | `server_restart_preserves_queued_work` |
| AT-18 | Cancel before dispatch never runs; cancel while running stops it | `cancellation_before_and_during_execution` |
| AT-19 | Undeliverable job expires and says it did not run | `undeliverable_job_expires_without_claiming_execution` |
| AT-20 | Tenant isolation; token scopes only narrow; CSRF; idempotency keys | `tenant_isolation_and_token_scopes` |
| AT-21 | Enrollment token single-use, expiry, revocation; revoked device cannot connect | `enrollment_and_device_revocation` |
| AT-22 | A disconnected device is never shown as live | `disconnected_device_is_not_shown_as_live` |
| AT-23 | Silent device → `outcome_unknown` → late result resolves it | `silent_device_becomes_unknown_then_late_result_resolves` |
| AT-24 | A device cannot report another device's job | `device_cannot_report_another_devices_job` |
| AT-25 | Unacknowledged delivery past deadline is unknown, not expired | `unacknowledged_delivery_is_unknown_not_expired` |
| AT-26 | Hostile frames close the connection; server keeps serving | `hostile_frames_close_the_connection` |
| AT-27 | Replayed authentication refused | `replayed_authentication_is_refused` |
| AT-28 | Every console page (16) renders without overflow or browser errors at 3 widths × 2 themes | `ui_capture` (needs Chrome) |
| AT-29 | At-most-once and eventual resolution under random faults | `crates/flyw8t-agent/tests/model.rs` |
| AT-30 | Native TLS end to end; an agent without the CA cannot connect | `agent_enrolls_and_runs_jobs_over_native_tls` |
| AT-31 | Repeated device reports are bounded; message bursts are cut off | `repeated_reports_are_counted_not_logged_and_bursts_are_cut_off` |
| AT-32 | Cross-origin form posts (login CSRF) refused | `cross_origin_posts_are_refused` |
| AT-33 | One agent process per state directory | `one_process_per_state_directory` |
| AT-34 | Attended support: consent before signaling, single-use invitation, clean end | `consented_session_relays_signaling_and_ends_cleanly` |
| AT-35 | Attended support: access control, cross-site sockets, expiry, guess limits, decline, revoke | `access_control_and_cross_site_sockets`, `invitations_expire_and_guessing_is_limited`, `decline_and_technician_revocation` |
| AT-36 | Attended support in real browsers: WebRTC media flows, matching security codes, honest ended state | `two_browsers_pair_consent_and_share_a_tab` (needs Chrome) |
| AT-37 | Two-step verification: password alone reaches only set-up or the code page; session rotated; replay refused; recovery codes single-use; attempts limited; admin reset | `tests/mfa.rs` (four tests) |

## Manual checks still owed

- **AT-06 as a service:** on a Windows machine, as Administrator, run `flyw8t-agent enroll …` then `flyw8t-agent service install`. Confirm the service starts, survives a reboot, restarts after `taskkill /f`, and that `%ProgramData%\flyw8t\agent` is not readable by a standard user.
- **AT-01:** `docker compose up` from `deploy/compose/` on a Docker host, then the [deployment](deployment.md) walkthrough end to end, including a backup and a restore into a fresh volume.
