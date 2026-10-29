# Job lifecycle

> **Standard:** an operation either succeeds with evidence, fails with an explanation, or explicitly reports that its outcome is unknown.

A *job* is one request to run one catalog action on one device. This document is the contract. The executable versions are `flyw8t_domain::job` (the transition table and report decision), `flyw8t_domain::evidence` (success contracts), `crates/flyw8t-agent/src/journal.rs` (at-most-once), and `crates/flyw8t-server/src/jobs.rs` (persistence and deadlines).

## Two dimensions, one headline

A job has two independent dimensions:

| Dimension | Column | Question it answers |
|---|---|---|
| Execution state | `jobs.state` | Where is the job in delivery and execution? |
| Verification | `jobs.verification` | Did a completed execution produce the evidence its action promised? |

They are kept separate because "the command ran to completion" and "the command did what it was supposed to" are different claims. A job **succeeded** only when execution is `completed` **and** verification is `verified`. That rule is a function (`domain::job::outcome`) and every UI label goes through it. A test asserts that no other combination reads as success.

### Execution states

| State | Meaning | Terminal? |
|---|---|---|
| `created` | Request recorded; authorization not decided. Exists only inside the creating transaction. | no |
| `authorized` | Role, organization scope and token scope all permit it. Exists only inside the creating transaction. | no |
| `queued` | Waiting for the device. **Not sent.** | no |
| `dispatched` | The offer was durably recorded as sent and written to the device's live connection. **Not proof of receipt.** | no |
| `acknowledged` | The device durably journaled the job. It will run it at most once. | no |
| `running` | The device reported that execution began. | no |
| `completed` | The device reported that execution ran to its end. Verification decides the verdict. | **yes** |
| `failed` | The action could not run or errored, or the device provably did not run it (declined, or restarted before starting). | **yes** |
| `timed_out` | The device's own time limit stopped the work. Output is partial. | **yes** |
| `cancelled` | Cancelled before dispatch (guaranteed not run) or stopped on request (partial). The note says which. | **yes** |
| `expired` | Never sent before its delivery deadline. **Provably not executed.** | **yes** |
| `outcome_unknown` | flyw8t cannot prove whether it ran or what it did. | *resolvable* (see below) |

`outcome_unknown` is final unless the device later sends conclusive evidence: a final report that is anything other than "interrupted". It can then move to `completed`, `failed`, `timed_out` or `cancelled`, and the event is recorded as `resolved_late`. Nothing else can resolve it, and nothing ever moves a job *into* success without a device report.

### Verification

| Value | Meaning |
|---|---|
| `pending` | Waiting for execution to complete, or for its evidence to be evaluated. |
| `verified` | Evidence satisfies the action's success contract. |
| `failed` | Execution completed but the evidence does not satisfy the contract. |
| `not_applicable` | Execution did not complete, so there is nothing to verify. |

Success contracts (`flyw8t_protocol::catalog::SuccessContract`, shown on every job page):

| Action | Contract |
|---|---|
| `system.info`, `process.top` | The structured payload parses as the action's result type. A device claiming a process exit for these is a contract failure. |
| `net.ipconfig` | Exit code 0 **and** non-empty stdout. Exit 0 with no output is not success. |
| `net.ping` | Exit code 0 or 1 (1 = host did not answer: a diagnostic result) **and** non-empty stdout. |

All catalog actions are read-only, so their "verification" checks the evidence itself. When state-changing actions arrive, each will carry a separate post-condition check (for example, "service is now running", read back from the device). The verification dimension exists so that check has a home.

## Transitions

Every transition is a row-locked, conditional update inside a transaction that also appends a `job_events` row (append-only, enforced by a database trigger). Illegal transitions are refused by `ExecState::can_transition_to`, and the server cannot be driven into one by any device report (exhaustively tested: `every_report_decision_is_a_legal_path`).

```text
created ──► authorized ──► queued ──► dispatched ──► acknowledged ──► running ──► completed
   │            │            │  ▲         │ │  │           │             │    ├─► failed
   └──► cancelled ◄──────────┘  │         │ │  └─► (any final, if the ack was lost)
                             │  └─unsent───┘ │                            ├─► timed_out
                             ▼              ▼                            ├─► cancelled
                          expired     outcome_unknown ◄──────────────────┘
                                            │
                                            └──► completed | failed | timed_out | cancelled
                                                 (only on a conclusive device report)
```

| From | To | Trigger |
|---|---|---|
| `created` | `authorized` | Server authorization passed (same transaction as creation). |
| `authorized` | `queued` | Same transaction. |
| `created`/`authorized`/`queued` | `cancelled` | Cancel before dispatch. **Guaranteed not executed.** |
| `queued` | `dispatched` | The device is connected; the dispatch is committed, *then* the offer is written. |
| `queued` | `expired` | `deliver_by` passed (default 15 min after creation). |
| `dispatched` | `queued` | The offer could not be written to the connection after the dispatch committed (it never left the server), and no newer offer has been sent since. |
| `dispatched` | `acknowledged` | Device report `Accepted`. |
| `dispatched`/`acknowledged` | `running` | Device report `Started`. |
| `dispatched`/`acknowledged`/`running` | final | Device report `Finished`. |
| `dispatched` | `failed` | The device declined for a reason that will not change (unknown action, invalid parameters). A *retryable* decline (`busy`, `storage_error`) changes nothing: the job stays `dispatched` and is re-offered after the redelivery interval, because another offer may already be in flight. A decline never resolves `outcome_unknown`. |
| `dispatched` | `outcome_unknown` | `deliver_by` passed without an acknowledgement. The device may have received it. |
| `acknowledged`/`running` | `outcome_unknown` | No result within `timeout + silence_grace` after acknowledgement, or the device reported `Interrupted`. |
| `outcome_unknown` | final | A conclusive late device report. |

If a device reports on a job recorded as `queued` (possible after restoring a database backup taken before the dispatch committed), the server records an `implied_dispatch` and then applies the report. It does not reject the evidence, and rejecting it would put the device into a resend loop.

## Behavior under failure

| Situation | Behavior | Test |
|---|---|---|
| **Agent disconnects** with jobs queued | Jobs stay `queued`; nothing claims they were sent. | `reconnect_and_duplicate_delivery_never_reexecutes` |
| **Agent disconnects** mid-job | The agent keeps running it (jobs outlive connections) and journals the result; it is reported on reconnect. If that takes longer than `timeout + grace`, the job shows `outcome_unknown` meanwhile, then resolves. | `silent_device_becomes_unknown_then_late_result_resolves` |
| **Reconnect** | The agent re-sends the latest state of every unacknowledged journal entry; the server re-offers `dispatched` jobs whose last offer went to an older connection, and re-sends pending cancels. | e2e + model test |
| **Duplicate delivery** | The agent checks its journal before anything else; a known job id is never run again. Its stored report is re-sent instead. | `reconnect_and_duplicate_delivery_never_reexecutes` (asserts identical start/finish timestamps after a real redelivery) and the model test |
| **Server restart** | All state is in PostgreSQL; the in-memory connection registry is rebuilt as agents reconnect. Queued work is delivered afterwards. | `server_restart_preserves_queued_work` |
| **Agent crash before start** | Journal says `Accepted` without `Started`, so on restart: `NotStarted` → `failed`, "it was not run". | journal unit test |
| **Agent crash during execution** | Journal says `Started` without `Finished`, so on restart: `Interrupted` → `outcome_unknown`, never re-run. | `agent_crash_mid_job_is_outcome_unknown_and_not_rerun` (kills the agent runtime mid-ping) |
| **Timeout during execution** | The agent kills the child process (in-process collectors are abandoned) and reports `TimedOut` with partial output. Server-side silence is never reported as a timeout: it is `outcome_unknown`. | `timeout_stops_the_process_and_keeps_partial_output` |
| **Cancellation race** | Before dispatch: atomic, guaranteed. After: `cancel_requested_at` is set and `JobCancel` sent; the device's report decides the outcome (it may have finished first, and the job then says so). A cancel for a job id the agent has not seen writes a tombstone, so a late offer is never run. Cancel and offer may arrive in either order; both are safe. | `cancellation_before_and_during_execution`, journal tombstone test |
| **Late result** | Stored and acknowledged. Resolves `outcome_unknown`; ignored (but recorded) for terminal states. | `silent_device_becomes_unknown_then_late_result_resolves` |
| **Partial output** | Each stream is capped at 256 KiB on the device; the report carries total bytes and a `truncated` flag shown in the UI. | `read_bounded_truncates_and_counts` |
| **Failed verification** | `completed` + `verification=failed`, headline "Verification failed", with the reason. | evidence unit tests |
| **Lost message on a live connection** | An unacknowledged offer or cancel is repeated after `redelivery_after` (60 s); the agent re-sends unacknowledged final reports every heartbeat. | model test (this rule was added because the model found the gap) |
| **Report about another device's job** | Ignored, audited as denied, not acknowledged. | `device_cannot_report_another_devices_job` |
| **Stale decline** (an old offer's `busy` arriving after a newer offer was accepted) | Changes nothing. An earlier design moved `dispatched` back to `queued` on `busy`; the model test showed a cancel could then claim "never sent" while a redelivered offer ran. | model test; `a_decline_never_resolves_an_unknown_outcome` |
| **Repeated reports** (duplicates, or a hostile device) | Counted in `jobs.unchanged_reports`; at most 50 events are kept per job; device-supplied text is truncated to 4,096 characters; more than 100 messages per second closes the connection. | `repeated_reports_are_counted_not_logged_and_bursts_are_cut_off` |

## Timestamps

| Column | Clock | Set when |
|---|---|---|
| `created_at`, `queued_at`, `first_dispatched_at`, `last_dispatched_at`, `acknowledged_at`, `terminal_at`, `cancel_requested_at` | server | the server records the event |
| `started_at`, `finished_at` | **device** | reported by the device; labelled "(device clock)" in the UI |
| `deliver_by` | server | creation + delivery window |

## What is not done yet

- Multi-device (fleet) jobs. A job targets exactly one device; the API has no batch endpoint.
- Scheduled jobs and retries. Nothing is ever retried automatically. A retry must be a new job created by a person, because a job may be non-idempotent.
- State-changing actions and their post-condition verification.
