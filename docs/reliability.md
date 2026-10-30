# Reliability: what is promised, what is proven, what is measured

"Reliable" is not a property you can claim for flyw8t; it has to be shown. This document separates three things that are easy to blur:

1. **Correctness properties:** things that must *never* happen (a job run twice, a success shown without evidence). These are proven by construction and by testing, not measured.
2. **Availability:** the fraction of time a component does its job. Measured against a budget.
3. **Outcome rates:** how often operations end in verified success, failure, or unknown. Measured and published, never rounded up.

## 1. Correctness properties

| # | Property | How it is enforced | Evidence |
|---|---|---|---|
| P1 | A job executes **at most once** on its device, under duplicate delivery, reconnects, server restarts and agent crashes. | Journal-before-ack and journal-before-start (`journal.rs`). | Unit tests; e2e `reconnect_and_duplicate_delivery_never_reexecutes` (real redelivery, identical timestamps); e2e crash test; model test (400 random fault sequences per run; 5,000 and 3,000 in recorded runs on 2026-10-29). |
| P2 | **No success without evidence.** "Succeeded" iff execution `completed` ∧ verification `verified`; `completed` only from a device report. | `domain::job::outcome`, `decide`, `evidence::evaluate`. | Exhaustive unit tests over all (state, verification) and (state, report) pairs; model test. |
| P3 | **Never "not run" about something that ran.** `expired` / cancelled-before-dispatch / `NotStarted` imply zero executions. | Dispatch commits before the offer leaves; journal start record precedes execution; a retryable decline never re-queues (another offer may be in flight); a failed send re-queues only if no newer offer was sent. | Model test invariants (the model found the decline re-queue violation; fixed); journal recovery tests; mutation checks ([dev-process.md](dev-process.md)). |
| P4 | **Terminal states never change.** `outcome_unknown` only resolves to a final state on device evidence. | Transition table. | `terminal_states_have_no_exits`, `outcome_unknown_resolves_only_to_final_states`, model test. |
| P5 | **No report can wedge the server.** Every (state, report) decision is a legal path, so no report causes an error-and-reconnect loop. | `decide` + exhaustive test. | `every_report_decision_is_a_legal_path`; e2e `report_for_job_recorded_as_queued_is_accepted_not_looped`. |
| P6 | **Eventual resolution.** Once faults stop and the device reconnects, no job remains `dispatched`/`acknowledged`/`running`, every device report is acknowledged, and `outcome_unknown` remains only where the device itself has no conclusive evidence. | Bounded redelivery of offers and cancels, heartbeat re-send of final reports. | Model test liveness phase. **This property found two real gaps** (lost offer or cancel on a live connection; dropped final report), both fixed. |
| P7 | **One agent process per device.** Two processes sharing a journal could each run a job once. | Exclusive OS lock on the state directory, held for the process lifetime. | `one_process_per_state_directory`. |

Formal model: [`spec/JobDelivery.tla`](spec/JobDelivery.tla) states P1 to P4 in TLA+. **It has not been model-checked yet** (see [spec/README.md](spec/README.md)); the executed evidence above is what the claims rest on today.

Not covered: concurrency inside the server process (row locks are relied on, not model-checked; `loom` is not applicable to code whose concurrency lives in PostgreSQL transactions). Disk-full on the agent is handled by design (a failed journal write declines or refuses to start the job) but is not fault-injected in a test yet.

## 2. Availability

### Define what is available

"flyw8t is up" means different things. The budgets below are per component, and they are **not** the same number:

| SLI | Good event | Measured from |
|---|---|---|
| **Control-plane availability** | `/readyz` returns 200 (process up **and** database answering) | external probe, every 30 s |
| **Console availability** | a signed-in page renders within 2 s | synthetic check |
| **Agent connectivity** | an enrolled, non-retired device has a live connection | `flyw8t_agents_connected / flyw8t_devices_enrolled`, every minute |
| **Agent process availability** | the agent service is running on the endpoint | Windows SCM + heartbeat gaps |
| **Command completion** | of jobs that reached a final state in the window: `completed+verified` vs `failed`, `timed_out`, `outcome_unknown` | `flyw8t_jobs{state,verification}` |

Agent connectivity is bounded by things flyw8t does not control: laptops sleep, networks fail, users shut machines down. **It is not an availability SLO for flyw8t**; it is a fleet-health signal. An agent "staying alive for 99.99 % of the year" and "the RMM being operational 99.99 % of the year" are different claims and are kept apart here.

### Budgets

| Target | Per year | Per month | Per week | Per day |
|---|---|---|---|---|
| 99.9 % | 8 h 45 m 36 s | 43 m 49 s | 10 m 5 s | 1 m 26 s |
| 99.99 % | 52 m 34 s | 4 m 23 s | 1 m 0 s | 8.64 s |

### What 0.1.0 can honestly target

**A single flyw8t instance on a single PostgreSQL cannot promise 99.99 %.** A routine upgrade restarts the process (seconds) and runs migrations. A PostgreSQL minor-version update or host reboot takes minutes. A disk or host failure means a restore measured in tens of minutes. One host reboot a month spends the whole four-nines monthly budget (4 m 23 s) by itself. Rust correctness does not change this; it removes *software-caused* outages, not hardware, OS, network or operator-caused ones.

| Deployment | Realistic control-plane target | Why |
|---|---|---|
| Single host, Compose, nightly backups (what exists) | **99.5 % to 99.9 %**, unmeasured until it runs somewhere | Restarts are fast; host and database failures are restores. |
| Single flyw8t + PostgreSQL with streaming replica and tested failover | ~99.9 % to 99.95 % | Database failure becomes a failover; server restarts still drop all agent connections. |
| ≥ 2 flyw8t instances behind a load balancer + HA PostgreSQL, zero-downtime migrations | **99.99 % becomes a plausible design target** | Needs [ADR-0009](decisions/ADR-0009-availability-and-scale-out.md): cross-instance dispatch wake-up via `LISTEN/NOTIFY`, a shared rate-limit store, expand/contract migrations, and agents spread across instances. |

What *does* hold regardless of deployment: **an outage of the control plane does not lose or corrupt work.** Agents keep running accepted jobs and journal their results; queued jobs wait (and expire honestly); on recovery, reports are re-sent and outcomes resolve. The server can be down; the record stays correct. That is the property the tests above defend.

### Recovery objectives (single instance)

| Objective | Target | Basis |
|---|---|---|
| RTO, process crash or restart | < 30 s for the console; agents reconnect within their backoff (≤ 60 s + jitter) | measured in tests: restart + reconnect completes within the 30 s test window |
| RTO, host loss | restore time of the PostgreSQL backup + container start | **not measured yet**; rehearse per [deployment.md](deployment.md) |
| RPO | the backup interval (daily `pg_dump` by default) | WAL archiving narrows it; not configured by default |

## 3. Measurement

`/metrics` exposes the counters these SLIs need (see [architecture.md](architecture.md#observability-implemented-minimal)). Reliability is not claimed until it is measured somewhere real. The plan, in order:

1. **Self-hosted dogfood fleet.** Run flyw8t on the homelab cluster, enroll every machine available, and scrape `/metrics` with an external Prometheus and a blackbox probe on `/readyz`.
2. **Publish the numbers**, including the bad ones: monthly control-plane availability, per-action outcome rates, the count and age of `outcome_unknown` jobs, the reconnect-time distribution after a server restart, and crash-free agent hours (from the Windows SCM restart count).
3. **Fault-injection drills against that fleet,** not just in tests: kill the server mid-job, kill agents mid-job, drop the network for longer than the delivery window, fill the agent's disk, restart PostgreSQL. Each drill has an expected outcome taken from [job-lifecycle.md](job-lifecycle.md); any deviation is a bug.

Until that has run for a meaningful period, flyw8t's availability is **unknown**, and documents should say so.

## Fault-injection inventory

| Fault | Where it is injected today |
|---|---|
| Duplicate and reordered messages | model test; e2e redelivery |
| Message loss (either direction) | model test |
| Connection drop / reconnect | e2e; model test |
| Agent crash (all tasks killed mid-execution) | e2e (agent runtime torn down mid-ping); model test (journal reopened) |
| Server restart with queued work | e2e |
| Database restore to an older state | e2e (job forced back to `queued` / `dispatched`) |
| Hostile or malformed frames, oversized messages | protocol tests |
| Process timeout and kill | executor tests (real `PING.EXE` to TEST-NET-1) |
| Agent disk full / journal write failure | **not yet** (code path exists; no test) |
| Power loss between a journal rename and the disk | **not yet.** Unix fsyncs the directory after rename. Windows relies on NTFS journaling; `MoveFileEx(MOVEFILE_WRITE_THROUGH)` (an isolated `unsafe` call) is the planned fix. Raised by the cross-family review as plausible, not demonstrated. |
| Two agent processes on one state directory | unit test (OS lock) |
| Message floods and duplicate-report floods | protocol test |
| PostgreSQL unavailable mid-request | **not yet** |
| Clock skew between device and server | **not yet** (device timestamps are labelled as device clock; no server logic depends on them) |
