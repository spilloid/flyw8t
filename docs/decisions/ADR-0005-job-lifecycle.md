# ADR-0005: Job lifecycle

**Status:** accepted · **Date:** 2026-10-29

## Decisions

1. **Two dimensions.** Execution state and verification are separate columns. "Succeeded" is derived: `completed ∧ verified`. *Why:* an exit code of 0 is not proof, and the UI must never conflate "ran" with "worked".
2. **`outcome_unknown` is a first-class state,** and the only one that can change after being reached, and only on conclusive device evidence. *Why:* the alternatives are guessing "failed" (which invites a dangerous re-run) or "succeeded" (a lie). Silence from a device is never reported as a timeout; `timed_out` means the device's own limit fired.
3. **At-most-once is the agent's job, enforced by a durable journal.** The server delivers at least once; the agent's journal-before-ack and journal-before-start make execution at most once. *Why:* only the endpoint can know whether it started something, and network failures make exactly-once delivery impossible.
4. **Nothing retries automatically.** A failed, timed-out or unknown job is never re-run by the system; a person creates a new job. *Why:* jobs will become non-idempotent (scripts, installs), and an automatic retry after "unknown" is how an RMM runs a destructive script twice.
5. **The server's response to every device report is a pure function** (`domain::job::decide`) that only produces legal transitions, tested over every (state, report) pair. *Why:* a report that drives an illegal transition causes an error, then a dropped connection, then a resend, then the same error: a livelock no amount of reconnecting fixes.
6. **Deliveries are bounded in time.** Jobs have a delivery deadline (default 15 min); an undelivered job expires and says it did not run, rather than surprising someone hours later.

## Alternatives considered

- *A single status enum* (`pending/running/success/failure`) like most RMMs. Rejected: it cannot express "ran but unverified" or "unknown".
- *Server-side exactly-once via two-phase commit with the agent.* Rejected: impossible across an unreliable network; the journal gives the property that matters.

See [job-lifecycle.md](../job-lifecycle.md) for the full contract and [reliability.md](../reliability.md) for the evidence.
