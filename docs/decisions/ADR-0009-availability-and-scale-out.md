# ADR-0009: Availability and scale-out

**Status:** accepted as design; single instance today. Cross-instance job dispatch is built; attended support and rate limits are still per instance · **Date:** 2026-10-29

## Context

The operator set a reliability bar of 99.99 % (52 m 34 s per year; 4 m 23 s per month). [reliability.md](../reliability.md) separates what that can mean (control plane, console, agent connectivity, command outcomes) and shows that a single process on a single database cannot meet it: one host reboot a month consumes the monthly budget.

## Decision

**Now (0.1 to 0.3):** one server process, one PostgreSQL. Optimize for correctness under failure (no lost or misreported work across restarts, tested) and fast recovery, and measure real availability on a dogfood fleet before promising a number.

**Path to a 99.99 % design target**, in order:

1. **HA PostgreSQL** (streaming replica + tested automated failover, e.g. Patroni, or a managed service for those who want one). The server already reconnects its pool; add a test that kills the primary mid-job.
2. **Multiple flyw8t instances** behind a load balancer (agents and browsers spread across them). The instance-local state must go:
   - *Connection registry:* stays local (a connection lives on one instance), but dispatch must reach the owning instance: on job create and cancel, `NOTIFY flyw8t_dispatch, '<device_id>'`; each instance `LISTEN`s and dispatches for devices it holds. The periodic sweep remains the backstop, so a lost notification costs latency, never correctness (the delivery rules already tolerate this). **Built 2026-10-30**, with a two-instance test (`work_created_on_one_instance_reaches_a_device_on_another`).
   - *Attended support signaling:* the hub pairing a technician's and a participant's sockets is per instance. **Until it routes across instances, run one instance, or pin each support session to one instance** (for example, a load balancer with affinity on the session id). This is the remaining blocker for several instances.
   - *Rate limits:* move to PostgreSQL (unlogged table) or accept per-instance limits multiplied by instance count.
   - *Sweeper:* safe to run on every instance, since every rule is a row-locked conditional transition; optionally elect one with `pg_try_advisory_lock` to cut load.
3. **Zero-downtime migrations:** expand/contract only; no migration that locks hot tables; the old and new binaries must both run against the expanded schema.
4. **Agent reconnect storms:** jittered backoff exists; add a server-side accept-rate limit so a restarted instance is not overwhelmed.

## Consequences

- Nothing in 0.1 blocks this: PostgreSQL is the only shared state ([ADR-0004](ADR-0004-postgres-only-state.md)); every state change is a row-locked transition; redelivery and resend already tolerate lost messages.
- The availability number will be claimed only after it has been measured on a real deployment, per [reliability.md](../reliability.md) §3.
