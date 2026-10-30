# ADR-0004: PostgreSQL is the only stateful dependency

**Status:** accepted · **Date:** 2026-10-29

## Decision

1. **PostgreSQL holds all durable state.** No Redis, NATS, or broker. The job queue is the `jobs` table: row locks (`SELECT … FOR UPDATE`) serialize every transition, and a periodic sweeper resolves deadlines. At MSP scale (thousands to tens of thousands of endpoints, jobs created by people) this is far below what PostgreSQL handles. Revisit only with a measured bottleneck.
2. **In-memory state is limited to what is safe to lose:** the live connection registry (rebuilt as agents reconnect) and rate-limit windows.
3. **Queries are runtime-checked** (`sqlx::query_as` with tuples or `FromRow`), not compile-time macros. Compile-time checking needs a live database or a committed offline cache at build time, which would make building the agent depend on a database. Every query is exercised by the PostgreSQL end-to-end tests instead.
4. **Migrations are embedded** (`sqlx::migrate!`) and applied at startup, each in a transaction. Versioned files under `migrations/`; never edit a migration that has shipped. (0001 is still unreleased and was edited during development.)
5. **History is append-only in the database,** not by convention: triggers reject UPDATE, DELETE and TRUNCATE on `job_events` and `audit_events`.

## Consequences

- Backup and restore is `pg_dump`/`pg_restore`, and a restore cannot leave a queue broker out of step with the database.
- The decision is what makes multi-instance operation possible later ([ADR-0009](ADR-0009-availability-and-scale-out.md)): instances share nothing but PostgreSQL.
- SQL typos surface in tests, not at compile time. Mitigation: every query path is covered by an `--ignored` PostgreSQL test, and CI runs them.
