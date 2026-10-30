# ADR-0001: Workspace shape

**Status:** accepted · **Date:** 2026-10-29

## Context

The founding brief suggested seven crates (`agent`, `server`, `web`, `protocol`, `domain`, `storage`, `integrations`) and asked for coherent modules over excessive abstraction.

## Decision

Five crates:

- `flyw8t-protocol`: everything both ends must agree on (messages, catalog, validation, signed bytes). The agent depends on nothing else from the workspace, so a server-side change cannot silently change what the agent accepts.
- `flyw8t-domain`: rules without I/O (state machine, report decision, evidence, access, findings). Exhaustively unit-testable.
- `flyw8t-web`: views over plain view models; no database access.
- `flyw8t-server`: everything with I/O on the control plane. Storage is SQL next to the code that uses it; integrations are traits (`remote_access`).
- `flyw8t-agent`: the endpoint.

`storage` and `integrations` crates were not created: each would have exactly one consumer (the server), and a repository layer over sqlx would mostly forward calls. Revisit when a second consumer exists (for example a CLI or migration tool that needs storage without the server), or when a second integration lands that has dependencies the server should not carry.

## Consequences

- The domain crate holds the decisions worth proving; the server is a thin, testable shell around them. The property test in the agent crate can use the real decision function because it lives in `domain`.
- The agent binary does not link the server, web or database code.
