# ADR-0007: Extension runtime: WASM components over embedded JavaScript

**Status:** proposed (no extension runtime before 0.5) · **Date:** 2026-10-29

## Context

Eventually endpoint capabilities should be extensible without shipping a new agent for every check. For now the catalog is compiled Rust, and that stays true until the core is proven. This ADR records the direction so that nothing built earlier forecloses it.

## Neither option is automatically secure

An extension that can call anything the agent can call is arbitrary code execution with extra steps. The security comes from the **host API**, not the runtime: what functions an extension may import, with which arguments, under which limits, and who signed it.

## Comparison

| | WASM components (Wasmtime + WIT) | Embedded JavaScript (QuickJS / Boa / V8) |
|---|---|---|
| Capability model | No ambient authority: an extension can do only what the host imports grant. WIT gives typed, versioned interfaces. | Engine globals plus whatever the host injects; easy to leak authority through a convenience binding. |
| Resource limits | Fuel/epoch interruption, memory limits, deterministic traps | Engine-dependent; QuickJS has memory and interrupt hooks; V8 isolates are heavy |
| Languages | Rust, C, Go, others compile to it | JavaScript/TypeScript only |
| Agent size | Wasmtime adds a few MB | QuickJS ~1 MB; V8 tens of MB |
| Maturity in Rust | Wasmtime is production-grade; component model is stable for host/guest typed calls | QuickJS via bindings is mature but C; Boa is pure Rust but less mature |
| MeshCentral compatibility | None, and that is fine: flyw8t extensions are flyw8t's | MeshAgent runs server-pushed meshcore JavaScript; a JS runtime is the only way to execute it. **That is a reason against, not for:** executing server-pushed code is exactly what flyw8t's catalog boundary forbids (threat T10) |

## Proposed decision

WASM components with a WIT-defined, versioned host API; no JavaScript runtime in the agent.

1. Extensions are **signed** packages (manifest + component), verified on the agent against keys the server does not hold. The server distributes; it cannot author.
2. Each extension declares capabilities (`read-registry-key`, `query-service-state`, `read-file:<path pattern>`, …); the agent grants only declared and policy-allowed capabilities; anything else traps.
3. Fuel and memory limits per invocation; results flow through the same job lifecycle and success contracts as built-in actions.
4. **No native FFI to extensions, ever.** No `unsafe` host imports.
5. The host API is versioned; an agent rejects extensions built for an incompatible major version.

## Revisit when

0.5 (scripts) has shipped and the signing and approval model has been proven on scripts first. Scripts are the simpler case of the same trust problem.
