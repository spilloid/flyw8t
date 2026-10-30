# ADR-0006: Remote access behind a provider seam; MeshCentral first

**Status:** accepted for the provider seam; **superseded for remote control by [ADR-0013](ADR-0013-unattended-access.md)** (2026-10-30: our own engine, not MeshCentral) · **Date:** 2026-10-29

## Context

Technicians need remote desktop. Building a remote-desktop stack is a multi-year project that flyw8t should not start before its RMM core is proven. MeshCentral (Apache-2.0, actively maintained: release 1.3.1 on 2026-10-23) already provides browser-based remote desktop, terminal and files through its own agent.

## Decision

1. `remote_access::RemoteAccessProvider` (server) is the seam: `describe(device)` and `launch_url(device)`. The default `NotConfigured` provider says so on the device page instead of showing a dead button.
2. **MeshCentral is the first provider, and it is never authoritative.** flyw8t's device identity, organization and inventory come only from flyw8t's own agent and enrollment. A MeshCentral node is linked to a flyw8t device by an explicit mapping (`device_id ↔ node id`), created by an administrator or by a matching rule that an administrator confirms. It is never inferred silently.
3. The RMM works with MeshCentral down: the provider reports "unavailable" and nothing else is affected.
4. Integration surface (verified against MeshCentral's `meshctrl.js`, 2026-10-29): a server-to-server WebSocket to `/control.ashx`, authenticated with a dedicated MeshCentral service account (`x-meshauth`) or a server login key. flyw8t would use `deviceopenurl`-style links or `devicesharing` (time-limited share links) to launch sessions, and would **not** use MeshCentral's `runcommand`/`shell`: command execution stays in flyw8t, where it has a lifecycle and an audit trail.

## Consequences

- Endpoints run two agents (flyw8t + MeshAgent) when remote desktop is wanted. Accepted for now; the cost is examined in [research/meshagent-rust.md](../research/meshagent-rust.md).
- MeshCentral's own users and permissions must be kept in step with flyw8t's organizations. The provider must create per-organization device groups and never grant a technician a MeshCentral group outside their flyw8t scope. This mapping is the riskiest part of the integration and needs its own tests.
- Not implemented yet (roadmap 0.4).
