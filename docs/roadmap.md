# Roadmap

Ordered by what makes flyw8t safe to depend on, not by feature count. Each milestone ships only when its exit criteria are demonstrated, not when its code exists. Feature parity with Datto RMM, NinjaOne or Tactical RMM is a long-term direction, not a goal for any milestone below.

## 0.1: Foundation (this release)

One working vertical slice: enroll a Windows device, run allowlisted read-only diagnostics, prove the outcome. See [acceptance-tests.md](acceptance-tests.md). Exit criteria met except AT-01 (Compose never run) and AT-06-as-a-service (never installed elevated).

## 0.2: Safe to run on our own machines

The minimum before flyw8t manages anything that matters:

- ~~TOTP two-step verification~~ (built 2026-10-29, required by default). **WebAuthn** and **OIDC** sign-in (STD-004: local + OIDC + PAT planes). Authentik as the reference IdP.
- Cross-family adversarial review of the gateway, journal and orchestrator (STD-001), with findings fixed.
- Run the Windows service install path for real; Authenticode-sign the agent (Azure Artifact Signing, as netviz/PortGlass/tuldMi do).
- Run Compose for real, then document and **rehearse** backup and restore.
- Dogfood fleet on the homelab with external Prometheus scraping `/metrics` ([reliability.md](reliability.md) §3).
- Server identity pinning at enrollment; login CSRF token; session list and force-logout.
- Agent disk-full and database-unavailable fault-injection tests.

## 0.3: Monitoring

- Monitors built on the `Finding` model ([monitoring.md](monitoring.md)): disk space, memory pressure, Windows service state, selected Event Log channels, agent offline with grace periods. Each finding keeps evidence, collection time, freshness and resolution state; one finding per check/device/key, updated in place, never duplicated.
- Alert routing with suppression and deduplication; maintenance windows.
- Monitoring page in the console (added to navigation only when it exists).

## 0.4: Remote access and AnchorDesk

flyw8t stands alone (operator, 2026-10-30). Longer term it becomes a first-class RMM provider inside AnchorDesk, alongside Tactical, NinjaOne and Datto.


- ~~MeshCentral remote-access provider~~: superseded by our own engine ([ADR-0013](decisions/ADR-0013-unattended-access.md)).
- AnchorDesk `FlyweightProvider` + `FlyweightRunner` against `/api/v1` ([anchordesk-integration.md](anchordesk-integration.md)).
- Attended support Phase B is already built (0.1).

## 0.5: Remote control, attended and unattended (ADR-0012, ADR-0013)

The `flyw8t-desktop` engine, proven through the attended helper, then the agent's desktop component for unattended access with per-device consent policy (default: notify with Stop). Platforms in order: Windows, Linux X11, macOS, Wayland. iOS and Android much later.

### Attended first (approved 2026-10-30, ADR-0010)

Design: [ADR-0012](decisions/ADR-0012-remote-control-helper.md) (proposed).

- A signed, temporary Windows helper launched from the consent page: screen capture plus, after a **separate consent**, keyboard and mouse. It shows an always-visible indicator with Stop, persists nothing, never bypasses OS consent, and its input path is audited.
- macOS and Linux (portal) helpers after Windows is proven.

## Mobile administration (approved 2026-10-30, ADR-0011)

- Done: the console installs to a phone's home screen (manifest, maskable icons, theme colour; Chrome confirms it installable in `ui_capture`). No script was needed.
- Next: touch-first on-call screens, then Web Push for findings and job outcomes (VAPID keys only, no vendor account).
- Later: a native client over `/api/v1`, after the operator approves the app-store and push-service costs.

## 0.6: Scripts, with consent and evidence

The first state-changing capability, and the biggest risk change in the product:

- Script library with versions; scripts **signed by a key the server does not hold**, verified by the agent.
- Risk classes mapped to STD-005: read-only (C0), bounded/reversible (C1), consequential (C2, durable approval), irreversible (C3, interactive only).
- Post-condition verification per script (the verification dimension's real job).
- Job Objects on Windows so a timeout kills the whole process tree.

## Later

- Scheduled jobs and policy inheritance (organization → site → device).
- Software inventory, patch state, software install with verification.
- Fleet-wide operations with count confirmation, scope limits and staged rollout.
- Signed agent auto-update ([ADR-0008](decisions/ADR-0008-agent-updates.md)).
- Linux (systemd) and macOS (launchd) agents.
- Horizontal scale-out and HA ([ADR-0009](decisions/ADR-0009-availability-and-scale-out.md)).
- Extension runtime (WASM first) per [ADR-0007](decisions/ADR-0007-extension-runtime.md).
- Postgres row-level security as defense in depth for tenant isolation.

## Explicitly not planned

- Forking Tactical RMM, rewriting AnchorDesk, porting MeshAgent now, or building a general unattended remote-desktop product from scratch. (Attended, consent-first remote control is approved: ADR-0010.)
- AI features before the core is proven reliable on a real fleet.
- Mandatory SaaS components, Redis, Kubernetes or a message broker without a demonstrated need.
