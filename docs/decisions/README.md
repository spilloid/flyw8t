# Architecture decision records

Each ADR records one decision, the alternatives, and what would make us revisit it. Status is **accepted** (in force), **proposed** (needs the operator's decision), or **superseded**.

| ADR | Decision | Status |
|---|---|---|
| [0001](ADR-0001-workspace-shape.md) | Five-crate workspace; storage and integrations as server modules | accepted |
| [0002](ADR-0002-device-identity.md) | Device identity: on-device Ed25519 key, per-connection signed challenge over WSS, not mTLS | accepted |
| [0003](ADR-0003-web-ui-ssr-first.md) | Web console: server-rendered Leptos, no WASM yet | accepted |
| [0004](ADR-0004-postgres-only-state.md) | PostgreSQL is the only stateful dependency; runtime-checked sqlx queries; embedded migrations | accepted |
| [0005](ADR-0005-job-lifecycle.md) | Two-dimension job lifecycle; `outcome_unknown` is first-class; nothing auto-retries | accepted |
| [0006](ADR-0006-remote-access-provider.md) | Remote access behind a provider trait; MeshCentral first, never authoritative | accepted |
| [0007](ADR-0007-extension-runtime.md) | Extensions: WASM components over embedded JavaScript, not before 0.5 | proposed |
| [0008](ADR-0008-agent-updates.md) | No agent auto-update until manifests are signed by a key the server does not hold | accepted |
| [0009](ADR-0009-availability-and-scale-out.md) | Single instance now; documented path to multi-instance HA for a 99.99 % target | accepted (design) |
| [0010](ADR-0010-attended-support.md) | Attended support: browser screen share via WebRTC with server signaling; consent-first native helper for remote control (approved 2026-10-30) | accepted |
| [0011](ADR-0011-mobile-admin.md) | Mobile administration: the console as an installable mobile web app first, then a native client over the same API | accepted |
| [0012](ADR-0012-remote-control-helper.md) | Attended remote control: a signed, uninstalled Rust helper; WebRTC media and an input data channel; two consents; Windows first | proposed |
