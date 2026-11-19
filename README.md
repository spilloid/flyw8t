# flyw8t

**Lightweight agents. Heavyweight control.** *(pronounced "flyweight")*

flyw8t is a self-hosted remote monitoring and management (RMM) platform for MSP technicians, written in Rust. Its defining rule:

> An operation either succeeds **with evidence**, fails **with an explanation**, or explicitly reports that its outcome is **unknown**. Never pretend otherwise.

**Version 0.1.5, pre-release. Not production-ready.** TOTP two-step verification, local passkey sign-in, sudo mode and optional [OIDC/SCIM directory integration](docs/directory-sso.md) are implemented. Native remote control, signed installation/update verification and deployment/fleet recovery evidence remain release work. See the [threat model](docs/threat-model.md#open-items-before-production) and the operator-approved [roadmap and release gates](docs/roadmap.md): Windows and macOS endpoints at 1.0; Android endpoints and mobile technician administration at 1.5.

## What works today

- **Windows agent** (Rust, Windows service). One outbound TLS WebSocket; a device key that never leaves the device; a durable journal that makes job execution **at most once** across duplicate deliveries, reconnects, server restarts and agent crashes.
- **Read-only diagnostics** from a compiled-in catalog (`system.info`, `process.top`, `net.ipconfig`, `net.ping`). No shell and no arbitrary commands; the agent enforces the catalog itself.
- **Honest job outcomes.** Execution state and verification are separate. "Succeeded" means the device ran it *and* its evidence satisfied the action's success contract. A device that goes silent produces `outcome_unknown`, never a guess.
- **Web console** (server-rendered Leptos, works without JavaScript): devices with live-vs-cached labelling, jobs with their full lifecycle, organizations and enrollment, audit history, administration.
- **Attended support:** send a code, the person consents in their browser, and you see the tab or screen they choose, with no install. Screen view only; no control.
- **JSON API** with scoped bearer tokens and idempotency keys, for integrations such as AnchorDesk.
- **Technician MCP preview.** A named AI client can request one screenshot from the attended web viewer after the participant grants screenshot access. [Setup and tool contract](docs/mcp.md)
- **Self-hosted:** one binary plus PostgreSQL. No Redis, no broker, no SaaS.

## Native Windows technician preview

`flyw8t-technician` offers four ways to work with a Windows computer.

- **Help someone** lists the host's Windows sessions under your current Windows credentials.
  Pick the account and desktop, then choose **View session** or **Request control**.
  Flyw8t rechecks the session identity and opens Windows' shadow client. The target's
  Windows permissions and consent policy apply. Discovery requires Windows session-query
  access over RPC, which can differ from permission to sign in over RDP.
- **Share a screen** opens your flyw8t Support console for an attended, view-only
  invitation. The person opens it inside the intended desktop and chooses the screen.
  Set `FLYW8T_PUBLIC_URL` to prefill the server address, or enter it in the window.
- **Unattended console** checks the owner's existing Windows computer policy and
  the active physical console login. Choose view or control within the policy's
  permission. Flyw8t rechecks both before handing the request to Windows.
  The workstation needs a routed path to the host, WTS session-query access and
  read access to its computer policy through Windows Remote Registry. A host
  that requires consent stays on the **Help someone** path. A computer with
  nobody signed in can still offer **Windows sign-in**. [Windows remote control policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-terminalserver#ts-remotecontrol-2)
- **Windows sign-in** opens an RDP desktop embedded in the native viewer. Enter a
  computer name, IP address, or `host:port` and choose whether to share the clipboard.
  Windows handles credentials and certificates. A sign-in can lock the physical
  console or transfer an existing session. Concurrent independent desktops depend
  on the Windows host's edition, licensing and configuration.

For a local Windows x64 build, install the Rust MSVC toolchain, Visual C++ build tools,
and a Windows SDK, then launch the viewer with Cargo.

```powershell
cargo run --release -p flyw8t-technician
```

An address argument prefills the field. `--assist HOST` opens the session picker.
`--console HOST` opens the preauthorized physical-console picker.
`--share HOST` opens attended sharing. `--connect HOST[:PORT]` starts one Windows sign-in attempt.
Cancel stays available while the network is being checked. A refusal or timeout explains
what happened, and the next attempt starts when you choose **Connect** again.
Clipboard sharing uses Windows RDP redirection and the remote host's policy.
This preview uses the endpoint's RDP permissions. Flyw8t's enrolled-device Take control
and consented shared-screen workflows have their own authorization and release gates.

## Network operations (unreleased)

**Unreleased network operations:** the current source adds NetViz site collectors,
agentless network inventory and discovery history, plus an explicit PortGlass handoff
inside this console. Start from a site's **Network operations** link or **Network** in
the navigation. See [setup and limits](docs/network-operations.md) and the
[AnchorDesk / Material family direction](docs/product-family.md). SNMP monitoring,
physical topology, configuration backups and flow analysis are still future work.

## How it is checked

```sh
cargo test --workspace                                   # unit, state machine, model-based property test
export FLYW8T_TEST_DATABASE_URL=postgres://user:pass@127.0.0.1:5432/postgres
cargo test --workspace -- --include-ignored              # + PostgreSQL end-to-end, protocol, TLS, UI capture, two-browser WebRTC
```

The suite includes real agents running real Windows commands against a real server, deliberate crashes mid-job, a model-based test that drives the real journal and the real state machine through thousands of random sequences of lost, duplicated and reordered messages, and headless-Chrome checks of every page at three widths in light and dark. How each reliability claim is backed is in [docs/reliability.md](docs/reliability.md), and what the tests found is in [docs/dev-process.md](docs/dev-process.md).

## Try it

```sh
# Server (PostgreSQL required)
export FLYW8T_DATABASE_URL=postgres://flyw8t:secret@127.0.0.1:5432/flyw8t
export FLYW8T_PUBLIC_URL=http://localhost:8080
export FLYW8T_BOOTSTRAP_ADMIN_EMAIL=admin@example.com FLYW8T_BOOTSTRAP_ADMIN_PASSWORD='a-long-password'
cargo run -p flyw8t-server
# Sign in at http://localhost:8080 → Organizations → create one → Create enrollment token

# Agent, on the same Windows machine (foreground)
cargo run -p flyw8t-agent -- --state-dir .\agent-state enroll --server http://localhost:8080 --token fw8e_…
cargo run -p flyw8t-agent -- --state-dir .\agent-state run
```

Docker Compose and production notes (TLS, backups, Windows service): [docs/deployment.md](docs/deployment.md).

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | Components, trust boundaries, what one instance can and cannot do |
| [Job lifecycle](docs/job-lifecycle.md) | The state machine and every failure behavior |
| [Agent protocol](docs/agent-protocol.md) | Wire format, authentication, delivery guarantees |
| [Threat model](docs/threat-model.md) | Threats, controls, evidence, open items |
| [Reliability](docs/reliability.md) | Correctness properties, availability targets, measurement |
| [Attended support](docs/attended-support.md) | Consent model, WebRTC design, status, two-browser demo |
| [AnchorDesk integration](docs/anchordesk-integration.md) | Using flyw8t as an AnchorDesk RMM provider |
| [Roadmap](docs/roadmap.md) · [Decisions](docs/decisions/) · [Acceptance tests](docs/acceptance-tests.md) | |

## License

MIT. See [LICENSE](LICENSE).
