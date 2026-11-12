# Roadmap and release gates

**Accepted by the operator: 2026-11-12.** These milestones are evidence gates, not dates or claims that their code exists. The build stays **0.1.1 pre-release** until a release is cut. Accepting this plan does not pass any gate.

## Product contract

| Release | Required scope |
|---|---|
| **1.0.0** | Windows and macOS endpoints; Linux-hosted server/console; monitoring, authorized remediation, native attended and unattended control. Windows UAC and sign-in screens are mandatory. |
| **1.5.0** | Android endpoints **and** mobile technician administration, each proven on the supported device matrix. |
| Conditional | iOS with separate feasibility results and a capability contract. Android does not imply iOS parity. |
| Outside 1.0 | Linux endpoint agents, general Linux desktop control and mobile endpoints. Linux remains the server platform. Full parity with established RMMs is not the release criterion. |

Use the shared in-house flyw8t-desktop engine for the temporary attended helper and installed agent's desktop component ([ADR-0012](decisions/ADR-0012-remote-control-helper.md), [ADR-0013](decisions/ADR-0013-unattended-access.md)). MeshCentral is not a planned dependency. Reuse established transports, cryptography and OS capture/codec APIs.

Diagnostics stay allowlisted. Scripts follow [ADR-0014](decisions/ADR-0014-scripts-and-custom-fields.md) and [ADR-0015](decisions/ADR-0015-script-trust-and-running.md): agent-side verification, keys outside the server and explicit approval rules. Remote input and updates need their own reviewed authorization and compromise models; script signatures do not protect them automatically.

## Delivery sequence

| Milestone | Deliverable | Required demonstration |
|---|---|---|
| **0.2.0: Trustworthy foundation** | Journal hardening, reproducible deployment, signed packages, restore, unified threat model and early Mac experiments. | Failed writes never publish unsaved state; damaged history blocks startup without being discarded; fresh install/restore work; real Mac permissions and session limits are understood. |
| **0.3.0: Useful daily operations** | Persistent findings, alerts, suppression, maintenance windows, signed remediation, scheduling and post-condition verification. | A real fault creates one incident; authorized remediation runs once; recovery resolves it with evidence. Prove the loop on Windows and Mac. |
| **0.4.0: Native attended control** | Shared engine, Windows/Mac capture and input, browser viewer, explicit consent, indicator and local Stop. | Separate physical machines connect directly and through TURN. Loss of consent/connectivity stops input/capture and releases held keys. |
| **0.5.0: Native unattended control** | Service/session supervision, endpoint-enforced policy, reconnects, Windows secure-desktop support and proven Mac session behavior. | Reboot, lock/unlock, user switching, sleep/wake, helper crash and revocation pass the platform matrix. Windows UAC and sign-in control work. |
| **0.6.0: Fleet lifecycle** | Signed auto-update, canaries, staged rollout, rollback, version compatibility, uninstall and revocation. | Bad signatures, incompatible builds, interrupted updates and reconnect failures fail safely or roll back without manual reinstalls. |
| **0.7.0: Technician-complete workflows** | OIDC, refined permissions, pagination, dependable presence, fleet policy, audit export, integrations and support diagnostics. | Another technician installs and operates supported workflows from the docs without author intervention or manual database repair. |
| **0.8.0: Feature complete** | Every promised 1.0 workflow on both endpoint platforms. | Pass the feature-freeze gate below. |
| **0.9.0: Pilot proven** | Mixed-platform fleet evidence, fault drills, capacity measurements, independent security review and candidate upgrades. | Pass the operational gates below. |
| **1.0.0: Supported release** | Verified artifacts, supported upgrades, recovery and support documentation. | Close all gates with evidence; pass final release review. |

Work already underway may finish before its milestone. A script library or server helper handshake does not prove the complete remediation or remote-control workflow.

## 0.2.0 gate and first sprint

| Gate | Exit criterion | Evidence / remaining work |
|---|---|---|
| G02-JOURNAL | Corruption and failed acceptance/start/result/ack writes cannot replay work or expose unsaved state. Legacy quarantines cannot bypass checks after restart. | Journal regressions exercise filesystem failures and repeated reopen/retry. Record before/after failures in [dev-process.md](dev-process.md). Independent review remains required. |
| G02-DURABILITY | State exactly what Windows journal durability guarantees, including rename; verify rather than assume power-loss behavior. | Write/rename error injection is distinct from actual disk exhaustion and power loss. Those drills remain open ([reliability.md](reliability.md)). |
| G02-DEPLOY | Fresh Linux deployment reaches ready, permits real sign-in and enrolls a Windows agent. | Image/config CI alone does not pass. Remove bootstrap credentials and document reproducible configuration. |
| G02-RESTORE | Off-host backup restores into an empty stack; sign-in and agent reconciliation work. | Include FLYW8T_FIELD_KEY, configuration, TLS material and separate signer/root-key recovery. A database dump alone is insufficient. Measure RTO/RPO. |
| G02-PACKAGES | Actual downloaded Windows packages verify; installation authenticates what it installs. Mac signing/notarization prerequisites are documented. | A signing workflow is not artifact or install-time verification evidence. |
| G02-TRUST | One reviewed threat model covers diagnostics, scripts, remote viewing/input, enrollment, policy, revocation and updates. | State compromised-server, stolen-session and stolen-signing-key powers for each path. Script trust and TLS server identity are separate. |
| G02-MAC | Physical Mac capture/input/permission experiments inform the shared engine interface. | Test refusal/revocation, launchd/per-user lifecycle, lock/unlock and sleep/wake. Choose OS/CPU and login-screen support from results. Windows cannot provide this evidence. |
| G02-VALIDATION | Required checks pass at an exact ref/toolchain; new regressions fail without their fixes. | Windows unit/model; Linux PostgreSQL/TLS/browser; fmt, clippy, container checks and independent review. |

First sprint: repair and regression-test the journal; establish a reproducible full test run; reconcile roadmap, guidance and reliability docs; repair script-runner validation without approving its unreviewed implementation; then deployment/restore and Mac experiments.

### Prepared Mac feasibility probe

On a Mac with Xcode command-line tools, close any previous probe and run `bash scripts/mac-feasibility.sh`. It builds an ad-hoc-signed development app under the ignored target directory. No permission prompt, capture or input happens until the local operator presses the corresponding button. Capture is limited to that app's own test window for five seconds, with audio off and no saved images. Tagged keyboard events target only the probe's PID; manual keystrokes are not recorded. Each launch preserves its own JSON report under `target/mac-feasibility/report-<time>-<pid>.json`, always stating that no release gate has passed automatically.

Run interactive mode from a logged-in GUI session. Record a baseline without permissions; refuse/allow each OS prompt; refresh or relaunch as instructed by macOS; capture a complete frame; observe tagged key-down/key-up counts; revoke permissions and repeat. Repeat launches/capture after lock/unlock and sleep/wake and record OS/CPU and results. A successful process-targeted test does not establish system-wide input, mouse control, SSH/launchd behavior, login-screen access, unattended service behavior or transport performance. The build-only CI job checks SDK/API compilation and ad-hoc signature verification; it does not run GUI permission experiments or close G02-MAC. No Mac was available in the 2026-11-12 development session.

API references: [ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit), [content filtering](https://developer.apple.com/documentation/screencapturekit/sccontentfilter), [process-targeted events](https://developer.apple.com/documentation/coregraphics/cgevent).

## 0.8.0 feature-complete gate

All promised workflows work on **Windows and macOS**:

- Install, enroll, inventory, recover after reboot, revoke and uninstall.
- Detect, alert, suppress and resolve supported problems with evidence/freshness.
- Authorize, schedule and execute remediations; verify post-conditions. Exit code alone is insufficient where the contract requires an observed state change.
- Start attended/unattended sessions under device policy, end locally, deny unauthorized tenants/technicians/capabilities.
- Update through canary/staged rollout and roll back a deliberately broken build.

Remote acceptance covers multiple monitors, mixed DPI, resolution changes, keyboard layouts, text input, held-key cleanup, network changes, TURN-only paths, interrupted sessions and browser loss. Windows UAC/sign-in are required. Mac lock/login behavior requires an explicit demonstrated support contract. Permission refusal is actionable, never fake success.

- Freeze OS/CPU/browser/network matrices, launch capacity and numeric performance budgets. Publish hardware/workload; test physical endpoints and synthetic load.
- Complete independent reviews of the shared engine, unattended access, signing, updates and recovery.
- No essential placeholder, dead button or manual database intervention remains.
- Reconcile README, console, threat model, acceptance tests, release notes and operator guide with actual artifacts.
- Freeze features. Exceptions require a recorded decision and re-running affected gates.

The 1.0 patching baseline is visibility plus vetted remediation. Full patch orchestration remains an explicit scope decision. Clipboard/file-transfer features, if included, need separate permissions, disclosure and tests.

## 0.9.0 pilot-proven gate

- Run a mixed Windows/Mac fleet for **30 consecutive days**, using physical endpoints behind several network types. Record device/organization/network counts and coverage; synthetic agents do not replace endpoint evidence.
- Measure session establishment success/time, interactive latency, reconnects, crashes, resource use, readiness and per-action outcomes. Separate direct/relayed paths. Pass the numeric capacity/latency budgets frozen at 0.8; never silently loosen them after failure.
- Test normal fleet load, mass reconnect and supported version skew on published hardware.
- Restore off-host backup into an empty deployment with keys/configuration; measure recovery time and data-loss boundary. Upgrade the supported previous version using candidate artifacts.
- Inject disk-full, journal corruption, database outage, interrupted jobs, revoked access, bad updates and network loss; compare outcomes with documented contracts.
- No unexplained duplicate executions, false success or cross-tenant access. Investigate unknown outcomes without relabelling them to improve the numbers.
- Complete independent security review. No unresolved critical/high findings; lower findings need owner, disposition and evidence for claimed fixes.
- Another technician completes routine operations and recovery from published instructions.

Security-boundary or supported-workflow changes re-open affected gates. Screenshots and two localhost tabs cannot replace network, session or recovery evidence.

## 1.0.0 final release gate

Attach 0.8/0.9 evidence to the exact candidate ref and require:

1. Signed Windows and signed/notarized Mac artifacts; hashes, manifests and install-time checks verify what users actually download.
2. Fresh install, supported upgrade, rollback, restore and uninstall pass the platform matrix.
3. Findings/limitations have explicit dispositions; the threat model describes shipped capabilities and compromise limits.
4. Current operator docs, troubleshooting, support diagnostics and release notes; successful independent operator recovery.
5. Passing automated checks and independent release review. Record ref, date, environment, evidence, reviewer and remaining limits in the gate ledger.

Implementation tests cannot pass a physical-machine, fleet-duration or independent-review gate. Publish through the release workflow after the release decision.

## 1.1 to 1.5: Mobile

- **1.1-1.3:** Android enrollment, identity, permissions, inventory and supported remote support/control; mobile technician workflows over the same scoped API. Decide BYOD versus fully managed-device behavior early; prove it on physical devices.
- **1.4:** mobile freeze/pilot. Test background/foreground, revoked permissions, sleep, network changes, update/rollback and lost-device revocation. Mobile administration never widens role or organization scope.
- **1.5:** Android endpoints and mobile technician administration pass their gates. iOS requires a separately demonstrated, accepted contract.

Android's normal MediaProjection path requires consent per session ([Android documentation](https://developer.android.com/media/grow/media-projection)); enrollment or Accessibility permission alone does not establish silent unattended capture. Mac capture permissions/distribution are product workflows too ([ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit), [Developer ID/notarization](https://developer.apple.com/macos/distribution/)).

## Deferred direction

Linux endpoints; integrations as demand proves them; horizontal HA ([ADR-0009](decisions/ADR-0009-availability-and-scale-out.md)); extensions ([ADR-0007](decisions/ADR-0007-extension-runtime.md)). No mandatory SaaS, Redis, Kubernetes or broker without demonstrated need. AI follows a reliable core and real fleet.
