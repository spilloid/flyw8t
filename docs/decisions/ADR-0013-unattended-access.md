# ADR-0013: Unattended remote access, on our own engine

**Status:** accepted (operator, 2026-10-30; corporate-strategy D-0056) · supersedes the "MeshCentral first" parts of [ADR-0006](ADR-0006-remote-access-provider.md) for remote control · builds on [ADR-0012](ADR-0012-remote-control-helper.md)

## Context

The operator: flyw8t should be a *useful, reliable* agent that a technician can see online and connect to, and take control of. That means Windows, macOS and Linux (X11 and Wayland) desktops first, with iOS and Android much later. On direction: "the direction of this tool changed. We are building from scratch. We're doing Rust. We're making it the best, so it becomes the new standard."

## Decision

### 1. One engine, two uses

The capture, encoding, input and WebRTC engine built for the attended helper (ADR-0012) is a library crate, `flyw8t-desktop`, used by:
- the **attended helper**, which a person runs, consents in, and closes;
- a **desktop component of the agent** for unattended access: a per-user-session process the agent service starts and supervises, because services cannot see or drive a user's desktop.

There is one viewer (the technician's browser page), one signaling path and one security code scheme. MeshCentral is no longer planned for remote control. The `RemoteAccessProvider` seam (ADR-0006) stays, so another backend can still be plugged in.

### 2. Consent is a per-device policy

| Mode | At the machine | Use |
|---|---|---|
| **Notify with Stop** *(default)* | A banner names who is connected, with **Stop** | Staffed desktops |
| **Ask first** | The signed-in user must allow; no answer means no connection | Sensitive or shared desktops |
| **Notify without Stop** | A banner that cannot dismiss the session | Kiosks and lab machines |
| **Silent** | Nothing on screen | Servers and unstaffed machines |
| **Calling card** (an extra, combinable with any mode) | A timestamped record left on the machine after every session: who, when, how long | Accountability where people were away |

- **Who sets it:** the policy is set per device, with an organization default. Only administrators can choose Silent, and changing a policy is audited.
- **Built first:** the default mode, Notify with Stop. The others follow on the same model.
- **In every mode:** the session is audited, the technician needs MFA, and the console shows the policy in force before connecting.

### 3. The agent gains a privilege, deliberately

Until now the agent's rule was "read-only catalog actions only". Unattended control is a different and much larger power, so:
- it is a separate capability, **off unless the device's policy enables it**;
- it is granted per session by the server and refused by the agent unless that device's policy (signed into its enrollment, not only stored on the server) allows it;
- the catalog stays read-only for jobs.

### 4. Platforms, in order

1. **Windows.** A service plus a per-session desktop process (CreateProcessAsUser into the active console session). Windows.Graphics.Capture / DXGI and `SendInput`; the secure desktop (UAC, lock screen) is reachable from a SYSTEM process in the user's session, which is in scope for unattended mode.
2. **Linux X11.** XShm/XComposite capture and XTest input.
3. **macOS.** A launchd daemon plus a per-user agent, using ScreenCaptureKit and CGEvent. The user must grant Screen Recording and Accessibility; MDM can pre-approve Accessibility but not Screen Recording. This is honest friction, and the docs will say so.
4. **Wayland.** The xdg-desktop-portal ScreenCast and RemoteDesktop portals. The compositor asks the user for consent, and restore tokens can make that persistent on GNOME and KDE. Fully silent unattended control on Wayland is limited by design, and the docs will say so.
5. **iOS and Android: much later.** iOS allows no remote input at all, and screen broadcast only on the user's action. Android can be controlled through MediaProjection plus an AccessibilityService. A technician's *viewer* app (React Native or similar) is a separate, later question.

### 5. Reliability is a feature

- **Presence:** online and offline status comes only from the live connection registry, as it does today. Last seen, agent version and policy are shown next to it.
- **Packaging:** each agent ships as a signed installer per OS (MSI, pkg, deb and rpm).
- **Updates:** signed auto-update (ADR-0008) becomes a requirement, because a fleet you cannot update is not reliable.

## Consequences

- **Larger security surface:** the agent becomes remote-control infrastructure. The threat model gains unattended-access threats, including a stolen technician session, a compromised server pushing a session, and policy tampering. Each step gets the top-tier cross-family review.
- **Build order:**
  1. the engine (`flyw8t-desktop`), proven first through the attended helper (ADR-0012 steps 2 to 4);
  2. the Windows agent desktop component with Notify with Stop;
  3. the device policy model and the console;
  4. Linux X11;
  5. macOS;
  6. Wayland;
  7. the remaining consent modes and the calling card.
- **Signing everywhere:** Windows through the existing Azure Artifact Signing. macOS needs an Apple Developer ID and notarization, a **recurring cost that needs the operator's approval** when the macOS step arrives.
