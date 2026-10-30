# ADR-0012: Attended remote control: the helper

**Status:** proposed · **Date:** 2026-10-30 · Builds on [ADR-0010](ADR-0010-attended-support.md) (Phase C approved by the operator, D-0055)

## Context

Phase B lets a person show a technician their screen through the browser. Phase C adds keyboard and mouse. A browser cannot inject input into the operating system, so control needs a native program on the participant's machine. The founding constraints still hold: consent first, nothing installed or left behind, no unattended access, and the server never sees media. Windows comes first, because the agent and the fleet are Windows.

## Decision

### 1. One small signed helper, run by the person, not installed

`flyw8t-helper.exe` is a single Rust binary, Authenticode-signed, downloaded from the consent page and run by the person being helped. It:
- installs nothing (no service, no autostart, no registry);
- writes no credentials to disk;
- exits when the session ends, when its window closes, or when its **Stop** button is pressed.

It runs with the person's own rights. It cannot reach UAC prompts or the secure desktop, because that needs a service, and it will not install one. The technician is told this up front.

### 2. Pairing: a one-time launch token, bound to the consented session

When the person allows control, the consent page asks the server for a **launch token**, which is:
- single-use and valid for 2 minutes;
- bound to that participant's session and to the `control_input` capability;
- stored as a hash.

The token travels in the downloaded file's name (`flyw8t-helper-<token>.exe`), the same pattern ScreenConnect uses, so the person never types anything. If the name has been changed, the helper asks for a short code shown on the consent page instead.

The token buys only a WebSocket attach as the session's **helper peer**. It grants nothing until the helper's own consent (step 4).

### 3. Media and input over WebRTC, end to end, through the existing signaling

The helper is a WebRTC peer built on `webrtc-rs`, in place of the participant's browser tab:
- **Video:** captured with Windows.Graphics.Capture and encoded as H.264 with Windows' own Media Foundation encoder. That encoder ships with Windows, so there is no codec to bundle and no patent-licence question.
- **Input:** travels back from the technician on a **reliable, ordered data channel**, as typed messages: pointer position as fractions of the shared surface, buttons, wheel, and keys as virtual-key and scan codes. The helper applies them with `SendInput`, clamped to the shared monitor.
- **Server's role:** it still relays signaling only, and only after consent. It sees no pixels and no keystrokes.
- **Security code:** the existing committed code applies unchanged. The technician commits to its certificate, and the helper checks the certificate DTLS actually uses. The helper shows the code in its own window, so the person compares it there.

### 4. Two consents, the second inside the helper

The browser consent ("allow control, download the helper") is the first. The helper then shows its own window naming the technician, the server host, the security code and exactly what is being allowed. It starts nothing until the person presses **Allow**.

While control is active, an always-on-top indicator stays on screen, showing who is in control, with **Stop**. Pressing **Stop**, closing the indicator, or a session ending anywhere stops capture and input at once, in the helper itself (fail closed, as in Phase B).

Ending the session takes **Ctrl+Alt+Shift+S**, a combination no remote input can produce: the helper only acts on it when it comes from the physical keyboard.

### 5. Audit and limits

- **Audit:** every grant, start and stop of control is audited, with actor, session and organization. The server records control *sessions*, never keystrokes.
- **Capabilities:** control is the new `control_input` capability. It is requested when the session is created, shown on the consent page, and can never be added to a session that started as view-only.
- **Permissions:** creating a control session is a separate permission from viewing, held by technicians and administrators and narrowable per organization later.

## Alternatives considered

| | Why not now |
|---|---|
| MeshCentral's attended features through ADR-0006 | Approved direction is a flyw8t-native attended helper; MeshCentral stays the unattended path. |
| Port MeshAgent | Explicitly excluded by the founding brief. |
| VP8/VP9 via libvpx, or bundled openh264 | A C dependency to build and ship (libvpx), or patent licensing that holds only for Cisco's own binaries (openh264). Media Foundation H.264 ships with Windows. |
| A custom media protocol instead of WebRTC | Loses end-to-end DTLS-SRTP, NAT traversal, and the technician's browser as the viewer. |
| Making the flyw8t agent the helper | Attended help must work on machines that are not enrolled, and must leave nothing behind. The agent is unattended infrastructure, and its read-only catalog rule stays intact. |

## Consequences and costs

- **Signing:** the helper must be Authenticode-signed before anyone is asked to run it. Unsigned, SmartScreen warns, and a warned-through download is a bad habit to teach people. Signing uses the company's existing Azure Artifact Signing account (corporate-strategy D-0047; SpoolSmith and PortGlass already sign through it), so adding flyw8t is configuration, not new spend. The agent and server binaries get signed the same way (roadmap 0.2).
- **Scope:** a new crate, `flyw8t-helper` (Windows-only for now), and server changes: a helper peer side, launch tokens, the `control_input` capability, and a migration.
- **Testing:** helper capture, encoding and `SendInput` can be tested on the Windows CI runner against a test window. Input injection is tested only against a window the test owns. The browser viewer gains a data channel and input capture, tested in Chrome.
- **macOS** (ScreenCaptureKit plus Accessibility consent) and **Linux** (PipeWire portal and the RemoteDesktop portal) come after Windows is proven, each with the OS's own consent prompts.

## Build order

 1. **Done (2026-10-30).** Server: the `control_input` capability (`RunControlSessions` permission), launch tokens, the helper peer side, audit, migration 0005, and the `awaiting_helper` state. The browser page offers the helper download (`FLYW8T_HELPER_PATH`); no helper binary exists yet.
2. Helper: pairing, signaling, and WebRTC with a synthetic test pattern (no capture yet). An end-to-end test goes from browser technician to helper.
3. Capture and encoding (Windows.Graphics.Capture and Media Foundation).
4. Input: the data channel, `SendInput`, the indicator, and the hotkey.
5. Signing and release packaging; the consent page's download flow.
6. A cross-family review before anyone is asked to run it.
