# Windows attended practice board

This opt-in developer fixture pairs a local Edge viewer with a Rust process over an ordered, reliable WebRTC data channel. A technician can click cells and type into the native process's practice board. The participant compares a six-digit code and clicks **Allow board control** in its Windows window. **Stop**, closing either window, a lost connection, invalid input, or the two-minute lifetime ends the session and releases held board keys and buttons.

## Try it on one Windows workstation

From `scripts/windows-media-probe`, use the repository's Rust toolchain and installed Microsoft Edge.

```powershell
npm.cmd ci --ignore-scripts
cargo build --locked --features owned-board --example owned-control
node owned-control.mjs target/x86_64-pc-windows-msvc/debug/examples/owned-control.exe
```

The launcher opens the Edge viewer. The Windows practice window appears after the native peer verifies the viewer certificate. Compare the two codes, click **Allow board control** in the native window, then click a cell and type in Edge. The marker and text should change on both sides. Click **Stop** on Windows while holding a board key or mouse button. A fresh session requires a new launch and decision.

The following check builds the Windows program, runs the native model tests and drives a real Edge-to-Rust keyboard and pointer round trip against a test-only in-memory participant. It resolves executable paths from Cargo build output and also works with a custom Cargo target directory.

```powershell
node owned-control-check.mjs
```

The local launcher starts one temporary Edge context and one native process. Private launcher bindings carry one session ID, the viewer's SHA-256 commitment and one SDP exchange. The native peer checks the certificate on the actual DTLS transport before displaying a consent window. The board updates shown by Edge are endpoint acknowledgments. The fixture accepts a single loopback SCTP transport and never binds an application listener.

Before sending an offer, the endpoint registers a hidden window for Windows session and input-desktop changes. It records the active console or RDP login, including its logon time. The same numeric session ID can identify a later login. The endpoint checks the recorded login when the technician connection is verified, at local Allow, before applying each input, and while idle. A queued desktop-switch notification also ends authorization if Windows has already switched back. These callbacks are asynchronous. [Windows session notifications](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification) · [Windows event-hook delivery](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwineventhook)

After Allow, the endpoint sends a fresh random value over the verified channel. Every input packet must echo that value and carry the next sequence number. Closing the owner pipe cancels pending network writes and releases held input. A fresh login or connection must go through pairing and consent again.

The Edge check exercises viewer disconnect, supervisor revocation while SCTP stays open, and a simulated replacement login while a key and mouse button are held. A separate Windows test posts a lock notification to the fixture's hidden window. Physical lock, user switching and local Stop still need a two-person trial on an enrolled PC.

The practice board is a fixed eight-by-four surface inside the fixture process. It accepts a bounded pointer position, a primary button and printable single-key events. It has no interface for controlling another Windows application. The test launcher exercises endpoint gating and cleanup with a simulated participant decision only in the Rust **test binary**. A human still needs to verify the native consent and Stop window.

The existing Support viewer, device policy, and signed Windows binaries use their existing entry points. Browser video and authenticated in-product control over a selected Windows desktop, organization MFA and grants, physical Stop, TURN and the independently distributed production viewer have their own integration and acceptance work.
