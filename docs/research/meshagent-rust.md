# Research: is a Rust, MeshAgent-compatible agent worthwhile?

**Status:** research note, not a plan. **Recommendation: not now.** Revisit after flyw8t has a proven fleet and MeshCentral integration (roadmap 0.4).

## What MeshAgent is (checked 2026-10-29 against `Ylianst/MeshAgent`)

- A C codebase (`microstack` networking, `meshcore`, `meshservice`, `webrtc`, bundled `openssl` and `lib-jpeg-turbo`) with **an embedded JavaScript engine** (`microscript`) that runs modules the MeshCentral server pushes to it ("meshcore"). Much of the agent's behavior is server-delivered JavaScript, not compiled code.
- Remote desktop, terminal, file transfer and Intel AMT support, across Windows, Linux, macOS and more architectures.
- Licensing: MeshCentral is Apache-2.0. **GitHub's API reports no license file in the MeshAgent repository**; verify the agent's license terms directly before reusing or reimplementing anything.

## What "MeshAgent-compatible" would require

Speaking MeshCentral's agent protocol well enough that an unmodified MeshCentral server accepts a Rust agent:

1. The agent's binary control protocol and authentication (agent certificates, server hash checks).
2. **Executing the server-pushed meshcore JavaScript**, or reimplementing everything it does natively and tracking it as MeshCentral changes it. The first means embedding a JavaScript engine in flyw8t's agent, with the security consequences in [ADR-0007](../decisions/ADR-0007-extension-runtime.md); the second is a moving target owned by another project.
3. Remote desktop capture, encoding and input, per platform: the hard, permission-laden part (screen recording, accessibility, UAC secure desktop, Wayland).

## Assessment

| Benefit | Cost |
|---|---|
| One agent instead of two on each endpoint | Years of work to match a mature C agent across platforms |
| Rust memory safety for remote-desktop code | Compatibility with a protocol flyw8t does not control; every MeshCentral release is a risk |
| | Either embed a JS runtime that executes server-pushed code (which collapses flyw8t's catalog boundary, threat T1) or reimplement meshcore |

The two-agent cost is real but small: disk, memory and one more service. The compatibility cost is open-ended, and the security cost of executing server-pushed code directly contradicts flyw8t's main safety property.

## Cheaper options to evaluate first

1. **Use MeshAgent as-is** through the provider seam ([ADR-0006](../decisions/ADR-0006-remote-access-provider.md)), with flyw8t's agent installing and supervising it.
2. **A flyw8t-native, narrow remote-view capability** using WebRTC and OS capture APIs. The attended-support proposal ([attended-support.md](../attended-support.md)) explores this for consented, temporary sessions. If that works well, unattended remote view could follow on the same transport without any MeshCentral compatibility.
3. Only if both fall short, a compatibility layer, and then only for the remote-desktop channel, not meshcore.
