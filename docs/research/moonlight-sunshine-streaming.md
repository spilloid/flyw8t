# Native desktop streaming research for issue #53

**Recommendation for review.** The product target is MeshCentral-style access from the Flyw8t browser to the existing desktop, including enrolled machines whose policy permits takeover without a per-session prompt. RDP can be disabled on the endpoint. Build one native sender for attended and policy-authorized sessions. The useful lessons from Sunshine are how to select a capture backend, keep the frame queue short and measure what the viewer actually presents. Supporting a stock Moonlight client would change both the wire protocol and the identity model. [Proposed ADR-0019](../decisions/ADR-0019-native-webrtc-streaming.md) records the boundary and the experiments that could change this recommendation.

## What exists on main

Baseline is Flyw8t `8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f`, workspace version 0.1.7, MIT. “0.10.0” is the issue's planning label. The accepted [release gates](../roadmap.md) govern delivery. The following links refer to the inspected commit. [Workspace members and package metadata][workspace]

| Surface | Executable behavior at this revision | Work the native engine would own |
|---|---|---|
| Session and protocol | `Capability`, `SupportState::after_browser_consent` and `may_relay_signaling` distinguish view and control. The enrollment/job protocol uses `ServerMsg` and `AgentMsg`. Support signaling uses its own socket messages. [State machine][states] · [Agent wire types][wire] | Use the support lifecycle. An agent connection or an accepted job supplies no desktop authority. |
| Server | `visible_session` scopes access. `technician_ws`, `browser_allow`, `spend_helper_token` and `on_message` bind the peers and the two control approvals. `SupportHub::relay` gates signaling and routes a control session to its helper. [Scope][scope] · [Relay][hub] · [Single-use helper attachment][hello] | Retain creator, tenant, capability, seal and audit checks. A successful signal only proves delivery to the peer. |
| Browser | The participant selects a surface with `getDisplayMedia` (audio off). `newPeerConnection`, `oneVideoSection` and `securityCheck` implement a single video section, DTLS certificate checks and a comparison code. An unavailable remote certificate has an explicit UI state. The viewer waits for a frame before showing it as ready. [Picker][picker] · [Topology][shape] · [Certificate check][verify] | First native proof should send exactly this video shape. Audio or a data channel changes the security assumptions and needs a negotiated capability and tests. |
| Network | `FLYW8T_ICE_SERVERS` defaults to an empty list. `selectedRoute` labels the selected ICE pair as direct, TURN or unavailable. The support WebSocket carries signaling. [Config][ice] · [Route reporting][route] | Test NAT and TURN on independent networks. [Earlier relay-first research](remote-control-prior-art.md) recommended a console WebSocket media relay; main has no such transport. Do not count signaling through an ingress as a successful media relay. |
| Helper | `launch_from_file_name` and `run` validate the destination, attach, ask locally, answer and observe termination. After approval the helper waits for session messages. [Helper lifecycle][helper] | Native capture, encoding, DTLS peer verification, media and input still need implementation. The local consent dialog alone proves none of them. |
| Agent and technician | `run_service` hosts the enrolled agent loop. Windows session selection and `shadow_args` belong to the technician's RDP launcher. [Service][service] · [Agent][agent] · [Shadow selection][rdp] | ADR-0013's shared desktop crate and per-session supervisor are absent from the workspace. RDP shadowing already reaches a Windows session but supplies no native WebRTC frames. |
| Other consumers | `MacProbe` exercises a test window and tagged local input. The separately consented MCP screenshot path handles an encrypted envelope at `submit`. [Mac fixture][macprobe] · [Screenshot submission][shot] | A Mac probe is feasibility evidence only. Continuous streaming inherits no screenshot grant, and must never upload plaintext frames to the server. |

## Upstream findings

The source pins are Sunshine `6b176045ccf6`, Moonlight Common C `94c65fd364d1` and Moonlight Qt `2dc63d1f1385`. Each link below names a file at its full commit. These are observations about those revisions.

| Question | What the source establishes | Consequence for Flyw8t |
|---|---|---|
| Where do pixels come from? | On Windows, `duplication_t::init/next_frame` use DXGI Desktop Duplication and `wgc_capture_t::init` opens a WGC capture item. Sunshine documents WGC as incompatible with its service. Its NvFBC integration lives in Linux CUDA code. macOS has a ScreenCaptureKit `startConfiguredStream` path. [DXGI][dd] · [WGC][wgc] · [Configuration][config] · [Linux NvFBC][nvfbc] · [Mac stream][sc] | Run the attended adapter as the participating user. Evaluate each source against the approved surface kind. A WGC window must never fall back to a whole monitor. |
| Who creates session keys? | Qt's `NvPairingManager::pair` implements PIN/certificate pairing. The client generates session material; `NvHTTP::startApp` sends `rikey` and `rikeyid` on HTTPS launch/resume. Sunshine's `make_launch_session` consumes them. [Pair][pair] · [Generation][rng] · [Launch request][start] · [Host][launch] | Keep Flyw8t's existing session identity, consent and DTLS commitment. A PIN is neither the streaming key exchange nor a Flyw8t grant. |
| Who listens and chooses ports? | Sunshine's `net::host_create` binds the ENet host. Common C's `startControlStream` connects its client peer. Sunshine's `cmd_setup` maps the requested stream to a server port and returns it. Common C's `parseServerPortFromTransport` reads it. The handlers and stream-specific ANNOUNCE attributes are a GameStream dialect. [Host][listen] · [Client][connect] · [SETUP][rtsp] · [Port parser][clientrtsp] · [ANNOUNCE][neg] | A generic RTSP or RTP implementation would still need a compatibility layer. None of these listeners or handlers belongs in the native sender. |
| Is ordinary H.264/RTP sufficient? | `videoBroadcastThread` reserves space for `video_packet_raw_t` and fills the per-packet frame index, stream index, start/end flags and FEC block fields. Common C expects `NV_VIDEO_PACKET` including `fecInfo`. Zero parity does not remove the video header. [Sender][fec] · [Receiver layout][packet] | Feed H.264 access units to a WebRTC RTP packetizer. Generic H.264/RTP packets cannot serve as a Moonlight compatibility test. |
| What is discovered or paired? | Qt queries NVHTTP `/serverinfo`, pairs using the PIN and launches over HTTPS. The separate administration API/UI normally uses 47990, including PIN submission. `ComputerManager::startPolling` browses `_nvstream._tcp.local.`; `NvComputer::serialize` retains the host MAC and `wake` constructs the client's magic packet when a MAC is known. [Discovery][mdns] · [Server info][serverinfo] · [Administration][api] · [Stored host][storemac] · [Wake][wol] | Existing enrollment, invitations and technician identity already solve discovery for this product. WoL is a separate management action. |
| Which input stack? | The pinned Windows `should_use_virtualhid_gamepads` checks Virtual HID capabilities. Configuration describes a licensed Virtual HID Broker and a limited legacy ViGEmBus gamepad fallback. Linux uses the virtualhid runtime and needs uinput device permission. macOS also uses libvirtualhid and probes runtime capabilities; `get_mouse_loc` uses Core Graphics. [Windows selection][whid] · [Driver policy][broker] · [Linux runtime][lhid] · [uinput][uinput] · [Mac backend][mhid] | Product requirements call for consented pointer/keyboard control. A gamepad driver, device installation or licensed broker adds no value to that proof. |
| Which codecs and how many sessions? | Common C defines H.264, HEVC and AV1 profile capability masks; Sunshine checks the requested format in `cmd_announce`, has hardware encoder backends and encodes Opus in `encodeThread`. Sunshine release v2025.118.151840 removed its concurrent-stream limit. Resource limits still apply. NVIDIA's discontinued GameStream host and current Sunshine releases are distinct products. [Formats][formats] · [Negotiation][neg] · [Video backends][encode] · [Opus][opus] · [Release notes](https://github.com/SunshineStream/Sunshine/releases/tag/v2025.118.151840) · [Moonlight project history](https://github.com/moonlight-stream/nvidia-gamestream-issues) | Negotiate a single baseline video track first. Keep one controlling technician per granted desktop. Neither codec support nor a concurrency limit is a universal property of GameStream. |

## Build, integrate or support stock clients?

| Option | What we would own | Decision and reconsideration trigger |
|---|---|---|
| Build the native WebRTC sender | User-session capture, hardware encoder availability, media pacing and lifecycle. The browser supplies the viewer and standard ICE/DTLS-SRTP. Our operator and endpoint grants remain authoritative. | **Propose.** Advance only on the staged proof and hardware gates in ADR-0019. |
| Operate a separate Sunshine process | The documented administration surface includes configuration, pairing, app lists and restart. It authenticates administrative requests and documents CSRF handling. That surface offers no documented encoded-frame-to-WebRTC feed or Flyw8t consent binding. Packaging/updating the host, managing credentials, limiting exposure and terminating orphan sessions would all need ownership. [Admin API][api] | **Defer.** Reconsider for a named deployment with a supported, versioned integration contract, isolation model, security review and distribution review. A local process boundary alone settles none of those questions. |
| Become a host for stock Moonlight | Implement and test the NVHTTP pairing and launch lifecycle, GameStream RTSP, packet layouts, control transport and cryptography, then maintain interoperability across client versions. The browser would still need the WebRTC path. | **Separate product decision.** Require client demand, independent license review, a compatibility-fixture owner and a separate ADR and milestone before starting. |

### Dependency and distribution audit

Flyw8t's workspace declares MIT. The inspected Sunshine, Apollo and Vibepollo repositories each carry GPLv3. Moonlight Qt and Common C also carry GPLv3; Common C includes an additional app-store permission. Those projects are references only. The offline fixture uses the Rust standard library. This change adds zero manifest, lockfile, vendored source, binary or driver changes. [Flyw8t][workspace] · [Sunshine][sunlic] · [Apollo][aplic] · [Vibepollo][vlic] · [Qt][qtlic] · [Common C][commonlic]

ADR-0012 names webrtc-rs, whose project lists MIT and Apache-2.0. Before choosing a version, inventory its resolved features, transitive licenses, native crypto/codec libraries and build artifacts on Windows and macOS. Verify hardware Media Foundation transforms on supported Windows editions and drivers. An OS-supplied codec reduces bundling but does not settle patent or distribution questions for a particular product. A future Sunshine bundle or external-process integration needs legal review of distribution, notices/source, coupling and any driver terms. Review separate-process IPC and credential isolation on their technical merits. [webrtc-rs](https://github.com/webrtc-rs/webrtc) · [Microsoft H.264 encoder](https://learn.microsoft.com/en-us/windows/win32/medfound/h-264-video-encoder) · [GNU GPL FAQ on aggregation](https://www.gnu.org/licenses/gpl-faq.html#MereAggregation)

## Prioritized handoff

1. **Now, offline.** Run the [Rust fixture](fixtures/native_stream_probe.rs). It models a one-frame mailbox with synthetic RGBA tiles and logical times. It exercises replacement under backpressure, revocation before delivery and stale callbacks after a new grant. Its results do not measure an encoder, network or display.
2. **Next, synthetic WebRTC.** Send a changing numbered synthetic tile through the candidate H.264 transform and test-only loopback WebRTC peers. Verify packetization/profile, first decoded frame, certificate commitment, cancellation, and absence of new listeners in shipped targets. Evaluate library/driver licensing before adding dependencies.
3. **Then, a test-owned Windows surface.** Obtain a fresh interactive grant for a disposable fixture window. Test WGC on that window; permit DXGI comparison only on an expressly approved, isolated whole display. Compare GPU paths on physical machines, drive no OS input, and publish only counters and latency distributions. Keep the interfaces adaptable for the macOS implementation and operator-run physical permission tests scheduled for 0.11.0.
4. **Before any shipping connection.** Resolve the ADR's open decisions. Exercise direct and forced TURN, browser compatibility, platform changes and endpoint revocation. Future input requires independent review and a separate change. Preserve the roadmap's Windows secure-desktop and physical Mac gates.

### Reproduce the offline check

From the repository root in PowerShell, run the following. The executable is a temporary Rust test binary. The second command lists the three scheduling tests and their outcomes when it runs.

```powershell
rustc --edition=2021 --test docs/research/fixtures/native_stream_probe.rs -o "$env:TEMP/flyw8t-stream-probe.exe"
& "$env:TEMP/flyw8t-stream-probe.exe"
```

[workspace]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/Cargo.toml#L1
[states]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-domain/src/support.rs#L77
[wire]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-protocol/src/messages.rs#L12
[hub]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-server/src/support.rs#L310
[scope]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-server/src/support.rs#L962
[hello]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-server/src/support.rs#L1832
[helper]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-helper/src/lib.rs#L283
[picker]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-web/src/support.js#L473
[shape]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-web/src/support.js#L173
[verify]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-web/src/support.js#L233
[ice]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-server/src/config.rs#L172
[route]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-web/src/support.js#L188
[shot]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-server/src/support/screenshot.rs#L422
[service]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-agent/src/service.rs#L180
[agent]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-agent/src/connection.rs#L61
[rdp]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/crates/flyw8t-technician/src/sessions.rs#L162
[macprobe]: https://github.com/spilloid/flyw8t/blob/8c7037451ac33dcc9a4b3d5bbda58f7c19959e9f/scripts/mac-feasibility.swift#L31
[dd]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/platform/windows/display_base.cpp#L64
[wgc]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/platform/windows/display_wgc.cpp#L103
[config]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/docs/configuration.md#L2344
[nvfbc]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/platform/linux/cuda.cpp#L1396
[sc]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/platform/macos/sc_capture.mm#L211
[serverinfo]: https://github.com/moonlight-stream/moonlight-qt/blob/2dc63d1f138557d15b21c051645280a58702da9d/app/backend/nvhttp.cpp#L134
[pair]: https://github.com/moonlight-stream/moonlight-qt/blob/2dc63d1f138557d15b21c051645280a58702da9d/app/backend/nvpairingmanager.cpp#L238
[start]: https://github.com/moonlight-stream/moonlight-qt/blob/2dc63d1f138557d15b21c051645280a58702da9d/app/backend/nvhttp.cpp#L199
[rng]: https://github.com/moonlight-stream/moonlight-qt/blob/2dc63d1f138557d15b21c051645280a58702da9d/app/streaming/session.cpp#L701
[launch]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/nvhttp.cpp#L487
[listen]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/network.cpp#L207
[connect]: https://github.com/moonlight-stream/moonlight-common-c/blob/94c65fd364d17b223f00a8763c9a5d94a66cb8dd/src/ControlStream.c#L1977
[rtsp]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/rtsp.cpp#L957
[clientrtsp]: https://github.com/moonlight-stream/moonlight-common-c/blob/94c65fd364d17b223f00a8763c9a5d94a66cb8dd/src/RtspConnection.c#L719
[packet]: https://github.com/moonlight-stream/moonlight-common-c/blob/94c65fd364d17b223f00a8763c9a5d94a66cb8dd/src/Video.h#L27
[fec]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/stream.cpp#L1610
[mdns]: https://github.com/moonlight-stream/moonlight-qt/blob/2dc63d1f138557d15b21c051645280a58702da9d/app/backend/computermanager.cpp#L365
[wol]: https://github.com/moonlight-stream/moonlight-qt/blob/2dc63d1f138557d15b21c051645280a58702da9d/app/backend/nvcomputer.cpp#L216
[storemac]: https://github.com/moonlight-stream/moonlight-qt/blob/2dc63d1f138557d15b21c051645280a58702da9d/app/backend/nvcomputer.cpp#L77
[api]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/docs/api.md#L5
[whid]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/platform/windows/input.cpp#L536
[broker]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/docs/configuration.md#L337
[lhid]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/platform/linux/input/virtualhid.cpp#L21
[uinput]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/docs/configuration.md#L47
[mhid]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/platform/macos/input.cpp#L23
[formats]: https://github.com/moonlight-stream/moonlight-common-c/blob/94c65fd364d17b223f00a8763c9a5d94a66cb8dd/src/Limelight.h#L227
[neg]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/rtsp.cpp#L1024
[encode]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/video.cpp
[opus]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/src/audio.cpp#L110
[sunlic]: https://github.com/SunshineStream/Sunshine/blob/6b176045ccf63e393d6d5f86be4938e0bc3c2f44/LICENSE
[commonlic]: https://github.com/moonlight-stream/moonlight-common-c/blob/94c65fd364d17b223f00a8763c9a5d94a66cb8dd/LICENSE.txt#L678
[qtlic]: https://github.com/moonlight-stream/moonlight-qt/blob/2dc63d1f138557d15b21c051645280a58702da9d/LICENSE
[aplic]: https://github.com/ClassicOldSong/Apollo/blob/adc5c5a0bd80831ce495434bb16aee2cd4175fb8/LICENSE
[vlic]: https://github.com/Nonary/Vibepollo/blob/1f9ea16c697b18499ae414c4e783416f9df84b46/LICENSE
