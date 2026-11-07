# Remote control: what others publish about how they do it

**Date:** 2026-11-07 · **For:** the `flyw8t-desktop` engine (ADR-0012 next step) and the agent's desktop component (ADR-0013)

We looked at ScreenConnect, NinjaOne Remote and Splashtop (closed source; they publish little about mechanics), plus MeshCentral and RustDesk (open source; MeshCentral publishes a real design document). Vendor statements are their claims, not verified. "Community" means forum posts, not documentation.

## Findings

### 1. Everyone dials out on 443 to a relay; direct paths are an upgrade, not a requirement

- **NinjaOne** relays all session traffic through its own servers over 443, with TCP 7075 as a fallback, and supports HTTP(S) and SOCKS5 proxies ([NinjaOne docs][ninja]).
- **Splashtop** endpoints each open TLS to a relay over 443, and the relay brokers the session ([Splashtop cloud security][st-pdf]).
- **ScreenConnect** splits the web server (8040) from a separate relay service (8041). Community posts report the relay cannot sit behind a web proxy or Cloudflare Tunnel ([community][sc-cf]).
- **MeshCentral** starts every session on a WebSocket relay through the server, and then tries to upgrade it to WebRTC. The WebSocket stays open, and closing it ends the session. Its design notes say no TURN server is needed ([design][mesh], [Intel][mesh-webrtc]).
- **RustDesk** tries a direct connection first, and falls back to its relay (`hbbr`) when that fails ([admin-magazine][rd]).

**For flyw8t:** start on a WebSocket relay through the console, then upgrade to WebRTC when it can, as MeshCentral does. That works through Cloudflare Tunnel and reverse proxies, which ScreenConnect's separate relay port does not. It also means we never have to run TURN.

### 2. The relay should not see the screen, and that depends on who vouches for the keys

- **Splashtop** says the endpoints agree the session key between themselves, so the data can only be decrypted at the endpoints ([Splashtop][st-pdf]).
- **RustDesk's** relay sees only ciphertext ([wz-it][rd-de]).
- **MeshCentral's** relay is **not** end to end: the server decrypts and re-encrypts. Its WebRTC upgrade carries the agent's DTLS certificate hash over the trusted control channel ([design][mesh]).

**For flyw8t:** ADR-0012 already says the server never sees media, and WebRTC's DTLS provides that. But the DTLS fingerprints travel through the server's signaling, so a compromised server could swap them and sit in the middle. Protecting against a malicious server needs the fingerprints signed by keys the endpoints already trust. The technician's key would come from ADR-0014's trust list, and the server key pinned at enrollment would cover the agent side. That makes the server-identity-pinning ADR a prerequisite for "end to end", not a separate concern.

### 3. Agents pin the server's key at install

- **MeshCentral** agents hold a hash of the server's private certificate. On connect, the server proves it holds that key in a second handshake (RSA-3072, SHA-384, fresh nonces).
  - The agent ignores management messages until that handshake passes.
  - The agent accepts a relay URL only if the server presents the same outer TLS certificate as the control connection ([design][mesh]).
- **RustDesk** clients are configured with the server's Ed25519 public key ([rustdesk-server][rd-srv]).
- **ScreenConnect** installers carry a public key thumbprint that ties each client to its server ([Naverisk][sc-thumb]).

**For flyw8t:** every product we looked at pins a server key when the agent is installed, so pinning at enrollment is the normal approach. MeshCentral's check against the outer certificate is a form of channel binding, which is the part that conflicts with TLS-terminating proxies (our earlier finding). The pinning ADR should decide how we cover both cases.

### 4. Windows: a separate streamer, started with the rights to see UAC

- **NinjaOne:** its agent installs a separate streamer (`ncstreamer.exe`) on each enrolled Windows device. Technicians use a separate player (`ncplayer.exe`) ([NinjaOne docs][ninja]).
- **ScreenConnect:** to see and answer UAC prompts, a session has to be elevated into "service mode".
  - An installed agent's access sessions are already in service mode.
  - An attended support session asks the person to approve elevation, and leaves service mode when the session ends ([ConnectWise docs][sc-uac]).

**For flyw8t:** this matches ADR-0013's plan.
- The agent service starts a separate desktop process in the user's session, running as SYSTEM so it can reach the secure desktop.
- The attended helper (ADR-0012) asks the person before it elevates, and stops being elevated when the session ends.
- Keep the desktop part a separate signed binary, as NinjaOne and Splashtop both do. Then the agent's catalog-only rule stays simple to audit.

### 5. What the end user sees and the controls around a session

| Control | Who publishes it | flyw8t today / plan |
|---|---|---|
| Consent prompt, with a timeout and a policy for when nobody is there | ScreenConnect (KB title only; the timeout detail is from the community), MeshCentral (set per device group) ([sc-consent][sc-consent], [Intel][mesh-consent]) | ADR-0013: a per-device policy, default "notify with Stop". Decide what happens at the lock screen and when nobody is signed in. |
| A visible bar showing a session is live | MeshCentral "privacy bar". Its own issue tracker calls it a **notice, not a security control**: anyone with root can hide it ([issue][mesh-bar]) | Our Stop notice should be described the same way. |
| Blank the remote screen and lock the remote keyboard | Splashtop ([blog][st-blog]) | Not planned yet. Worth adding for unattended sessions. |
| What happens when the session ends: nothing, lock, or sign the user out | NinjaOne ([docs][ninja]) | Not planned. Lock on end is a cheap, sensible default. |
| Clear the clipboard at the end | NinjaOne (press) ([kbi][ninja-press]) | Not planned. Copy it. |
| Idle timeout and maximum session length | NinjaOne, Splashtop | Support sessions have limits already. Carry them over. |
| End the session if the technician's public IP changes | NinjaOne ([docs][ninja]) | Interesting. We already end sessions at sign-out. This is a cheap extra against a hijacked technician session. |
| Recording | NinjaOne (auto-record), ScreenConnect ("video auditing") | Not planned. The server never sees media, so a recording would have to come from the technician's side or be opt-in at the endpoint. That needs a decision. |
| Run commands without being seen ("Backstage") | ScreenConnect. Community posts complain that anyone with access gets it, with no separate permission ([sc-backstage][sc-backstage]) | Avoid that mistake: a hidden mode would need its own permission, sudo mode and the audit log. |

## What this does not settle

- None of the closed-source vendors publish their capture or encoding pipeline, how they handle the secure desktop, or their key exchange in detail. For those we have ADR-0013's own plan (Windows.Graphics.Capture / DXGI, `SendInput`, a SYSTEM process in the user's session).
- RustDesk's exact handshake would need its source. Nothing we found describes it.
- The Splashtop white paper's full text was not read; only search excerpts were used.

[ninja]: https://www.ninjaone.com/docs/remote-and-quick-connect/getting-started-with-remote-access/
[ninja-press]: https://kbi.media/?p=25561623
[st-pdf]: https://splashtop.com/api/assets/2WcfKvs6YRyWhNu6mxUVFl/Splashtop-Cloud-Security.pdf
[st-blog]: https://www.splashtop.com/blog/understanding-splashtops-multilayered-approach-security
[sc-cf]: https://screenconnect.product.connectwise.com/communities/1/topics/4579-allow-sc-web-and-relay-server-to-be-both-proxied-on-cloudflare-using-cloudflare-tunnels
[sc-thumb]: https://kb.naverisk.com/en/articles/2832825-screenconnect-configuration
[sc-uac]: https://docs.connectwise.com/ScreenConnect_Documentation/Get_started/Knowledge_base/Control_Windows_UAC_dialogs
[sc-consent]: https://screenconnect.product.connectwise.com/communities/1/topics/3747-lock-screen-on-connect-only-if-consent-timer-runs-out-access
[sc-backstage]: https://control.product.connectwise.com/communities/1/topics/2612-restrict-access-to-backstage
[mesh]: https://docs.meshcentral.com/design/
[mesh-webrtc]: https://www.intel.com/content/www/us/en/developer/articles/news/meshcentral2-now-with-webrtc-support.html
[mesh-consent]: https://www.intel.com/content/www/us/en/developer/articles/technical/meshcentral2-multi-os-user-consent-feature.html
[mesh-bar]: https://github.com/Ylianst/MeshCentral/issues/382
[rd]: https://admin-magazine.com/Articles/Self-hosted-remote-support/(offset)/3
[rd-de]: https://wz-it.com/knowledge/remote-access/teamviewer-alternative-self-hosted/
[rd-srv]: https://github.com/l3278b/rustdesk-server
