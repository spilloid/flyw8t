# Attended support

**Status:** Phase A (architecture and threat model): this document. Phase B (browser screen view with consent): **implemented and tested**; see the status table at the end. Phase C (native helper with input) is **designed only, and needs an operator decision** ([ADR-0010](decisions/ADR-0010-attended-support.md)), because it is remote-desktop control, which the founding brief said not to build from scratch.

## The experience

1. A technician opens flyw8t → **Support** → *New session*, and chooses what to request. Phase B offers only *view screen*.
2. flyw8t shows a **9-digit code** and an **invitation link**, both single-use and valid for 10 minutes.
3. The person being helped opens the link (or goes to `/s` and types the code). **No account, no install.**
4. They see **who** is asking (the technician's name and email, as flyw8t knows them), **what** is being asked for, in plain words, and a matching code to read aloud.
5. They choose *Allow* or *Decline*. Allowing opens **the browser's own screen picker**; they choose a tab, window or screen, or cancel.
6. The technician sees the shared content. Both sides see the connection state, the granted capabilities, and an *End session* button that works at any moment.
7. Ending (by either side, by expiry, or by revocation) closes the media, invalidates every credential for the session, and records why.

## Two kinds of attended help, never confused

| | **Browser screen view** (Phase B) | **Temporary native helper** (Phase C, proposed) |
|---|---|---|
| Install | None | A small signed Rust executable the user downloads and runs; nothing persistent |
| What the technician gets | **Pixels only**: what the user picked in the browser's picker | Screen capture plus, on separate consent, keyboard and mouse |
| OS permission | The browser's screen-share prompt | OS prompts as required (macOS Screen Recording + Accessibility; Wayland portal) |
| Can it control the machine? | **No.** Browsers expose no input injection, and flyw8t does not pretend otherwise. | Only after a distinct "allow control" consent; revocable instantly |
| UI wording | "View screen (no control)" everywhere | "Control keyboard and mouse" as its own request |

The console never calls a browser screen view "remote desktop" or "remote control".

## Components and reuse

```text
 Technician browser                 flyw8t server                    Remote user's browser
 (signed-in console)        (existing auth, audit, rate limits)       (no account)
 ┌──────────────────┐   WSS   ┌────────────────────────────┐   WSS   ┌──────────────────┐
 │ /support/{id}    │◄──────►│ support signaling           │◄──────►│ /s/{invite}       │
 │ viewer (video)   │ signals│  · session state machine    │ signals│ consent + picker  │
 └────────┬─────────┘        │  · relays opaque SDP/ICE    │        └────────┬──────────┘
          │                  │    only after consent       │                 │
          │                  └────────────────────────────┘                  │
          │        WebRTC media (DTLS-SRTP, end-to-end encrypted)            │
          └──── direct (LAN / NAT traversal via STUN) ── or via TURN ────────┘
                         (TURN relays ciphertext only)
```

| Need | Reused from the existing repository | New |
|---|---|---|
| Technician identity | session auth, roles, CSRF (`auth.rs`, `web.rs`) | permission `RunSupportSessions` (technician, admin) |
| Audit | `audit::Audit`, append-only `audit_events` | `support.*` actions; append-only `support_events` |
| Abuse limits | `ratelimit::RateLimiter` | per-IP code-guess and session-create limits |
| Pages | Leptos SSR shell, CSS, flash messages | `/support`, `/support/{id}`, `/s`, `/s/{invite}` |
| Live sockets | the agent registry pattern (`registry.rs`) | a per-session two-party signaling hub |
| State machine discipline | `domain::job` (legal-transition table, exhaustive tests) | `domain::support` |
| Typed wire messages | `flyw8t-protocol` conventions | `SupportSignal` envelope |

**Not reused, on purpose:** the agent. Attended sessions do not need flyw8t's agent installed and never create or enroll one. Unattended access remains a separate, explicit enrollment workflow.

## Session state machine

```text
created ─► waiting ─► authorizing ─► connecting ─► connected ─► disconnecting ─► closed
   │          │            │              │             │
   │          │            ├─► rejected   ├─► connection_failed
   │          ├─► expired  │              │
   └──────────┴────────────┴──────────────┴─────────────┴─► revoked (technician or admin ends it before close)
```

| State | Meaning | Leaves by | Timeout |
|---|---|---|---|
| `created` | Recorded; invitation not yet issued (same transaction) | invitation issued | — |
| `waiting` | Code and link valid; nobody has opened them | remote opens → `authorizing`; expiry → `expired`; technician ends → `revoked` | 10 min from creation |
| `authorizing` | The remote participant is bound (the code is now spent) and sees the consent screen | Allow → `connecting`; Decline → `rejected`; expiry → `expired`; either ends → `revoked`/`closed` | 5 min |
| `connecting` | Consent given; WebRTC negotiating | both report media flowing → `connected`; failure or timeout → `connection_failed` | 60 s |
| `connected` | Media flowing | either ends → `disconnecting`; transport lost → `connection_failed` | session cap 4 h |
| `disconnecting` | Teardown in progress | → `closed` | 10 s |
| **terminal:** `closed`, `expired`, `rejected`, `connection_failed`, `revoked` | Credentials invalid; sockets closed; the session cannot be reopened (a new session is needed) | — | — |

Rules:
- Only the server changes state, and only along the table (a domain function with exhaustive tests, like jobs).
- **No SDP or ICE message is relayed before the participant's explicit consent.** The server drops signaling in `waiting`/`authorizing`, so a technician cannot start media before consent.
- Capabilities are fixed when the session is created and shown on the consent screen. Asking for more (for example control) means **a new consent**; it can never activate from an existing grant.
- Every terminal transition closes both sockets and invalidates the invitation and participant credentials in the same transaction.

## Credentials

| Credential | Form | Lifetime | Stored as |
|---|---|---|---|
| Pairing code | 9 random digits | single use; 10 min | SHA-256 |
| Invitation link | `/s/<32 random bytes, base64url>` | single use; 10 min | SHA-256 |
| Participant credential | random cookie set when the code or link is spent (`HttpOnly`, `SameSite=Strict`, path `/s`) | until the session ends | SHA-256, cleared at end |

A code or link **is not authorization.** It only gets someone to the consent screen. Spending it binds the session to that one browser, so a second person with the same code is refused. Authorization is the person's explicit Allow, and then the browser's own picker.

Code guessing: 9 digits give a 10⁹ space; with a handful of sessions live at once and code entry limited to 10 attempts per IP per 10 minutes, a single source's success probability per window is about 10⁻⁸. Codes are compared as hashes, and a wrong code gives the same response as an expired one.

## End-to-end encryption and the server's position

WebRTC media is DTLS-SRTP between the two browsers; neither the flyw8t server nor a TURN relay sees plaintext. **However, the signaling server carries each side's DTLS fingerprint inside the SDP, so a malicious or compromised signaling server could substitute its own and sit in the middle.** Mitigation: both pages compute a **short authentication string** from the two DTLS fingerprints actually in use (SHA-256 of the sorted fingerprints, shown as three groups of digits). The technician reads theirs aloud; the user checks it matches. A relay that intercepted the media would produce different fingerprints and a different code. This is the same defense used by Signal and ZRTP-style calls, and it is what makes "public relay operators cannot impersonate participants" true rather than assumed.

## Relay, NAT traversal and deployment

| Mode | How | Needs |
|---|---|---|
| LAN-direct | host ICE candidates | nothing |
| NAT traversal | STUN server(s) in `FLYW8T_ICE_SERVERS` | a STUN server (any public one, or self-hosted coturn) |
| Relay fallback | TURN in `FLYW8T_ICE_SERVERS` | self-hosted coturn (sees SRTP ciphertext only) |
| Public community relay | a flyw8t instance run by someone else, used only for signaling + TURN | **never required**; same binary and config as self-hosted |

`FLYW8T_ICE_SERVERS` defaults to empty (LAN only), so **no third party is contacted unless an operator configures one.** Changing relays never touches agent identities: attended sessions do not involve agents.

## Threats specific to attended support

| Threat | Control |
|---|---|
| Malicious technician starts viewing without consent | Server refuses to relay signaling before Allow; the browser's own picker is a second, unforgeable consent. |
| Malicious technician escalates (view → control) | Capabilities fixed at creation; escalation requires a new session and a new consent; Phase B has no control capability at all. |
| Technician impersonation (a scammer with a flyw8t install) | The consent page states the requester's name, email and organization **as asserted by this flyw8t server**, and the server's own hostname, so a user can see which server is asking. A self-hosted server can lie about its own users; the page says "verified by <hostname>", not "verified". |
| Code interception / shoulder-surfing | Single use; binding to the first browser; 10-minute expiry; consent still required. |
| Code brute force | Per-IP limits; uniform responses; hashed codes. |
| Signaling-server man-in-the-middle | Short authentication string over the DTLS fingerprints. |
| Malicious remote participant attacks the technician | Signaling messages are size-capped (64 KiB), typed, and relayed only to the paired peer; the viewer renders a `<video>` element only; no file or clipboard channel exists. |
| Resource exhaustion | Per-technician cap on concurrent sessions; per-IP creation and guess limits; every state has a timeout. |
| Session outlives intent | 4-hour hard cap; ending from either side is immediate; the server closes both sockets on any terminal state. |
| Unattended persistence via an attended session | Impossible in Phase B (nothing is installed). Phase C's helper deletes its credentials on exit, installs no service, and cannot enroll. |

## Phase C: temporary native helper (proposed, not built)

- A signed (Authenticode / Developer ID) Rust binary, downloaded from the consent page and run by the user; it shows a persistent, always-visible indicator with a *Stop* button.
- It pairs to the same session using the participant credential (passed via a one-time launch token, not a URL the browser could leak), and offers capture (Windows Desktop Duplication / macOS ScreenCaptureKit / PipeWire portal) and, **after a separate consent**, input (Windows `SendInput`, macOS Accessibility, portal remote-desktop).
- It **never bypasses OS consent**: no UAC secure-desktop access (that requires a service, which it will not install), no TCC manipulation, no Wayland workarounds.
- File transfer, shell and elevation are separate capabilities with their own consents and policies, and are out of scope until the core helper is proven.
- It exits and deletes everything at session end; nothing persists.

This is remote-desktop control. The founding brief says not to build remote desktop from scratch and to use MeshCentral first. **Phase C proceeds only if the operator decides the attended helper is a distinct product need that MeshCentral does not meet** ([ADR-0010](decisions/ADR-0010-attended-support.md)).

## Implementation status (2026-10-29)

| Item | Status | Evidence |
|---|---|---|
| Session state machine (`domain::support`) | Implemented | exhaustive transition tests; consent is the only way into `connecting` |
| Code + link invitations, single use, hashed, 10-minute expiry | Implemented | `consented_session_relays_signaling_and_ends_cleanly`, `invitations_expire_and_guessing_is_limited` |
| Consent page: requester identity, capability text, what they cannot do | Implemented | `support_browser` screenshots; `consented_session_…` asserts the wording |
| No signaling relayed before consent; technician cannot consent for the participant | Implemented | `consented_session_…`; a mutant that relays early is caught |
| WebRTC screen view between two browsers | Implemented | `two_browsers_pair_consent_and_share_a_tab`: headless Chrome, real media, video frames received |
| Short authentication string over both DTLS fingerprints | Implemented | same test asserts both sides compute the same code |
| End from either side; leaving mid-session ends it; credentials cleared | Implemented | `decline_and_technician_revocation`, `consented_session_…` |
| Cross-site WebSocket handshakes refused (Origin) | Implemented | `access_control_and_cross_site_sockets` |
| Per-technician session cap, per-IP code-guess limit | Implemented | `invitations_expire_and_guessing_is_limited` |
| STUN/TURN through `FLYW8T_ICE_SERVERS` | Implemented (config); **only LAN/loopback tested** | no NAT or TURN path has been exercised |
| Cross-family security review of the support code | **Not done** | blocking before anyone relies on it |
| A person actually using it on two machines | **Not done** | tests use one machine and Chrome's fake screen source |
| Native helper with keyboard and mouse (Phase C) | **Not built.** Needs the operator's decision (ADR-0010) | — |

### Trying it locally with two browsers

1. Start the server (see [deployment.md](deployment.md)) and sign in as an administrator or technician.
2. **Support → Create invitation.** Copy the link (or note the 9-digit code).
3. In a *different* browser, or a private window (it must not share the technician's cookies), open the link, or go to `/s` and type the code.
4. Read the request, click **Allow, and choose what to share**, and pick a tab or window in the browser's picker.
5. The technician's page shows the shared content and a 6-digit security code; the participant's page shows the same code.
6. Either side clicks **End**. Both pages say it ended, and the link or code no longer works.

For two machines on different networks, set `FLYW8T_ICE_SERVERS` (for example `[{"urls":"stun:stun.example.org:3478"}]`, plus a TURN server for restrictive networks) and serve over HTTPS: browsers allow screen capture only in secure contexts (`https://` or `localhost`).
