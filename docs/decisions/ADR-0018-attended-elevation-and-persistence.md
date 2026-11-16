# ADR-0018: reduced-rights attended support, elevation and persistence

**Status:** proposed; no implementation authorized by this ADR
**Date:** 2026-11-15
**Context:** the operator asked about an uninstalled helper that starts with reduced rights, with credentials entered by the technician when elevation or a persistent installation is needed.

## Current behavior

Browser screen viewing is implemented. The uninstalled native helper currently pairs and asks for consent; native capture/input is unfinished. There is no technician-credential elevation or installation path. The current product rule says attended support never installs anything. This proposal does not amend that rule or authorize a new execution action.

## Proposed decision

Start every uninstalled helper in the participant's user context. Joining, viewing, remote input, elevation and persistence are separate capabilities. Each requires an explicit endpoint consent that names the technician, organization, server, requested rights and duration. Declining elevation leaves only the previously consented capabilities. Declining persistence leaves the uninstalled session usable without invoking the product installation workflow. Consent must use a trusted local-only confirmation surface that technician input and server-delivered UI cannot approve or imitate. If a platform cannot enforce that boundary, keep elevation local and do not offer remote credential entry.

Elevation is temporary and session-bound. A fixed, signed endpoint broker asks the operating system for the requested elevation; it does not accept a command line, shell text, executable path or arbitrary installer from the server. An unsuccessful elevation is reported with the operating-system error; it is never silently retried and never reported as elevated without endpoint evidence. Windows UAC secure-desktop and macOS authorization/session behavior require physical-machine experiments before a supported design is selected.

Persistence is a distinct installation workflow, not an implicit continuation of attended support. A new endpoint-owner consent must explain the installed service, account/privilege level, reconnect behavior, update policy and removal instructions. Enrollment binds to an explicitly authorized organization. Installing requires the signed installer and install-time publisher verification already required by the release roadmap. Ending the attended session does not falsely claim that an installed service was removed; its installation and removal have their own recorded outcomes. The product rule must be deliberately amended before this workflow can ship.

## Credential path and its limits

A signed native technician client collects credentials in a dedicated control, never in the browser's remote-input stream, a clipboard, a command line, a URL or a support message. The endpoint broker receives them over a purpose-bound, mutually authenticated encrypted channel and passes them directly to the local operating-system authorization API. The server may route ciphertext but must never receive a decryption key or the plaintext. Audit events contain identities, requested capability, consent, attempt/result codes and expiry only; they must not contain credential material or reusable ciphertext. Credentials are not persisted, returned to the technician after submission, or reused for later sessions.

This requires an independently trustworthy pairing design. Encrypting to a key supplied by the same server does not protect against that server substituting its own key. The channel must bind both endpoint and technician identities, session, requested capability, nonce and expiry, with endpoint-enforced replay prevention. The design must specify an independent trust anchor or verification ceremony that a compromised server cannot replace. Existing browser support's server-delivered JavaScript and security code do not provide that guarantee.

The participant's ordinary desktop should not display or receive the typed secret. This is a UI/data-flow goal, not a promise that a compromised endpoint administrator, compromised technician client, operating-system credential provider, debugger or kernel cannot recover it. Memory clearing is best effort and cannot erase operating-system or crash-dump copies. The selected OS API's credential caching, token lifetime, impersonation boundaries and secure-desktop requirements must be documented and tested. An implementation that cannot satisfy these limits must not accept technician credentials remotely; local endpoint entry remains the fallback.

## What a compromised server could do

A compromised server can deny service, suppress or falsify its own records, request misleading capabilities and route/replay/replace signaling. It must not be able to authorize elevation, consent, installation or a new endpoint trust identity by itself. Endpoint policy and fresh local consent must enforce those boundaries. Authentication and encryption alone do not prevent a stolen authorized technician session from asking for a harmful operation, or an elevated remote-input session from opening a shell outside the signed-script path. An elevated technician can also change endpoint state or establish persistence through remote input outside the product installer. Declining the installation workflow cannot guarantee that an elevated operator leaves no durable changes; elevation consent must explain that power, or the implementation must enforce a narrower capability it can prove. Those powers need an explicit entry in the unified trust model (G02-TRUST), rather than inheriting the script-signing guarantee.

## Evidence required before acceptance or implementation

- Review the threat model and consent screens independently at the auth/security tier, including stolen technician session, substituted server keys, compromised server and malicious participant scenarios.
- Demonstrate that declining, cancelling, disconnecting or expiring each request leaves exactly the previously consented capabilities; race consent against end/revocation and prove no elevated token or installer survives unexpectedly.
- Prove credential plaintext is absent from HTTP/WebSocket payloads visible to the server, browser DOM/remote input, logs, audit, telemetry, URLs, environment and child-process arguments. Inject crashes, failed authorization and cleanup failures; preserve truthful unknown outcomes.
- Exercise Windows UAC/sign-in/secure desktop and macOS permission/session boundaries on physical endpoints, including user switching, lock/unlock and service removal/reboot behavior.
- Prove remote input, synthetic input, server-rendered UI and an already-connected technician cannot approve or counterfeit the local elevation/persistence confirmation. Verify the consent text and policy explicitly cover any durable changes possible through elevated remote input.
- Bind elevated broker lifetime and requests to endpoint policy, session, technician and capability. Reject replay, cross-session/cross-tenant substitution, older signed binaries, arbitrary executables and unverified installers.
- Obtain the operator's decision on the amended attended-support product rule, supported OS/account types, endpoint-owner authority and persistence lifecycle before implementing either privileged capability.

## Alternatives and revisit conditions

Keep attended support uninstalled and require local OS credential entry; this remains the current behavior and has the smallest credential exposure. Use already-enrolled unattended endpoints with separately managed endpoint policy when persistence is required. Revisit this proposal only when the native engine and endpoint-enforced trust/consent gates can support the stronger boundary; a convenient browser-only password dialog is not sufficient evidence.
