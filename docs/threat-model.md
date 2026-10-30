# Threat model

flyw8t is privileged remote-execution infrastructure: whoever controls it controls every enrolled endpoint. This model covers **0.1.0** as built. Each threat lists the control that exists, the evidence (a test, or "none: by inspection"), and the residual risk. **flyw8t 0.1.0 is not production-ready**; the open items at the end are why.

## Assets

1. The ability to make endpoints do things: today only read-only diagnostics, eventually anything.
2. Device credentials (Ed25519 private keys on endpoints; public keys on the server).
3. Technician credentials: passwords, session cookies, API tokens.
4. Tenant separation between MSP customers (organizations).
5. Endpoint data in transit and at rest: inventory, command output.
6. The integrity of the record: job outcomes and the audit trail.

## Actors

| Actor | Can |
|---|---|
| Anonymous network attacker | Reach the server's HTTPS port; observe or tamper with traffic it can route. |
| Compromised endpoint | Hold a valid device key; send anything the protocol allows, and anything it doesn't. |
| Compromised technician account | Act with that user's role and organization scope. |
| Malicious or compromised integration | Hold a bearer token. |
| Compromised server or database | Everything (see below). |

## Threats and controls

### T1: Arbitrary command execution
- **Control:** there is no arbitrary-execution path. Jobs name one of four compiled-in, read-only actions; parameters are typed and validated on the server *and again* on the agent; unknown actions fail to deserialize on both sides. Child processes are absolute paths with argument vectors and no shell; the ping target cannot begin with `-` (option injection) and is restricted to IP or hostname characters.
- **Evidence:** `ping_target_rejects_option_injection_and_shell_metacharacters`, `unknown_actions_do_not_deserialize`, `invalid_params_never_reach_a_process`, the API test that `shell.exec` is rejected.
- **Residual:** adding a script-execution action changes this threat completely. It needs signed scripts, an approval flow for high-risk classes (STD-005 C2/C3), and its own review before it ships.

### T2: Cross-tenant access
- **Control:** every query is scoped by the caller's organizations; out-of-scope records return 404. Job creation re-checks scope before permission. The database enforces job organization = device organization. Devices get their organization from the enrollment token, never from anything they send.
- **Evidence:** `tenant_isolation_and_token_scopes` (list, view and run against another organization's device all fail as not-found).
- **Residual:** scoping is applied per query by convention, not by row-level security. A new query that forgets the scope parameters leaks. Postgres RLS as defense in depth is on the roadmap; until then every new read path needs review against this item.

### T3: Enrollment-token theft
- **Control:** tokens are 256-bit random, shown once, stored as SHA-256, expire (5 min to 24 h, default 1 h), have a use limit (default 1), can be revoked, and are rate-limited (10 enrollments per minute per IP). Enrollment is audited, failures included, with a uniform error.
- **Evidence:** `enrollment_and_device_revocation` (reuse, expiry and garbage refused).
- **Residual:** a stolen, unused token within its validity enrolls a rogue device into that organization. That device can only *receive* read-only diagnostics, and it is visible in the device list and audit log. The roadmap adds an optional "approve new devices" step.

### T4: Device impersonation and replay
- **Control:** per-connection 32-byte nonce, Ed25519 signature over a domain-separated message binding nonce and device id; one active key per device; TLS required for non-loopback servers (a code rule, not a setting).
- **Evidence:** `replayed_authentication_is_refused` (captured signature on a new connection; correct signature from the wrong key), `auth_message_binds_nonce_and_device`, `plaintext_only_to_loopback`.
- **Residual:** the server is not authenticated beyond TLS. An attacker with a certificate the agent trusts (a public CA mis-issuance, or a private CA the agent was told to trust) can impersonate the server. Pinning the server's key at enrollment is on the roadmap.

### T5: Compromised endpoint attacking the server
- **Control:** credentials are re-checked after a connection registers, closing the window where a revocation could slip between authentication and registration; reports about jobs the device does not own are ignored and audited; messages are capped at 1 MiB; malformed or out-of-sequence messages close the connection; device-supplied strings are length-truncated and rendered with HTML escaping; a newer connection supersedes an older one; handshakes are rate-limited per IP.
- **Evidence:** `device_cannot_report_another_devices_job`, `hostile_frames_close_the_connection`, `newer_connection_supersedes_older`, `pages_escape_untrusted_text`.
- **Residual:** a compromised device can lie about *its own* results and inventory. Verification checks evidence shape, not truth. Nothing inside a device can prove it is not compromised.

### T6: Compromised technician account
- **Control:** two-step verification (TOTP) required by default, with replay refusal, five wrong codes per partial session and ten per user per five minutes, single-use hashed recovery codes, and the session secret rotated when the second factor completes; Argon2id passwords (minimum 12 characters); login rate limits per IP and per email with a constant-time path for unknown users; sessions expire after 12 h and are revocable at sign-out; CSRF tokens on every form; every mutation audited with actor and credential.
- **Evidence:** CSRF forgery test; audit assertions in `vertical_slice`; `tests/mfa.rs` (partial sessions shut out, replay refused, recovery codes single-use, attempts exhausted, admin reset), each mutation-checked.
- **Residual:** TOTP is phishable in real time (a proxy that relays the code within 30 seconds); WebAuthn is the fix and is not built. TOTP secrets are stored unencrypted in PostgreSQL, so a database reader can mint codes (they can also read everything else; an application-held key would narrow this). `FLYW8T_REQUIRE_MFA=false` lets users opt out. No OIDC yet. No session list or force-logout UI beyond the administrator's MFA reset.

### T7: Fleet-wide abuse
- **Control:** there is no fleet-wide or multi-device operation; one job targets one device. Actions are read-only.
- **Residual:** when fleet operations arrive they need per-operation scope limits, rate limits, a confirmation that states the count, and C2 approval for anything state-changing.

### T8: Malicious job payloads
- Covered by T1. Payloads are typed; there is no string that the agent interprets as code.

### T9: Compromised software updates
- **Control:** there is no automatic update mechanism. Agents are installed and upgraded by an administrator.
- **Residual:** auto-update is designed to require a signed manifest (an Ed25519 key held outside the server, following PortGlass's updater) **before** it is enabled. Binaries are not Authenticode-signed yet.

### T10: Compromised server or database
- **Reality:** a compromised server can command every agent within the catalog. Today that means read-only diagnostics to every endpoint and full knowledge of inventory. It **cannot** obtain device private keys (they never leave devices) or user passwords in plaintext (Argon2id), and it cannot execute arbitrary code on endpoints, because the agent enforces its own catalog.
- **Control direction:** keep the agent's catalog the real boundary. When script execution arrives, scripts must be signed by a key the server does not hold, so a server compromise cannot become arbitrary fleet-wide execution.

### T11: Secrets in logs, URLs and responses (STD-006b)
- **Control:** tokens are shown once and stored hashed; API token responses are never re-displayed; reveal pages send `Cache-Control: no-store`; audit records hold credential *prefixes*; agent logs never include tokens or keys; the enrollment token is passed by flag or environment, never in a URL.
- **Residual:** the enrollment token appears on the agent's command line (`--token`), which a local administrator can see in the process list during enrollment. `FLYW8T_ENROLL_TOKEN` is supported as an alternative.

### T12: Tampering with the record
- **Control:** `job_events` and `audit_events` reject UPDATE, DELETE and TRUNCATE with database triggers.
- **Evidence:** `vertical_slice` asserts UPDATE and DELETE fail.
- **Residual:** a database superuser can drop the trigger. The triggers protect against application bugs and application-level compromise, not against DBA-level compromise. Off-host log shipping is a deployment concern ([deployment.md](deployment.md)).

### T13: Browser-side attacks on the console
- **Control:** CSP `default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'`; no inline script; `X-Frame-Options: DENY`; `nosniff`; `Referrer-Policy: same-origin` (`no-referrer` would make browsers send `Origin: null` on the console's own form posts); flash messages chosen from fixed codes so a URL cannot inject text.
- **Login CSRF:** state-changing requests whose `Origin` names another site are refused before routing (covers sign-in, which has no session token yet). Evidence: `cross_origin_posts_are_refused`.
- **Residual:** a browser that sends no `Origin` on a cross-site POST would bypass the login check (current browsers send it).

### T14: Denial of service
- **Control:** bounded queues and message sizes; per-IP handshake, enrollment and login limits; an absolute 30 s handshake deadline that ping frames cannot extend; at most 100 messages per second per authenticated agent connection; at most 50 events per job for reports that change nothing; device-supplied text truncated when stored; a 256 KiB body limit on HTTP.
- **Residual:** the limiter is in memory and per instance; there is no global connection cap; a botnet can still exhaust connections. Put a reverse proxy with connection limits in front of any internet-exposed deployment.

## Agent endpoint threats

| Threat | Control | Residual |
|---|---|---|
| Local user reads the device key | `service install` restricts the state directory to SYSTEM + Administrators | A local administrator can read it (by design). Running the agent in the foreground with a custom state dir does **not** restrict permissions. |
| Journal corrupted to force a re-run | Atomic writes; a corrupt entry is quarantined and logged | Deleting the journal (local admin) erases dedupe history. Re-delivery then re-runs the job, but only if the server still offers it, which only happens while it is `dispatched`. |
| Timeout bypass by a hung child process | Child killed on timeout and cancel (kill-on-drop) | Grandchildren are not tracked; a Windows Job Object per child is on the roadmap. Current actions spawn no children. |

## Open items before production

1. OIDC sign-in and WebAuthn. TOTP two-step verification is built and required by default (2026-10-29).
2. Cross-family adversarial review: **done for the core** (Codex gpt-6.1-sol, 2026-10-29: ten findings, nine fixed, the tenth (Windows rename durability) fixed on Unix only; see [dev-process.md](dev-process.md)). **Done for attended support** (Codex gpt-5.6-sol, 2026-10-29: 13 findings, 12 fixed, 1 partly fixed); two-step verification reviewed (row 13) and both re-reviewed (row 15, 10 of 11 fixed); **the row 15 fixes are not yet reviewed.**
3. Authenticode-signed agent and server binaries; signed update manifests before any auto-update.
4. Pin the server identity at enrollment.
5. Postgres row-level security as defense in depth for T2.
6. A session list and forced logout.
7. External penetration test.

## Attended support

Attended (consent-based, browser screen view) sessions have their own threat analysis in [attended-support.md](attended-support.md#threats-specific-to-attended-support): consent before any signaling, single-use invitations, signaling-tampering detection through a committed security code (not a defense against a compromised flyw8t server), and no capability beyond viewing what the participant chooses.
