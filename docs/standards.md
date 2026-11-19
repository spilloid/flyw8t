# Company standards in flyw8t

Adoption of corporate-strategy `standards/STD-*.md`, as of 2026-10-29.

| Standard | Status | Where / why |
|---|---|---|
| STD-001 Orchestrated, adversarially-reviewed development | adopted | `CLAUDE.md` routing; [dev-process.md](dev-process.md) log. One cross-family review round (Codex gpt-6.1-sol) on the core; attended support not yet reviewed. |
| STD-002 PR template | adopted | `.github/PULL_REQUEST_TEMPLATE.md`, checked by the `standards` CI job. |
| STD-003 Documentation freshness | adopted | README states the Cargo workspace version and `CHANGELOG.md`'s latest entry matches it, both checked in CI; dated quarantine list in `CLAUDE.md`. |
| STD-004 Identity architecture | adopted (partial) | Local accounts, TOTP, passkeys and prefixed scoped bearer tokens (`fw8_`, hashed, revocable) are built; **OIDC remains open**, required by roadmap 0.7 before the 0.8 feature freeze. Devices have a separate Ed25519 plane (ADR-0002) that cannot satisfy user checks, and vice versa. |
| STD-005 Agent-facing surface | partial | API authorization and tenancy match the console. The MCP preview supports attended screenshots with a dedicated token scope, participant grant and request receipts. The proposed diagnostic tools still require the replay and attribution work below. |
| STD-006 Secret handling | adopted (a, b) | (a) no deployment secrets committed; `.env` is git-ignored, `.env.example` holds placeholders, stated in `SECURITY.md`. (b) passwords Argon2id; session, API and enrollment tokens and support invitations SHA-256 only, shown once with `Cache-Control: no-store`; device private keys never leave devices. |
| STD-007 Repo metadata | adopted | MIT `LICENSE` (`Joseph Spillers`); `CHANGELOG.md`. AI attribution: none, per the operator's standing preference. |
| STD-008 UI capture & overflow validation | adopted, **mechanism deviates** | `crates/flyw8t-server/tests/ui_capture.rs` drives headless Chrome over DevTools from Rust (as PortGlass does): 16 pages × 3 widths × 2 themes, failing on horizontal overflow or browser errors; plus `support_browser.rs` for the attended-support flow. Wired into CI. `standards/check.sh` looks for `docs/scripts/capture-*.mjs` and will not detect this shape. |

## MCP integration for the technician tools

Implementation review, 2026-11-18, against preview `2a3a0b8`, kvm-it 0.7.0 and the corporate STD-005 reference for identity, attribution and approval. [kvm-it adapter guide](https://github.com/spilloid/kvm-it/blob/v0.7.0/docs/mcp.md)

Ship a small Rust executable, `flyw8t-mcp`, alongside the technician tools. A local MCP client launches it over stdio. The operator selects one flyw8t server and authorizes a revocable technician credential through a local profile. Keep secrets out of tool arguments, client command lines and stdout. The adapter calls the control plane over HTTPS. The enrolled agent continues using its authenticated outbound connection, including behind NAT. The GUI and MCP share server-side authorization, jobs and audit. This follows the ownership model in kvm-it, where the GUI and MCP use the same console controller. [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

The screenshot adapter and its browser integration are implemented in this preview. The management tools below are proposed. [Connect an MCP client](mcp.md)

### Proposed management tools

| Proposed tools | Existing operation and result |
|---|---|
| `device_search`, `device_get` | Search accessible organizations, then select an explicit device UUID. Summarize live connection state separately from the timestamp on cached inventory. The current list API caps results at 2,000. Expose possible truncation until the server supplies a cursor. |
| `diagnostic_catalog`, `device_jobs`, `job_status` | Use the existing catalog, history and outcome APIs. Return bounded structured results. Return full diagnostic output only on explicit request. Treat endpoint text as untrusted data. |
| `diagnostic_start`, `job_cancel` | Use the existing bounded actions and effective `jobs:run` permission. For start, map a caller-provided `request_id` to `Idempotency-Key` and return a job ID and console link immediately. For cancellation, report the request and read the final outcome from the job. |

The server already owns these operations. Preserve its execution state, verification and `outcome_unknown` result across client disconnects. A status check reads the existing job. [Operator API](anchordesk-integration.md) · [Job lifecycle](job-lifecycle.md)

### Server work before publishing the tools

- Add an authenticated effective-capabilities response for the configured principal. Filter discovery by role and credential scope. Check current authorization, organization and target on every call, including calls from a cached catalog. When capabilities cannot be retrieved, return an actionable connection or authentication status.
- Bind MCP attribution to a server-issued credential purpose or authenticated MCP entry point. Today bearer calls record `api`. Carry principal, credential identifier, organization, tool/version, request ID and decision into the audit record. Keep the existing transaction boundary for accepted jobs. [Principal](../crates/flyw8t-server/src/auth.rs) · [Audit](../crates/flyw8t-server/src/audit.rs)
- Fix create replay before exposing diagnostic starts. Today the replay check compares device and action and omits the effective timeout. Two matching creates can race and one can receive a unique-key conflict. Identical concurrent requests should return the same authorized receipt. A change to device, action parameters or effective timeout should produce a conflict without disclosing the previous job. [Job creation](../crates/flyw8t-server/src/jobs.rs)

### Desktop integration

Begin with a support request, its status, and a link for the technician to open the viewer. These require new scoped server operations. Deliver the participant's one-use invitation through the human console. The current technician socket belongs to the session creator, and the Windows picker rechecks the selected logon before requesting shadow. Preserve both properties. Bind each model-visible frame to the participant and shared source described below. Keep viewing, input, clipboard and file transfer separately authorized. An operator taking over, a changed logon or participant revocation must invalidate outstanding observations and pending input. Windows sign-in stays interactive. [Attended support](attended-support.md) · [Session validation](../crates/flyw8t-technician/src/sessions.rs)

### Attended screenshot tool

`support_screenshot(session_id, request_id, crop?)` returns one fresh frame from the screen, window or tab the participant selected in the active support session. The optional crop uses normalized source coordinates `{x, y, width, height}` within the shared frame. Crop before resizing so a technician can read a small dialog. Return one MCP `image/png` image block, capped at 512 KiB before base64, with the returned dimensions and the time the viewer observed the frame. [MCP image results](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#image-content)

The participant grants screenshots separately from ordinary viewing. Show the recipient in the prompt, for example **Allow screenshots for this session to be sent to [AI client]?** Keep a visible switch to turn this off. The grant is bound to the owner, organization, participant, recipient and current shared source. A browser share identifies that source through its active media track. A native Windows provider must also verify the endpoint and logon.

The browser provider takes pixels from the technician viewer's decoded remote video and delivers an encrypted one-shot response to the adapter. It checks the grant and source before capture and before releasing the frame. An issued request ID is consumed once. Audit records contain request metadata. An image already delivered is available to the receiving client. [Viewer frame handling](../crates/flyw8t-web/src/support-screenshot.js)

Verify with a synthetic shared window containing a known color pattern. Check the PNG and crop, denial before consent, loss of a fresh frame, a source switch, revocation during encoding, and an identical request arriving twice.

### Acceptance

Launch the packaged executable from a real MCP client and exercise discovery and a bounded diagnostic against a test device. Verify read-only discovery, rejection of a cached tool after revocation, cross-organization isolation, identical concurrent creates, changed-timeout conflicts, audit attribution and reconnecting to the same receipt. For desktop support, separately verify participant consent, correct Windows logon, human takeover and immediate revocation before advertising those tools.
