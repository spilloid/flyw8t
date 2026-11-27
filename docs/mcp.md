# MCP tools for attended support

`flyw8t-mcp` is a local stdio executable. `support_screenshot` returns one PNG from the screen, window or tab a participant is sharing in the web viewer. Both browser pages must remain connected. The tool reads the decoded video in the technician's browser and supports the same direct and relayed media paths as that viewer.

## Set up the client

1. On the same preview version of flyw8t-server, open **Administration → API tokens**. Under your own technician-capable account with token-creation permission, issue a token named for the receiving AI client. Select **Attended screenshots (participant permission required)**. The participant sees the registered token name. Use this token with one client.
2. Save the token in a private file readable by your OS account. Configure the MCP client to launch the absolute path to `flyw8t-mcp` with no arguments. The executable also accepts a token through `FLYW8T_MCP_TOKEN` in place of the file. Use `FLYW8T_MCP_CA_FILE` for a private CA.
3. In that same account's web console, start a **view screen** session and select the participant's organization. Share the invitation with the participant. After they pick a screen and the viewer displays it, open **Connection details** for the full support session ID. The invitation and its code stay with the people pairing the session.

An example for a client that reads `mcpServers`:

```json
{
  "mcpServers": {
    "flyw8t": {
      "command": "C:\\Tools\\flyw8t\\flyw8t-mcp.exe",
      "env": {
        "FLYW8T_SERVER_URL": "https://support.example.com",
        "FLYW8T_MCP_TOKEN_FILE": "C:\\Users\\operator\\.flyw8t\\mcp-token"
      }
    }
  }
}
```

## Check a session

Call `support_session_status` with the support session UUID. It reads the recorded session state and screenshot permission for the credential. Access belongs to the technician who created the session and still has access to its organization. Use `support_screenshot` when you want to request a fresh frame.

| Screenshot access | Meaning |
| --- | --- |
| `unavailable` | A supported live share is unavailable for this client. |
| `consent_required` | A screenshot request can ask the participant for permission. |
| `consent_pending` | The participant has a prompt for this credential. |
| `allowed` | The participant has allowed this credential during the current share. A new capture still requires a fresh frame. |
| `revoked` | The participant or technician declined or withdrew permission. |

## Take a screenshot

In builds that show these options in `flyw8t-mcp --help`, use `--server`, `--token-file`, and `--ca-cert` to override their corresponding environment settings. In v0.1.7 use the environment configuration above. Keep the token itself out of command arguments. Supply either a token file or the existing `FLYW8T_MCP_TOKEN` environment variable.

The new **Connect an MCP client** form creates a 30-day, screenshot-only credential. Directory administrators can use their organization’s authenticator-app code (TOTP). In **Administration → Connect an MCP client**, select **Confirm organization sign-in to continue** if prompted. Sign in with your provider, select **Continue to MCP setup**, then **Create 30-day screenshot token**. This path works without enrolling a Flyw8t passkey. Mixed scopes and local accounts use the existing passkey confirmation. Creating the credential and allowing a screen capture are separate decisions.

Call `support_screenshot` with the support session UUID and a new request UUID. The first call asks the participant for screenshot permission and reports that the decision is pending. After the participant chooses **Allow screenshots**, repeat the call with the same request UUID. The permission lasts for this client's current session and source. Keep the technician viewer visible so the browser can produce a fresh frame. The participant can turn screenshots off and keep sharing with the technician.

Screenshot permission stays pending until the server records the participant's decision in Audit. The permission entry records that decision even if a revocation or peer disconnect prevents the grant from opening. The screenshot request and release authorization have separate entries. Turning off screenshots stops capture immediately even if recording the change takes time.

```json
{
  "session_id": "d73571b7-505a-472e-a2c2-ad30e7a56186",
  "request_id": "089c4d24-b100-42f3-aada-4511ca8bcd0e",
  "crop": {"x": 0.5, "y": 0, "width": 0.5, "height": 1}
}
```

Omit `crop` to use the entire shared source. The example requests its right half. The result contains one native MCP image block and metadata for its dimensions and observation time. Each issued request ID is consumed once. Use a new ID for a deliberately new image. A missing frame, disconnected viewer or revoked grant returns an explanation. A new support session is required after the participant declines or turns off access.

## Keyboard and mouse design

[KVM IT v0.8.2](https://github.com/spilloid/kvm-it/blob/v0.8.2/docs/mcp.md#operational-tools) provides the reference. Its local console owner exposes status and screen observations separately from input. Each input call binds to a recent observation of the same capture and connection, and the owner records the request ID before input. Local takeover revokes access and releases held input.

Flyw8t provides session status and screenshots for attended support. Keyboard and mouse support depends on a live native control session that can acknowledge input and release it locally. Start with an individual key or chord, pointer movement, click, or scroll inside a session with an explicit input grant. Bind each request to the session and a fresh observation of its current source. Record the request ID, actor, input category and outcome. Keep typed content out of audit records. A disconnect, source change or local Stop ends the grant. A timeout after delivery leaves the outcome unknown until the endpoint can confirm it.

## Data handling

The browser crops and bounds the PNG to 512 KiB, then encrypts it for the requesting adapter using an ephemeral P-256 key and AES-GCM. The server checks the session owner, organization, credential, live sockets and participant grant, and forwards the encrypted result. The database records request IDs and audit metadata. The receiving MCP client controls any handling or retention after delivery. Taking control of the native Windows desktop and using the text clipboard are separate operations.

The control plane serves the viewer JavaScript and conveys the ephemeral public key, so it remains trusted. The browser share identifies the selected media track. Source-switch protections depend on what the browser reports. The Windows shadow and sign-in windows use a separate renderer and do not feed this tool.

## Diagnose an enrolled device

Enable device diagnostics on a Flyw8t MCP profile with a technician API token scoped to the relevant organization. Grant it `read` to list devices and inspect jobs. Add `jobs:run` to queue a diagnostic. Keep the token in a private file and start the adapter with `--device-diagnostics` or set `FLYW8T_MCP_DEVICE_DIAGNOSTICS=true`. These tools use the existing v1 device and job APIs.

1. Call `device_list` with an optional `query` to locate an enrolled device and check its connection state. Results are capped at 40 devices. Refine the query if the list is truncated.
2. Call `device_system_info` with the selected `device_id` and a newly chosen `request_id` UUID. The server queues the built-in inventory diagnostic and returns its job ID. If the response is lost, reuse the request ID for the same device to avoid a duplicate job.
3. Call `device_system_info_status` with that `job_id`. Check the execution state, verification, and outcome. Treat device-reported evidence as untrusted data. The adapter bounds the evidence it returns and signals when it omits an oversized result.

## Hand off to the technician console

Call `device_terminal_handoff` with an explicit `device_id` on a device-diagnostics profile with `read` scope. The tool checks the device through the scoped API and returns its connection options URL on the configured Flyw8t origin. Open it in the technician's authenticated browser. On a Windows device, the Connect section presents the background terminal policy check directly when the agent is online and the technician has control permission; otherwise it explains what is needed. This checks local opt-in and does not open a terminal. The browser handles sign-in, authorization, and the technician's actions. [Background terminal status and acceptance](background-terminal.md)
