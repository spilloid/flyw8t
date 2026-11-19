# MCP screenshots in an attended support session

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

## Take a screenshot

Call `support_screenshot` with the support session UUID and a new request UUID. The first call asks the participant for screenshot permission and reports that the decision is pending. After the participant chooses **Allow screenshots**, repeat the call with the same request UUID. The permission lasts for this client's current session and source. Keep the technician viewer visible so the browser can produce a fresh frame. The participant can turn screenshots off and keep sharing with the technician.

```json
{
  "session_id": "d73571b7-505a-472e-a2c2-ad30e7a56186",
  "request_id": "089c4d24-b100-42f3-aada-4511ca8bcd0e",
  "crop": {"x": 0.5, "y": 0, "width": 0.5, "height": 1}
}
```

Omit `crop` to use the entire shared source. The example requests its right half. The result contains one native MCP image block and metadata for its dimensions and observation time. Each issued request ID is consumed once. Use a new ID for a deliberately new image. A missing frame, disconnected viewer or revoked grant returns an explanation. A new support session is required after the participant declines or turns off access.

## Data handling

The browser crops and bounds the PNG to 512 KiB, then encrypts it for the requesting adapter using an ephemeral P-256 key and AES-GCM. The server checks the session owner, organization, credential, live sockets and participant grant, and forwards the encrypted result. The database records request IDs and audit metadata. The receiving MCP client controls any handling or retention after delivery. Taking control of the native Windows desktop and using the text clipboard are separate operations.

The control plane serves the viewer JavaScript and conveys the ephemeral public key, so it remains trusted. The browser share identifies the selected media track. Source-switch protections depend on what the browser reports. The Windows shadow and sign-in windows use a separate renderer and do not feed this tool.
