# Agent protocol (version 1)

The agent makes one outbound WebSocket connection to `wss://<server>/api/agent/ws` (plain `ws://` only to loopback). Every message is one JSON text frame tagged by `"type"`. The types live in `crates/flyw8t-protocol`; unknown message types and unknown actions fail to deserialize and end the connection.

## Limits

| Limit | Value | Enforced by |
|---|---|---|
| Message / frame size | 1 MiB | both sides' WebSocket configuration |
| Captured output per stream | 256 KiB (rest counted, discarded) | agent |
| Concurrent jobs per agent | 2 (further offers declined `busy`, not buffered) | agent |
| Agent outbound buffer | 256 reports (overflow dropped; the journal re-sends) | agent |
| Server outbound buffer per connection | 64 messages (overflow: the offer is not sent and stays queued) | server |
| Handshake deadline | 30 s | both |
| Idle connection | 3 × heartbeat with no message → closed | both |
| Handshakes per source IP | 60 / min; enrollments 10 / min | server |

## Handshake

```text
agent                                   server
  │ ── TLS + WebSocket upgrade ─────────► │
  │ ◄──────── Challenge{protocol_version, nonce} (32 random bytes, base64)
  │
  ├─ enrolled device:
  │ ── Authenticate{protocol_version, device_id, signature, agent_version} ─►
  │ ◄──────── Welcome{device_id, heartbeat_secs}   or   Refused{code, message}
  │
  └─ new device:
    ── Enroll{protocol_version, token, public_key, signature, facts} ─►
    ◄──────── Enrolled{device_id, organization}    or   Refused{EnrollmentFailed}
    (connection closes; the agent reconnects and authenticates)
```

**Authentication signature.** Ed25519 over `"flyw8t/agent-auth/v1\0" ‖ nonce ‖ device_id (16 bytes)`. The nonce is fresh per connection, so a captured signature is useless on any other connection (`replayed_authentication_is_refused`). The server tries every credential on record for that device. A match on an active credential succeeds. A match on a revoked one returns `Refused{Revoked}`, which stops the agent permanently. No match returns `Refused{AuthFailed}`. "Revoked" is never disclosed to someone who cannot sign with that key.

**Enrollment signature.** Ed25519 by the *new* key over `"flyw8t/agent-enroll/v1\0" ‖ nonce ‖ public_key ‖ SHA-256(token)`. It proves possession of the private key being registered and binds it to one token without signing the secret itself. The server:

1. hashes the token and locks its row;
2. requires: exists, not revoked, not expired, `uses < max_uses`;
3. requires the public key is not already registered;
4. increments `uses`, creates the device **in the token's organization and site** (the device's `facts` are display hints only), stores the public key, and audits it, all in one transaction.

Every failure returns the same message, so there is no oracle for which tokens exist. The reason is in the audit log.

## Messages after `Welcome`

### Server → agent

| Message | Meaning | Agent must |
|---|---|---|
| `JobOffer{job_id, action, timeout_secs}` | Run this, at most once. May arrive more than once. | Look up `job_id` in the journal **first**. If known, re-send its stored report and do nothing else. Else validate, check capacity, **journal, then** reply `Accepted`. |
| `JobCancel{job_id}` | Stop it if not finished. May name a job the agent has never seen. | Running: stop it (it reports itself). Known and finished: re-send its report. Unknown: write a cancel tombstone and report `Cancelled{started:false}`, so a later offer is never run. |
| `ReportAck{job_id}` | The final report is durably stored. | Mark the journal entry acknowledged; stop re-sending it. |
| `Refused{code}` | Connection is being closed. | `Revoked`: stop permanently. Anything else: reconnect with backoff. |

### Agent → server

| Message | When |
|---|---|
| `Heartbeat{agent_version, uptime_secs, running_jobs}` | Every `heartbeat_secs` (default 30). |
| `Inventory{…}` | On connect and every 6 h. Stored as a timestamped snapshot; display fields only. |
| `Job{job_id, phase}` | `Accepted` · `NotAccepted{busy\|unsupported_action\|invalid_params\|storage_error}` · `Started{at}` · `Finished{outcome, started_at, finished_at, stdout, stderr, structured}` |

`Finished.outcome` is one of `Exited{code}`, `Collected`, `Failed{error}`, `TimedOut`, `Cancelled{started}`, `NotStarted{reason}`, `Interrupted{reason}`. The server maps it to an execution state with `domain::job::state_for_outcome`.

### Delivery guarantees

- **Agent → server reports:** at-least-once. On every (re)connect the agent sends the latest state of every journal entry the server has not acknowledged. On every heartbeat it re-sends unacknowledged *final* reports. The server stores reports idempotently and acknowledges every final report, including duplicates and ones that change nothing.
- **Server → agent offers:** at-least-once while the job is `dispatched`. Re-offered on a new connection, or after `redelivery_after` (60 s) on the same one. Execution is still **at most once**, because of the journal.
- **Server → agent cancels:** re-sent on a new connection, or after `redelivery_after`, until the job is final.

## The journal (at-most-once)

One file per job in `<state_dir>/journal/`, replaced atomically (write temp file, fsync, rename):

1. `Accepted` is written **before** the agent acknowledges or starts.
2. `Started` is written **before** execution begins. If that write fails, the job is not run (`NotStarted`).
3. On restart: `Accepted` without `Started` becomes `NotStarted` (provably not run); `Started` without `Finished` becomes `Interrupted` (unknown). Neither is re-run.
4. Only acknowledged entries are pruned (30 days, at most 5,000 kept).
5. An unreadable entry is renamed `.corrupt` and logged. This is the one way the journal can forget a job id. Atomic replacement makes it unexpected, and it is listed in the threat model.

## Versioning

`protocol_version` is a major version. A server refuses an agent that speaks a different one (`Refused{ProtocolVersion}`), and an agent treats a mismatched server as a retryable error (it cannot update itself yet). Additive changes that old peers can ignore do not need a bump only if both sides would deserialize them. Today neither side ignores unknown variants, so in practice **every message change is a version bump** until a compatibility policy is written (roadmap).
