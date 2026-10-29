# AnchorDesk integration

flyw8t is fully functional on its own. AnchorDesk integrates through flyw8t's public API as one more RMM provider, exactly as it treats Tactical RMM, NinjaOne and Datto RMM. Neither product imports the other's code or database.

## What AnchorDesk already has (verified 2026-10-29 against AnchorDesk 2.10.0)

- `DeviceProvider` (`backend/src/providers/DeviceProvider.ts`): `fetchDevices(since?)`, `getDevice(externalId)`, `normalize(raw) → ExternalDevice`. Devices keep a per-provider `DeviceExternalRef`.
- `ScriptRunner` (`backend/src/runners/ScriptRunner.ts`): `run(invocation) → ScriptResult{invocationId, status: queued|running|success|error, output, exitCode}`, optional `getResult(invocationId)`, chosen by device source in `runners/index.ts`.
- `ScriptJob` (Prisma) persists `invocationId` *before* returning a non-terminal result, "so later scheduler/API polls can safely refresh without re-executing". That is the same at-most-once concern flyw8t's API is built around.

## The contract flyw8t offers

Base: `https://<flyw8t>/api/v1`. Auth: `Authorization: Bearer fw8_…` (create in flyw8t → Administration → API tokens; scopes `read` + `jobs:run`). The token acts as the flyw8t user who created it and never exceeds that user's organizations.

| Need | Call | Notes |
|---|---|---|
| Device sync | `GET /devices?q=&organization=` | `DeviceRow[]`: `id`, `hostname`, `organization{id,name}`, `site`, `os`, `agent_version`, `connection{state, since \| last_seen}`, `retired` |
| One device | `GET /devices/{id}` | adds `inventory{received_at, source, report}`, `credential`, `recent_jobs`, `remote_access` |
| Catalog | `GET /catalog` | the actions, their parameters, timeouts and success contracts |
| Run | `POST /devices/{id}/jobs` + `Idempotency-Key` header, body `{"action":"net.ping","params":{"target":"10.0.0.1"},"timeout_secs":30}` | `202 {job_id, url}`. Same key + same request returns the same job; same key + different request returns `409`. **The key is required.** |
| Poll | `GET /jobs/{id}` | full detail + `outcome{label, tone, explanation}` + `events[]` |
| Cancel | `POST /jobs/{id}/cancel` | `202`; the job's final state says whether it ran |
| Device history | `GET /devices/{id}/jobs` | |

## Mapping onto AnchorDesk

`FlyweightProvider implements DeviceProvider` (name `flyweight`):

| ExternalDevice | from flyw8t |
|---|---|
| `externalId` | `id` |
| `hostname`, `displayName` | `hostname` |
| `os` | `os` |
| `companyName` | `organization.name` |
| `status` | `connection.state == "connected" ? "online" : "offline"` (`never_connected` → `unknown`) |
| `lastSeenAt` | `connection.since` or `connection.last_seen` |
| `metadata` | `{ site, agentVersion, flyweightOrganizationId }` |

`FlyweightRunner implements ScriptRunner`:

- `run()` sends `POST /devices/{externalDeviceId}/jobs` with `Idempotency-Key = "anchordesk-scriptjob-<ScriptJob.id>"`, so an AnchorDesk retry after a timeout returns the **same** flyw8t job instead of running a second one. It returns `{invocationId: job_id, status: "queued"}`. AnchorDesk already persists `invocationId` before returning.
- `getResult()` maps flyw8t's two dimensions onto AnchorDesk's single status **without inventing success**:

| flyw8t `state` / `verification` | AnchorDesk `status` | output |
|---|---|---|
| `queued`, `dispatched`, `acknowledged` | `queued` | — |
| `running` | `running` | — |
| `completed` / `verified` | `success` | stdout (or structured result as JSON), `exitCode` |
| `completed` / `failed` | `error` | stdout + "Verification failed: <verification_note>" |
| `failed`, `timed_out`, `cancelled`, `expired` | `error` | error / state note + any partial output |
| `outcome_unknown` | **`error`, with the output starting "OUTCOME UNKNOWN:"** + the state note | AnchorDesk has no "unknown" status; the gap is recorded below rather than papered over |

`script` in an AnchorDesk invocation is a flyw8t catalog action name (`net.ping`); `args` map to the action's parameters in catalog order.

## Gaps to close, on AnchorDesk's side

1. **AnchorDesk has no `unknown` script status.** Mapping it to `error` is honest-ish but loses the distinction flyw8t exists to make. Proposal: add `unknown` to `ScriptJobStatus` (AnchorDesk migration + UI badge).
2. AnchorDesk polls; flyw8t has no webhook yet. Poll `GET /jobs/{id}` with backoff (2 s, then up to 30 s) until a final state or `outcome_unknown`.
3. Ticket linkage: flyw8t does not store ticket references yet. The planned field is `jobs.external_ref` (free text, e.g. `anchordesk:ticket:1234`), set via an optional `external_ref` in the create body and shown on the job page.

Nothing in this document has been run against a live AnchorDesk instance; the provider and runner do not exist yet (roadmap 0.4).
