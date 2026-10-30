# Monitoring model

**Status: designed; only connectivity is implemented.** The types live in `flyw8t_domain::finding` so the first real monitors land in a model that already preserves evidence.

## Principles

1. **A finding is evidence, not a feeling.** It carries the raw facts it was derived from, when they were collected (device clock), and when they were evaluated (server clock).
2. **Stale is not live.** Every value shown has an age, and data past its freshness window is labelled as such. The device page already does this for inventory (Fresh / Aging / Stale).
3. **Silence is not an incident.** A device that misses heartbeats raises nothing until a grace period passes (default 10 minutes), then a warning; critical after 24 hours. Laptops sleep.
4. **One finding per (check, device, key).** Re-evaluation updates the existing finding in place; it never creates a duplicate.
5. **Resolution is recorded, not deleted.** Findings move `open → resolved` (condition cleared, with the clearing evidence) or `open → suppressed` (by a person, with a reason and an expiry).

## Finding

| Field | Meaning |
|---|---|
| `check` | Stable identifier: `connectivity.offline`, `disk.low_space`, `service.stopped`, … |
| `severity` | `info` · `warning` · `critical` |
| `status` | `open` · `resolved` · `suppressed` |
| `evidence` | The facts as reported, e.g. `{"mount": "C:\\", "free_bytes": …, "total_bytes": …}` |
| `collected_at` | Device clock: when the evidence was gathered |
| `evaluated_at` | Server clock: when the verdict was made |
| `dedup_key` | `check + device + key` (e.g. the mount point) |

## Connectivity (implemented)

`Connectivity` is derived, never stored: `Connected` (a live authenticated connection in this server's registry), `Disconnected { last_seen }`, or `NeverConnected`. The console shows the live badge only from the registry, so a server restart never shows a stale "connected". `offline_severity(connectivity, now, policy)` implements principle 3 and is unit-tested; nothing raises alerts from it yet.

## Next monitors (0.3)

| Check | Evidence source | Default thresholds |
|---|---|---|
| `disk.low_space` | inventory disks | warning < 15 % free, critical < 5 % free (per mount) |
| `memory.pressure` | inventory memory, sustained over 3 samples | warning < 10 % available |
| `service.stopped` | new collector: Windows service state for a configured list | any configured service not running |
| `eventlog.match` | new collector: query Event Log channels by ID and level | per policy |
| `connectivity.offline` | registry + `last_seen_at` | grace 10 min → warning; 24 h → critical |
