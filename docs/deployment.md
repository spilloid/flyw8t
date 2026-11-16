# Deployment

> **Status (2026-11-12):** packaged Compose startup, password/TOTP sign-in, record creation and dump/restore into an empty database passed at `a48f7e6` in [CI run 43171178365](https://github.com/spilloid/flyw8t/actions/runs/43171178365). Docker is unavailable on this Windows host. The automated same-host database round-trip leaves off-host recovery, key recovery and physical Windows-agent deployment gates open. Native server/database suites run separately against PostgreSQL.

## Server with Docker Compose

```sh
cd deploy/compose
cp .env.example .env        # set FLYW8T_DB_PASSWORD and the bootstrap admin
docker compose up -d --build
docker compose logs -f server
```

Open `http://localhost:8080`, sign in as the bootstrap administrator (you will be asked to set up an authenticator app and to save recovery codes), then remove `FLYW8T_BOOTSTRAP_ADMIN_*` from `.env` (it is only used while no users exist, but it should not linger).

By default the server publishes on **127.0.0.1 only** and the database is not published at all.

### Reaching it from other machines (TLS)

Agents refuse plaintext to any non-loopback host, and the server refuses to start with an `http://` public URL that is not loopback. Pick one:

- **Native TLS:** put `fullchain.pem` and `privkey.pem` in `deploy/compose/tls/`, then set `FLYW8T_TLS_CERT=/tls/fullchain.pem`, `FLYW8T_TLS_KEY=/tls/privkey.pem`, `FLYW8T_PUBLIC_URL=https://rmm.example.com:8443` and `FLYW8T_PUBLISH=0.0.0.0:8443`. Native TLS is verified by `tests/tls.rs`.
- **Cloudflare Tunnel** (recommended for a home or office server): no inbound port, no NAT rule, no certificate to manage. In Cloudflare Zero Trust, create a tunnel, copy its token, and add a public hostname (for example `rmm.example.com`) pointing at `http://server:8080`. In `.env` set `CLOUDFLARE_TUNNEL_TOKEN`, `FLYW8T_PUBLIC_URL=https://rmm.example.com` and `FLYW8T_TRUSTED_PROXIES=172.29.0.10`, then `docker compose --profile tunnel up -d --build`. Agents enroll against `https://rmm.example.com`; their WebSockets and the support pages' pass through the tunnel. Rate limits and the audit log see each client's real address (`CF-Connecting-IP`), believed only from the tunnel container.
- **Reverse proxy** (Caddy, Traefik, nginx): terminate TLS at the proxy, forward to `127.0.0.1:8080` with WebSocket upgrade enabled, and set `FLYW8T_PUBLIC_URL=https://…`. Set `FLYW8T_TRUSTED_PROXIES` to the proxy's address and `FLYW8T_CLIENT_IP_HEADER` to the header it sets (for example `x-forwarded-for`), or client addresses will all be the proxy's.

For a private CA, give agents the CA certificate at enrollment (`--ca-cert ca.pem`); it is stored in the agent's configuration and trusted alongside public roots.

### The published image

Each tagged release publishes the server as `ghcr.io/spilloid/flyw8t-server:<version>` (for example `:0.1.3`), built from `deploy/compose/Dockerfile`. The release notes give its digest; the image is not signed, so pin the digest (`ghcr.io/spilloid/flyw8t-server:0.1.2@sha256:…`) wherever a registry or a tag you do not control could otherwise change what runs. It listens on `0.0.0.0:8080`, runs as UID 10001, keeps nothing on disk, and needs only the variables below and a PostgreSQL database (18 is what the tests and the Compose file use). `flyw8t-server healthcheck` exits 0 when this server is ready, `flyw8t-server --version` prints the version, and `/readyz` answers 200 once the database is reachable and migrated.

Of the script syntax checkers, only `bash` is in the image (it comes with the Debian base); `pwsh` and `python3` are not, so PowerShell and Python revisions say "not checked" while Bash ones are checked. Set `FLYW8T_SCRIPT_CHECKS=off` to check none.

### Behind a proxy that signs people in

A proxy that requires its own sign-in (Authentik, Authelia, oauth2-proxy, Cloudflare Access) in front of the console is a second lock, not a replacement: flyw8t still asks for its own password, second factor and passkeys. Agents and support participants are not people with an account at that proxy, so these paths must reach flyw8t without it:

| Path | Who calls it | What protects it |
|---|---|---|
| `/api/agent/ws` | agents (enrollment and the live connection) | the enrollment token, then the device's Ed25519 key |
| `/s`, `/s/…`, `/api/support/participant/ws`, `/api/support/helper/ws` | the person being helped, and the helper | the one-time invitation code or link, then consent |
| `/probe/devices`, `/probe/heartbeat` | site network collectors (NetViz probes; see [network-operations.md](network-operations.md)) | the collector's own key, bound to one site and address range |
| `/static/…`, `/manifest.webmanifest`, `/favicon.ico` | the pages above | nothing secret is served |
| `/api/v1/…` (only if an integration calls it from outside) | API clients | the API token |

Everything else is the console and may sit behind the proxy. Keep `/metrics` off the public side altogether and scrape it from inside. Set `FLYW8T_TRUSTED_PROXIES` to the proxy's addresses, or every rate limit and audit entry will carry the proxy's address. The proxy must pass WebSocket upgrades and must not rewrite `Origin`: flyw8t refuses writes whose origin is not `FLYW8T_PUBLIC_URL`.

## Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `FLYW8T_DATABASE_URL` (or `DATABASE_URL`) | yes | — | PostgreSQL URL |
| `FLYW8T_PUBLIC_URL` | yes | — | URL technicians and agents use; `https://` unless loopback. Use a **host name**, not an IP address (`http://localhost:8080` locally): browsers refuse passkeys for an IP address, and sudo mode (field definitions, users, API tokens) needs one. It must also be the address people actually open, since passkeys are bound to it |
| `FLYW8T_BIND` | no | `127.0.0.1:8080` (image: `0.0.0.0:8080`) | listen address |
| `FLYW8T_TLS_CERT`, `FLYW8T_TLS_KEY` | together | — | PEM chain and key for native TLS |
| `FLYW8T_BOOTSTRAP_ADMIN_EMAIL`, `…_PASSWORD` | together | — | first administrator, created only while no users exist; password ≥ 12 characters |
| `FLYW8T_REQUIRE_MFA` | no | `true` | every console user sets up two-step verification (TOTP) before reaching the console; `false` makes it optional per user |
| `FLYW8T_HELPER_PATH` | no | — | the signed `flyw8t-helper.exe` offered to participants of remote-control sessions (ADR-0012). Without it, control sessions say the helper is not available; screen viewing is unaffected |
| `FLYW8T_FIELD_KEY` | no | (none) | 32 random bytes, base64 (`openssl rand -base64 32`), encrypting secret custom-field values at rest (AES-256-GCM). Without it, secret fields can be defined but no secret value can be stored. **Back it up with the database**: a lost key makes stored secrets unreadable. There is no rotation yet |
| `FLYW8T_SCRIPT_CHECKS` | no | `on` | check script syntax on save with the languages' own parsers, found on `PATH`: `pwsh` (PowerShell 7; on Windows also Windows PowerShell), `bash`, `python3`. Each that is missing is reported on the script page as "not checked". None of them runs the script. `off` turns all of them off. The checkers do not yet run without network access or as a separate identity. PowerShell's parser can look up modules, assemblies and types while parsing; scripts that look like they might make it do so are not given to it, but that screen is a heuristic. If the server runs under an identity with network credentials (a domain account on Windows), run it where it has no outbound access, or set this to `off` |
| `FLYW8T_TRUSTED_PROXIES` | no | (none) | comma-separated addresses or `addr/prefix` ranges of reverse proxies whose forwarded client address is believed (the Compose tunnel is `172.29.0.10`). Empty: the socket address is used and forwarding headers are ignored, so a client cannot choose its own address |
| `FLYW8T_FAMILY_LINKS` | no | (none) | links to your other products, shown in the console's navigation under **Products**: `Label=https://url`, comma-separated, at most 8 (for example `AnchorDesk=https://desk.example.com,PortGlass=https://portglass.example.com`). Links only: nothing is fetched from them, no sign-in is shared and no context is passed. The server refuses to start on an entry that is not `http(s)://host[:port]` with an optional path (the host and port are checked; the rest only for characters that cannot appear in an address) |
| `FLYW8T_CLIENT_IP_HEADER` | no | `cf-connecting-ip` | the header a trusted proxy puts the client address in (`x-forwarded-for` for most others; its last entry is used) |
| `RUST_LOG` | no | `info,sqlx=warn` | log filter |

Migrations are embedded in the binary and applied at startup.

## Windows agent

Build (or, once releases exist, download a signed build):

```powershell
cargo build --release -p flyw8t-agent      # target\x86_64-pc-windows-msvc\release\flyw8t-agent.exe
```

On the endpoint, in an **elevated** PowerShell:

```powershell
# In flyw8t: Organizations → <org> → Create enrollment token (shown once)
.\flyw8t-agent.exe enroll --server https://rmm.example.com --token fw8e_…
.\flyw8t-agent.exe service install      # copies itself to Program Files; automatic start, LocalSystem, restart on failure
.\flyw8t-agent.exe status
```

`enroll` creates `%ProgramData%\flyw8t` and `%ProgramData%\flyw8t\agent` owned by Administrators and open only to SYSTEM and Administrators, in the same Windows call that creates them, before it writes the device key. So it must run elevated. If either folder already exists, it must already be exactly that, with no junctions, links or other accounts' permissions; otherwise `enroll` refuses and says so. flyw8t never "repairs" a folder someone else made, because whoever made it may still hold a way back in.

`service install` copies the agent to `flyw8t\flyw8t-agent.exe` under Program Files, and the service runs that copy, never the file you ran. A download folder is usually writable by other accounts, and whatever sits there would run as SYSTEM. The program folder is created owned by Administrators: everyone may read and run it, and only SYSTEM and Administrators may change it. An existing program folder must already be like that and hold nothing but the agent. Install also refuses if the service is already installed, or if the state folders are not as `enroll` made them. Both locations come from Windows itself, not from `%ProgramFiles%` or `%ProgramData%`.

The service uses only the default state folder. `--state-dir` is for running the agent in the foreground (`flyw8t-agent run`); such a folder is left with its usual permissions, so its key is not protected.

The agent never loads `VCRUNTIME140.dll` (the VC runtime is linked in), and it loads its other DLLs from System32 only, so a DLL planted next to it in a download folder is ignored. Until release binaries are signed and `install` checks its own signature, run `install` from a folder only administrators can write to, such as the one the release was unpacked into as Administrator: nothing yet proves that the file being copied is the one Windows started.

The service's log is `logs\agent.log` in the state folder; it grows to 10 MiB, then rotates to `agent.log.1`. If the log cannot be opened, the service says so in the Application event log (source `flyw8t-agent`) and runs without one. A crash shows in the System event log (Service Control Manager, event 7031), and Windows restarts the service after 10 s, then 60 s (checked: a killed agent was back and connected within about 12 s). Restarting after the service stops itself with an error (a revoked credential, say) is configured too, but Windows applies that setting only from its next restart, and it has not been tested.

To upgrade: `flyw8t-agent service uninstall`, then `service install` from the new file. To remove: `flyw8t-agent service uninstall`, delete `%ProgramFiles%\flyw8t` and `%ProgramData%\flyw8t`, then retire the device in the console.

> Run for real on Windows 11 (2026-11-07, dev-process row 36): install, refusals, uninstall, restart after a kill, owners and permissions, the log, and a DLL-planting test. A reboot was not checked.

## Damaged agent journal

The agent refuses to start if a journal entry cannot be read/decoded, its job id does not match its file name, two files name the same job, or a legacy `.corrupt` quarantine exists. It preserves the files. Earlier builds quarantined unreadable entries and then forgot their jobs, allowing a repeated offer to be accepted as new. Restarting must not bypass this protection.

1. Stop the service and preserve the whole state directory with its existing restricted permissions. The startup error identifies the offending file. Investigate the disk/filesystem before attempting recovery.
2. Do not delete the entry, clear the journal or restore an older journal backup to get the agent online: that can erase proof that work ran. Recover the same identity only if its complete execution history can be established.
3. If that history cannot be recovered, retain the evidence, retire/revoke the old device in the console and enroll a **new device identity** into a fresh protected state directory. The new identity does not inherit the old device's jobs. Follow the normal enrollment and service installation procedure; do not weaken directory permissions to reuse damaged state.
4. Preserve unknown outcomes on the old device. A technician reviews effects before explicitly issuing any replacement work. Recovery never automatically retries an old operation.

Ordinary temporary-file and rename failures leave the previous journal state in memory and on disk; a retry must perform the write again. These tested I/O failures do not establish behavior under physical power loss or actual disk exhaustion (see [reliability.md](reliability.md)).

## Backup and restore

Application records are in PostgreSQL; a recoverable deployment also needs its configuration, `FLYW8T_FIELD_KEY` (when secret fields are used), TLS material and the separate signer/root-key recovery plan. Keep these protected and backed up off-host. Losing the field key makes the encrypted values unreadable even with a good database dump. Signing keys stay outside the server and have their own protected backup, never bundled into a server image.

Agents retain their own journals and re-send unacknowledged results after a server-database restore. Jobs created after the database backup are gone; reports about an unknown job are audited no-ops. This reconciliation does not recover missing jobs, prove a zero RPO, or permit rolling back an agent's journal.

**Backup** (daily at minimum; copy off-host):

```sh
docker compose exec -T db pg_dump -U flyw8t -Fc flyw8t > flyw8t-$(date +%F).dump
```

**Restore** into an empty stack:

```sh
docker compose down
docker volume rm flyw8t_pgdata
docker compose up -d db
docker compose exec -T db pg_restore -U flyw8t -d flyw8t --no-owner < flyw8t-YYYY-MM-DD.dump
docker compose up -d server
```

Off-host restore into an empty stack has **not been rehearsed** yet; doing so is a 0.2 exit criterion. Restore into a scratch stack and sign in before trusting a backup.

The repeatable CI check is `node scripts/compose-smoke.mjs` from the repository root (Node 22+, Docker Compose). It creates a uniquely named project with throwaway credentials and a loopback port, sets up TOTP through the console, creates an organization, dumps the database, stops that server, restores into a newly created empty database, and verifies the restored account/factor and organization without bootstrap credentials. It removes only its own project/volumes on exit. Its fixed Compose subnet must be free. This is integration evidence, not a substitute for off-host backups, encryption-key recovery, an actual host-loss drill or Windows service testing.

The append-only triggers on `job_events` and `audit_events` are restored with the schema, and `pg_restore` inserts rows rather than updating, so the triggers do not block a restore.

## Upgrades

Stop the server, back up, pull or build the new image, start it. Migrations run on start; a failed migration leaves the server down, not half-migrated (each migration runs in a transaction). Agents reconnect on their own. Zero-downtime upgrades need more than one instance ([ADR-0009](decisions/ADR-0009-availability-and-scale-out.md)).

## Monitoring the deployment

Scrape `/metrics` and probe `/readyz` from **outside** the host. See [reliability.md](reliability.md) for the SLIs. `/metrics` is unauthenticated and exposes counts only (no names or identifiers); restrict it at the proxy if that matters to you.

## Existing test enrollment

An enrollment refusal means the state directory already contains a device identity.
Changing `--server` or downloading a newer binary does not move that identity to another
server. Preserve its complete state directory, including the private key and job journal;
do not delete or edit the journal to get past the refusal.

For an existing localhost/test enrollment, stop the agent/service first and retain an
access-controlled archive of the complete old state. Follow an operator-reviewed migration
procedure to create a fresh state directory and enroll a new identity against the intended
server, then verify that exact device appears there before retiring the old test identity.
Keep any unresolved old job evidence with its original identity; never transplant an old
journal into a new identity. Use the reviewed migration helper when the operator supplies
it, rather than removing individual credential or history files.

A signed upgrade of an agent staying on the same server should preserve its identity and
journal. Re-enrollment is a migration step, not the normal upgrade path.

## Directory-aware server rollout and rollback

Remove all server processes older than 0.1.4 before provisioning directory users or sudo
keys. Once directory data exists, do not roll back only the server image: 0.1.3 lacks the
new authentication exclusions. A reviewed rollback must preserve history while removing
or revoking directory authority; backup restore requires coordination with agent journals,
job reconciliation and IdP/ingress configuration. Restoring an old database casually can
lose fleet/job evidence. See [directory setup and limits](directory-sso.md). Existing 0.1.3
agents may continue diagnostics; this is a server downgrade constraint.
