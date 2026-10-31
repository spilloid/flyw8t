# Deployment

> **Status:** the Compose stack and Dockerfile are written but **have not been run yet** (no Docker on the development machine; AT-01). CI builds the image. The server itself, native TLS, and every database path are tested against PostgreSQL 18 directly.

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

## Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `FLYW8T_DATABASE_URL` (or `DATABASE_URL`) | yes | — | PostgreSQL URL |
| `FLYW8T_PUBLIC_URL` | yes | — | URL technicians and agents use; `https://` unless loopback |
| `FLYW8T_BIND` | no | `127.0.0.1:8080` (image: `0.0.0.0:8080`) | listen address |
| `FLYW8T_TLS_CERT`, `FLYW8T_TLS_KEY` | together | — | PEM chain and key for native TLS |
| `FLYW8T_BOOTSTRAP_ADMIN_EMAIL`, `…_PASSWORD` | together | — | first administrator, created only while no users exist; password ≥ 12 characters |
| `FLYW8T_REQUIRE_MFA` | no | `true` | every console user sets up two-step verification (TOTP) before reaching the console; `false` makes it optional per user |
| `FLYW8T_HELPER_PATH` | no | — | the signed `flyw8t-helper.exe` offered to participants of remote-control sessions (ADR-0012). Without it, control sessions say the helper is not available; screen viewing is unaffected |
| `FLYW8T_TRUSTED_PROXIES` | no | (none) | comma-separated addresses or `addr/prefix` ranges of reverse proxies whose forwarded client address is believed (the Compose tunnel is `172.29.0.10`). Empty: the socket address is used and forwarding headers are ignored, so a client cannot choose its own address |
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
.\flyw8t-agent.exe service install      # automatic start, LocalSystem, restart on failure
.\flyw8t-agent.exe status
```

State lives in `%ProgramData%\flyw8t\agent` (`agent.json`, `device.key`, `journal\`). `service install` restricts it to SYSTEM and Administrators. To remove: `flyw8t-agent service uninstall`, then delete the directory, then revoke the device in the console.

> The service install path has **not** been run yet (AT-06 manual check). Foreground `flyw8t-agent run` is what the tests exercise.

## Backup and restore

Everything that matters is in PostgreSQL. Agents keep their own journal and re-send unacknowledged results after a restore, so a restore loses nothing they still hold. Jobs created after the backup are gone, and the job-lifecycle rules make any device report about a job the restored database does not know a no-op that is audited, not an error.

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

Restore has **not been rehearsed** yet; doing so is a 0.2 exit criterion. Restore into a scratch stack and sign in before trusting a backup.

The append-only triggers on `job_events` and `audit_events` are restored with the schema, and `pg_restore` inserts rows rather than updating, so the triggers do not block a restore.

## Upgrades

Stop the server, back up, pull or build the new image, start it. Migrations run on start; a failed migration leaves the server down, not half-migrated (each migration runs in a transaction). Agents reconnect on their own. Zero-downtime upgrades need more than one instance ([ADR-0009](decisions/ADR-0009-availability-and-scale-out.md)).

## Monitoring the deployment

Scrape `/metrics` and probe `/readyz` from **outside** the host. See [reliability.md](reliability.md) for the SLIs. `/metrics` is unauthenticated and exposes counts only (no names or identifiers); restrict it at the proxy if that matters to you.
