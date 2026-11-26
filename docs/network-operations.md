# Network operations in flyw8t

Status: first sprint, unreleased. flyw8t owns the operations console, organizations,
sites, access control and audit history. NetViz supplies discovery observations;
PortGlass supplies device web-interface access from the technician's computer.

## Set up a site

1. Create an organization and site in flyw8t. Open the site, then **Network operations**.
2. Expand **Add a site collector**. Give it a name, one IPv4 CIDR (/16 through /32),
   and a scan interval of 30–3600 seconds. Separate ranges can use separate collectors.
   NetViz's existing one-range service remains unchanged; this sprint does not add
   multi-range service orchestration.
3. Register the collector. Save the JSON configuration shown once as `probe.json`
   on the site machine. It is compatible with the current NetViz probe's configuration
   format: `version`, `cidr`, `anchordesk_url`, `probe_key`, and `interval`. The legacy
   `anchordesk_url` field points to flyw8t here. The file contains a secret: restrict it
   to the service account. Do not paste the key into a command line or a URL.
4. Run `netviz-probe -config probe.json`, or use NetViz's existing service installation
   workflow with this configuration. The one-time setup page does not install software.
5. The collector page shows receipt of heartbeats and inventory independently. Open
   **Network**, filter by site, and select an asset to inspect its observations.

`FLYW8T_PUBLIC_URL` must be the reachable console origin, using HTTPS beyond loopback.
The generated configuration uses this configured URL, not an untrusted Host header.
The probe needs local reachability to the selected range and outbound access to flyw8t.
For local ARP-derived MAC information, deploy it on the relevant LAN segment. Scanning
a routed range does not establish switch-port or physical topology relationships.

Collectors authenticate with their own random `fw8n_` key in `X-Probe-Key`. Only its
SHA-256 digest is stored. It cannot sign in, enroll endpoints, run jobs, change access
settings or read inventory. Scope comes from registration, never from a report body.
Wrong keys are budgeted per client address (30 in five minutes across both endpoints; only a refused key is counted: a good key, a database error or an abandoned request is not), so set `FLYW8T_TRUSTED_PROXIES` when a proxy is in front or every collector shares the proxy's budget.

If a key is lost, revoke the collector and register a replacement. Revocation retains
inventory and history; in-flight writes serialize with revocation on the collector row.

## Device access

Run a PortGlass probe at the site and configure its normal controller authorization,
destination allowlist and optional relay. In flyw8t, save that probe's SHA-256
fingerprint on the corresponding collector. This is public identity metadata, not a
credential or a new trust grant. Each technician must already have exactly one matching
probe pinned in their own PortGlass controller.

From a recently reachable network asset, choose a discovered web port and **Review in
PortGlass**. The handoff page opens the local controller with the right probe and target
prefilled. The person must press Connect there. PortGlass's existing mTLS, allowlist,
session lifetime, isolated browser and audit checks still apply. The console records an
access **request**, never a successful connection it has not observed.

The PortGlass controller must include the `open-url` command from this sprint. On Windows,
register browser links explicitly after putting the executable in its permanent location:

```powershell
.\scripts\register-console-links.ps1 -ControllerPath 'C:\Tools\PortGlass\portglass.exe'
```

Registration is per-user and needs no elevation. Use `-Unregister` to remove it.
The handoff page also gives a `portglass open-url "portglass://connect?..."` command
for computers without a protocol registration. macOS browser-link registration is not
implemented in this sprint; the CLI handoff works where the controller is available.

Only discovered ports 80, 443, 8080 and 8443 are offered initially. Stale observations,
revoked collectors, no-response observations and addresses reported more recently for
another asset cannot launch through the console. The link contains only a probe
fingerprint, IPv4 address/port and HTTP(S) scheme. It cannot supply a probe address,
new trust, credentials, command, browser flags or an arbitrary URL path.

## Identity, history and freshness

Network assets have their own records; they do not need an endpoint agent or agent key.
Their stable UUID is independent of their current IP. Identity prefers normalized MAC,
then site-scoped IP. An initial IP-only record can gain a MAC without changing its UUID;
a known MAC can move addresses without creating another asset. Duplicate IP ranges
across sites/customers remain independent. These are observed identities, not proof of
physical identity. MAC reuse, cloning and observations lacking MACs can require future
operator reconciliation; cross-site merging is deliberately not automatic.

Observation collection time and server receipt time are separate. A sample becomes stale
after three configured scan intervals plus 60 seconds; freshness is based on collection
time, so receiving old data does not make it current. Missing devices are not declared
offline just because a restarted collector sends a smaller snapshot. Older or duplicate
samples cannot overwrite newer state. First-seen time means first received by flyw8t,
not an unverified device-supplied discovery date.

Each asset retains its latest 100 observations; the detail page shows 30. Retrying an
identical timestamp creates no duplicate history. Reports are limited to 1 MiB and 1024
devices, 128 ports per device, and bounded descriptions. A batch is validated completely
before it writes; duplicate identities/addresses and out-of-range addresses reject it.
Empty snapshots update collector receipt status without changing asset reachability.
The workspace paginates assets in groups of 50 and shows up to 200 collectors per filter.

## Contract and first-sprint boundary

The server accepts NetViz's existing v1 `POST /probe/devices` and
`POST /probe/heartbeat` contract. No change to NetViz's frozen wire contract is required.
An authorized collector can lie about its own observations; the server validates shape,
scope and age, not the physical truth of a compromised machine's report.

This sprint provides discovery, inventory history and access handoff. It does not provide
SNMP health polling, LLDP/CDP topology, configuration backups, flow analysis, network
alert policies or automatic collector deployment. Those should extend these same site
and asset workflows. It is not yet a complete Auvik replacement.

## Verification

`tests/network.rs` checks the contract, site and role isolation, CSRF, key separation,
revocation, address changes, stale/replayed observations, bounded history and access
handoff. Its real-probe test also needs `FLYW8T_NETVIZ_PROBE` pointing to a built
NetViz probe; it scans loopback only. `ui_capture` includes network workspace, site,
asset and collector pages at all existing widths and themes.

## Proposed Network node selection

From **Network**, open a discovered asset and choose **Open web interface**. Show eligible enrolled devices for that site as network nodes. A node appears only after its owner opts it in, and the technician sees which node and web interface will be used before connecting.

Keep the session scoped to the selected asset's observed HTTP or HTTPS interface and the technician's organization and site access. Recheck the node's opt-in and connection at launch. Record the operator, node, asset, destination interface and outcome. The existing PortGlass handoff continues to use its site's pinned probe and its own access policy.

**Browser links** in Windows Technician registers the local `flyw8t://` launcher for desktop actions. Node selection belongs on the Network asset page.
