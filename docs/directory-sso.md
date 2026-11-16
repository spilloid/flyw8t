# Directory sign-in and provisioning

flyw8t 0.1.4 supports optional OpenID Connect sign-in and SCIM 2.0 provisioning.
Keep at least one enabled **local** administrator with a working password/MFA and local
passkey as a break-glass account. Local identities remain independent of the provider.
Directory accounts cannot use local password or passkey sign-in; their passkeys confirm sudo.

Set all three values and restart the server:

```text
FLYW8T_OIDC_ISSUER=https://auth.example.com/application/o/flyw8t/
FLYW8T_OIDC_CLIENT_ID=flyw8t
FLYW8T_OIDC_CLIENT_SECRET=<secret from the provider's secret store>
```

Keep the client secret in an environment/secret store, never a URL or source control.
Issuer comparison is exact, including the trailing slash. Discovery, authorization, token
and JWKS endpoints must share the issuer's scheme/host/port. HTTPS is required except on
loopback. Requests follow no redirects and have a 3-second connect deadline, 10-second
total deadline and 1 MiB response limit. The server requests `openid profile email groups`,
authorization code, S256 PKCE and `max_age=300`. Supported ID-token algorithms are RS256
and ES256. The provider must include email and groups in the signed ID token; flyw8t never
calls userinfo. In Authentik, enable `include_claims_in_id_token` and configure the matching
property mappings. The provider must enforce its own MFA policy.

Register this exact redirect URI (using your own public origin):

```text
https://rmm.example.com/login/oidc/callback
```

The sign-in page offers **Sign in with your organization**. On completion, a static page
asks the person to continue into the console. This commits a same-origin page before
navigation so the console's Strict session cookie works after a cross-site provider visit.
Pending sign-ins expire after five minutes, are single-use and browser-bound, and do not
survive a server restart. There is no provider logout/backchannel logout or refresh token. Replacing an issuer does
not migrate identities or mappings: revoke old-provider users and credentials explicitly
before changing the configuration.

On **Administration → Directory sign-in and provisioning**, a local administrator in sudo
mode maps exact directory group keys to `readonly`, `technician` or `admin` and organizations.
Several matches grant the highest role and the union of organizations. Administrators span
all organizations. No match means no access. Changes apply immediately to existing users;
a change that would remove the last enabled administrator fails atomically. Keep a local
administrator while changing directory administrator groups. Large group/admin handovers
may need a separate promotion before demotion, because each reconciliation preserves an
administrator. Directory accounts have immutable `(issuer, sub)` identity; an email change
keeps that identity. A collision with another account returns a conflict, never links them.

SSO creates a full session; provider MFA replaces flyw8t TOTP for that sign-in. It does not
grant sudo. A directory user's first flyw8t passkey requires an OIDC session whose signed
`auth_time` and local session creation are both no more than five minutes old. A stale,
missing or future `auth_time` cannot bootstrap a passkey: sign in with the provider again,
and configure it to return `auth_time`. Later passkeys and all sudo confirmations require
an existing local passkey. During the five-minute first-key window, a stolen full session
can enroll an attacker's own user-verifying key and then enter sudo if no keys exist yet.
A compromised trusted provider can produce the same proof for keyless mapped users.
Protect the provider and fresh sessions accordingly. Accounts with established keys still
require a local key for further key changes and sudo. Purpose-bound provider reauthentication
is future hardening. Hardware/security-key interoperability remains an evidence gate.

## SCIM

On the directory page, **Rotate SCIM credential** makes a random `fw8s_` secret, displays it
once and revokes the previous credential. Only its hash and prefix are stored. Configure
the provider with this base URL and bearer credential:

```text
https://rmm.example.com/scim/v2
Authorization: Bearer fw8s_<shown once>
```

A SCIM credential cannot sign into the console or personal API, and personal API/session
credentials cannot provision a directory. Protect it as an administrative secret: it can
change membership in groups mapped to administrator access. Disabling/demoting the issuing
administrator also revokes their provisioning credentials; provision another key from an
active administrator after such a change. Revocation never restores old credentials.

The provider must supply these stable identifiers:

- **Users.externalId:** exactly the user's OIDC `sub`. Authentik can use `sub_mode: user_uuid`
  and a SCIM mapping of `str(user.uuid)`.
- **Groups.externalId:** exactly the string in the signed OIDC `groups` claim that the
  administrator maps. Configure the same property mapping for sign-in and provisioning.
- **Users.userName:** a usable unique email address; **displayName** is the person's name.

Only directory identities are SCIM resources. Once SCIM manages a user, synchronized active
status and group memberships are authoritative; sign-in cannot override them with token
claims. Before the first SCIM sync, JIT sign-in uses signed groups claims. SCIM `active=false`
or removing all mapped memberships disables the account. Re-enabling in the directory
restores directory access but cannot undo an explicit flyw8t administrator disable.

Users/Groups support resource reads, bounded lists, creation, replacement, supported PATCH
operations and deletion. User deletion deactivates and preserves the stable identity;
group deletion removes membership and reconciles affected users. Filters support explicit
equality forms; unsupported filters/operations return SCIM errors. Discover supported schema,
resource types and service features at `Schemas`, `ResourceTypes` and `ServiceProviderConfig`.
This is a constrained SCIM deletion contract: deleted users remain in GET/list as inactive,
rather than returning 404. Providers that require hard resource deletion need a compatibility
adaptation. An inactive identity still reserves its email: a different issuer/subject conflicts
until an operator resolves the address, never links automatically.

Authentik 2026.5.3 compatibility includes its exact single group metadata replacement
without outer PatchOp schemas (unchanged id/externalId and explicit inner Group schema),
and targeted `remove path=members` with a bounded array of user IDs. Missing membership
in metadata preserves existing members; removing an absent member is idempotent. Explicit
wrong schemas, changed identities and ambiguous filtered-path-plus-value removals fail.
Bulk is unsupported; `bulk.maxOperations=100` is advertised solely as the provider's PATCH
chunking hint. Normal PATCH requests still require their PatchOp schema.

There is no nested-group expansion, bulk provisioning, password provisioning or automatic
local-account linking.

Role/organization loss and deprovisioning revoke sessions, personal API tokens, SCIM keys
issued by that user and unspent enrollment tokens, and end attended-support sessions.
Already queued jobs and independently issued collector credentials retain their existing
semantics. Group/active changes at the provider are learned through SCIM or a later JIT
sign-in; disabling a provider account is not instantaneous without a notification.

## Deployment and evidence

Exclude the callback path's query string from proxy/CDN/access logs. Authorization codes
and state necessarily appear in the OIDC callback URL; they are short-lived and single-use,
while reusable credentials and provider tokens never appear in URLs. Callback responses
use `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. Provider/CDN query logs
remain the deployment operator's responsibility.

The in-process fake-provider tests exercise real code/PKCE exchange, RSA/ECDSA signatures,
negative token/state checks and directory revocation. They do not prove a live Authentik
blueprint, provider MFA policy, hardware passkeys, provider logout or remote-browser flows.
See [ADR-0017](decisions/ADR-0017-directory-sso.md) for the trust decision and limits.

If an unfamiliar passkey was enrolled, it persists until it is removed or an administrator
resets the account factors; investigate the provider and end affected sessions. Directory
passkeys cannot independently sign in, but can confirm sudo after a full provider sign-in.

Authentik 2026.5.3 interprets a create 409 as permission to find and adopt a resource by
mutable email/displayName. Both SCIM POST routes therefore emit no 409 responses. An exact
immutable identity replay with a matching profile returns 200 and that exact existing ID
without changing authority; all other create conflicts are explicit refusals with a status other than 409.
Users require the same normalized userName, display name and directory active state.
Groups require the requested case-insensitive displayName filter to resolve uniquely to
that same externalId; omitted members preserve existing membership, while explicit members
must match. Resolve profile drift by verified immutable externalId and PUT/PATCH before
retrying creation. Direct-ID responses close a rename/reuse race between POST and lookup.
Manual Authentik discovery/recovery is prohibited unless every externalId binding is
verified; the installed client's manual discovery does not itself guarantee that match.

A mapped SSO administrator who obtains sudo has ordinary application-administrator powers,
including password/MFA recovery and account administration against local users. A compromised
provider can reach those powers through the accepted keyless-admin bootstrap path. Local
identity-plane independence does not protect local accounts from an application administrator.

After directory identities or sudo keys exist, require server 0.1.4 or newer: server 0.1.3
lacks the directory password/passkey exclusions. Do not perform an image-only server downgrade.
Complete removal of older server processes before provisioning directory users. A reviewed
rollback must preserve histories while removing/revoking directory authority, or coordinate a
database backup restore with agent journals, job reconciliation and IdP/ingress changes; a
casual pre-SSO database restore can discard fleet/job evidence. Agent 0.1.3 can remain a
diagnostics client; this restriction applies to servers, not routine agent upgrades.

## HTTPS roots (0.1.5 hotfix)

OIDC uses bundled WebPKI trust roots with the explicit Ring rustls provider. Certificate
and hostname verification remain mandatory; redirects, cross-origin metadata endpoints,
and non-loopback plaintext stay refused. Version 0.1.4 accidentally selected reqwest's
manual-root feature without supplying roots, so HTTPS providers failed with UnknownIssuer.
Upgrade the server to 0.1.5; do not disable TLS verification or change the issuer to HTTP.
Private-CA providers are not configured through this feature; custom-CA support is separate
work. Public DNS/egress and the provider's valid certificate chain must still be reachable.

The release/full validation includes an ignored-by-default public HTTPS regression against
`https://example.com/`, with strict TLS, no proxy, no credentials, no redirects and bounded
requests. It requires outbound HTTPS and runs under `--include-ignored`; it never silently
skips. Local controls prove an untrusted self-signed certificate and a wrong hostname are
rejected, while a test-only trusted CA reaches the same running fixture.
