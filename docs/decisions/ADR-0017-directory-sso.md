# ADR-0017: Optional OpenID Connect sign-in and SCIM directory authorization

Status: accepted (operator direction, 2026-11-15). Implementation/review evidence: dev-process rows 48 and 50; live provider and hardware validation remain open.

## Decision

Keep local accounts as independent break-glass identities (STD-004). Add optional OIDC
Authorization Code sign-in with S256 PKCE, browser-bound single-use state and nonce,
discovery, and JWKS signature validation restricted to RS256 and ES256 through the
maintained `openidconnect` library. Identity is the exact configured issuer and immutable
`sub`; email is display/contact data, never a linking key. An email collision returns a
conflict and requires a distinct local break-glass address; it never attaches the identities.
Directory accounts have no usable local password. Their passkeys serve sudo only.

The operator configures issuer/client credentials on the server. Discovery, authorization,
token and JWKS endpoints must share its origin, use HTTPS (HTTP only for loopback), have
no embedded credentials or fragments, and follow no redirects. Outbound requests have
connection and total deadlines and response byte limits. Requested scopes are fixed to
openid, profile, email and groups. IdP tokens are used only during sign-in and never retained.
A five-minute, browser-bound flow holds the verifier and nonce only in bounded process
memory; a restart expires pending flows. The flow cookie is HttpOnly, SameSite=Lax and
Secure with __Host- on HTTPS. Console sessions remain SameSite=Strict. The callback returns a static same-origin completion
document before navigation; a direct cross-site redirect would suppress the Strict cookie.
OIDC necessarily carries short-lived code/state in the callback query, a narrow exception
to the no-secrets-in-URLs rule; reusable credentials never use URLs. Callback responses
set no-referrer/no-store and deployment access logs must exclude callback queries.

An SSO sign-in creates a full session: the provider owns MFA policy. It never grants sudo.
First local passkey registration for a directory account requires a provider session with
verified `auth_time` no more than five minutes old, checked again under the user/session
locks. Authorization requests send max_age=300; a new flow against an old IdP session is
not evidence of fresh authentication. Later keys and sudo require an existing local
passkey exactly as for local accounts. Local password/TOTP registration remains unchanged.

## Directory synchronization and authorization

Expose SCIM 2.0 Users and Groups under `/scim/v2`, authenticated only by a separate
`fw8s_` credential. It is random, hashed at rest, revocable, shown once, and cannot authenticate
console/API requests. Personal API tokens and session cookies cannot authenticate SCIM.
An administrator in local passkey sudo mode rotates credentials and maps directory group
keys to a role and organization assignments. Several matches grant the highest mapped role
and union of organizations; administrator means all organizations. No mapping grants no access.

SCIM Users.externalId must be the exact OIDC subject. Groups.externalId must be the key
emitted in the signed ID token's groups claim. SCIM-managed users use synchronized group
membership as authoritative; sign-in cannot restore a deprovisioned account or overwrite
SCIM membership. JIT users use the signed groups claim. Local identities are never SCIM
resources. Unsupported SCIM operations/filters fail explicitly rather than pretending success.
Authentik 2026.5.3's exact group metadata replacement may omit outer PatchOp schemas;
only one pathless replace with unchanged id/externalId, Group schemas and displayName is
accepted in that shape. Explicit outer schemas are always checked. Targeted membership
removal accepts its bounded value array without removing other members. Bulk stays
unsupported; maxOperations=100 is an Authentik patch chunking hint.

Sign-in, sync and mapping changes use one reconciliation path. Directory writes serialize
on a transaction advisory lock, then lock all existing user rows in id order. State is read
in separate statements after locks, avoiding stale snapshots after a wait. Role/scope loss
or deprovision revokes sessions, personal API tokens, SCIM credentials the person issued and unspent enrollment tokens, and ends
attended-support sessions. Changes never remove the last enabled administrator. Directory
restoration cannot undo a separate manual administrator disable. Local users remain outside
reconciliation. Existing queued jobs and independent collector credentials retain existing
semantics. A compromised SCIM credential can change directory membership and so may grant
mapped administrator authority: protect it as an administrative secret.

## Limits and alternatives

No SAML/XML signature implementation, automatic email linking, IdP access-token API auth,
refresh-token storage, OIDC logout/backchannel logout, nested groups, SCIM bulk or password
provisioning. IdP disable is learned through SCIM or a later sign-in, not instantaneously
without that notification. Local break-glass administrators and recovery remain required.
The IdP is trusted for directory identities, signed group claims and MFA. OIDC/SCIM do not
directly link, authenticate or provision local identities. For a keyless directory account, a stolen full session
whose provider authentication and session age are both within five minutes can enroll an
attacker's own user-verifying key, then use it for sudo. A compromised trusted IdP can
create the same fresh-session proof and reach sudo through keyless mapped accounts.
For accounts with established keys, adding/removing keys and sudo still require a local
passkey. This bounded bootstrap tradeoff is accepted for the beta; purpose-bound provider
reauthentication for first-key enrollment is future hardening. Local break-glass accounts
remain independent. Local cross-site Chrome tests prove cookie completion behavior;
live Authentik provisioning/MFA and hardware passkeys need separate deployment evidence.

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
