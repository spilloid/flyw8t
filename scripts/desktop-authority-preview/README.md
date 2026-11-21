# Independent workstation authorization rehearsal

This offline test package exercises how an independently administered authority and an endpoint decide whether a technician may receive a short-lived grant. The only scope is `view_synthetic_chart`. A successful grant permits the test to exercise a lease in SQLite. The tests use synthetic identities and generated keys.

Run the native Node tests from this directory with Node.js 24.22 or later.

```sh
npm ci --ignore-scripts
npm test
```

## Workstation selection

The policy administrator signs a selection for one tenant, device, enrollment and enrollment generation. The authorization service and endpoint each verify it against an independently provisioned Ed25519 public key and persist the decision in their own SQLite store. Each selection has a revision and expires within two minutes. Changing an enrollment ID requires a higher generation. Even a new signed revision cannot return a workstation to an earlier generation.

| Latest selection | Effect on a synthetic grant |
| --- | --- |
| Notify with Stop | A technician may request a grant with fresh identity, endpoint and viewer evidence. |
| Ask first | Deny the request. The technician needs a separate attended workflow. |
| Disabled, unknown, stale or wrong enrollment | Deny the request. |

The endpoint signs a one-minute offer naming the technician session, device tuple, policy revision, scope, viewer origin and both transport fingerprints. It persists a random nonce and the digest of the exact signed offer. The test supplies synthetic fingerprints.

The authority verifies three separate signatures. The endpoint must match an independently configured entitlement. The identity issuer must attest the expected technician, authority-specific audience, challenge nonce and dedicated password-and-TOTP assurance within five minutes. The viewer must confirm the same technician, session, origin, offer digest and fingerprints. The authority verifies its own workstation selection before issuing the grant and after the signer responds.

The grant signer accepts a verified transaction through a scope-specific adapter. Its test key is independent of the identity, viewer, endpoint and policy administrator keys. The endpoint verifies the signed result. Grant expiry is bounded by 30 seconds, the selection expiry and each underlying piece of evidence. The test adapter uses an ephemeral software key. A deployed authority could also hold a provider-managed key.

## Replay, changes and local Stop

The endpoint spends an offer once and records admission in the same transaction. Each lease check reads the current decision, local revocations, expiry and clock high-water mark. A demotion invalidates pending and active work. A later Notify with Stop selection requires a fresh offer. The SQLite policy history retains the applied revision, enrollment, time, mode, expiry and a digest of each signed update. Lower revisions and conflicting updates at the same revision are rejected after restart.

To stop one synthetic session, the fixture can cancel its offer or revoke its lease. Other sessions can continue. The fixture also exposes an endpoint-wide emergency disable through `stopLocally()`. It permanently vetoes all current and future admissions in that ledger, including after restart and receipt of a fresh signed policy. There is no recovery operation in the rehearsal. A lease UUID indexes simulated local state. It proves no binding to a running Windows logon, input target or transport.

Revocation persists its audit intent with the veto. The verifier can recover an interrupted journal delivery once. A veto records the greatest trustworthy time observed so far and still takes effect if the clock fails. Verification and admission preserve time observations even on rollback, signature failure and failed audit writes, preventing an unrelated expired lease from becoming usable after restart. Audit correlation uses a one-way digest.

## Remaining evidence for deployment

- Independent administration and custody of the policy and grant keys, grant signer permissions, and recovery and rotation procedures.
- Organization SSO with a dedicated TOTP assurance mapping, independently distributed viewer code, observed transport fingerprints, and binding to the actual Windows logon session.
- Authenticated delivery of policy changes, endpoint-protected storage and rollback-resistant recovery. An isolated verifier can continue relying on its last signed selection through expiry.
- Integration of revocation and a visible local Stop with a real transport, independently operated issuance and denial auditing, and physical Windows acceptance. The rehearsal contains no screen capture, input injection, network service or deployment switch.
