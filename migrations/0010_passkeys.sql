-- Passkeys and security keys (WebAuthn), and sudo mode (ADR-0014 section 3).
--
-- A credential is an ES256 public key a user registered from their browser. A fresh assertion with one puts the
-- session in sudo mode for a few minutes, which the changes that widen what can run require. Approving scripts will
-- use the same credentials, each signing at the moment it approves.

CREATE TABLE webauthn_credentials (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The authenticator's own identifier for the credential, as the browser reports it.
    credential_id  bytea NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    -- Uncompressed SEC1 P-256 point: 0x04 || x || y.
    public_key     bytea NOT NULL CHECK (octet_length(public_key) = 65),
    name           text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    -- The authenticator's signature counter, when it keeps one (synced passkeys report 0).
    sign_count     bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_used_at   timestamptz
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id);

ALTER TABLE sessions
    -- Sudo mode lasts until this time.
    ADD COLUMN sudo_until            timestamptz,
    -- One WebAuthn ceremony in flight per session; spent by the first answer, right or wrong.
    ADD COLUMN webauthn_challenge    bytea,
    ADD COLUMN webauthn_purpose      text CHECK (webauthn_purpose IN ('register', 'sudo')),
    ADD COLUMN webauthn_expires_at   timestamptz,
    ADD CONSTRAINT sessions_webauthn_consistent CHECK (
        (webauthn_challenge IS NULL) = (webauthn_purpose IS NULL)
        AND (webauthn_challenge IS NULL) = (webauthn_expires_at IS NULL)
    );
