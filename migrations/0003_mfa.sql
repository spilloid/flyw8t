-- Second factor for the web console: TOTP plus single-use recovery codes.
--
-- A browser session now has a stage. A correct password alone yields an `mfa` session (enter
-- a code) or an `enroll` session (set up a code first, when MFA is required); only a `full`
-- session reaches the console. Completing the second factor rotates the session secret.

ALTER TABLE users
    ADD COLUMN totp_secret      bytea,
    ADD COLUMN totp_enabled_at  timestamptz,
    -- The last time step a code was accepted for; a code is valid only for a later step.
    ADD COLUMN totp_last_step   bigint,
    ADD CONSTRAINT users_totp_consistent CHECK (
        (totp_enabled_at IS NULL) = (totp_secret IS NULL)
    );

ALTER TABLE sessions
    ADD COLUMN stage                text NOT NULL DEFAULT 'full' CHECK (stage IN ('mfa', 'enroll', 'full')),
    -- A secret being set up in this session, not yet confirmed with a code.
    ADD COLUMN pending_totp_secret  bytea,
    ADD COLUMN mfa_attempts         integer NOT NULL DEFAULT 0 CHECK (mfa_attempts >= 0);

-- Sessions created before this migration were password-only. Sign everyone out.
UPDATE sessions SET revoked_at = now() WHERE revoked_at IS NULL;

CREATE TABLE recovery_codes (
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    used_at     timestamptz,
    PRIMARY KEY (user_id, code_hash)
);
