-- Signing in with a passkey (ADR-0014 section 3). Before sign-in there is no session to hold the challenge, so it is
-- held here, keyed by the digest of the browser's sign-in cookie (the login CSRF token): only the browser that opened
-- the page can answer it, once.
CREATE TABLE webauthn_sign_in_challenges (
    login_hash  bytea PRIMARY KEY,
    challenge   bytea NOT NULL,
    expires_at  timestamptz NOT NULL
);
CREATE INDEX webauthn_sign_in_challenges_expiry ON webauthn_sign_in_challenges (expires_at);
