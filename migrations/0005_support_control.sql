-- Attended remote control (ADR-0012): sessions may request `control_input`, which adds a
-- consent step in the native helper (`awaiting_helper`) and a one-time helper launch token.

ALTER TABLE support_sessions DROP CONSTRAINT support_sessions_capabilities_check;
ALTER TABLE support_sessions ADD CONSTRAINT support_sessions_capabilities_check CHECK (
    capabilities <@ ARRAY['view_screen', 'control_input']::text[]
    AND 'view_screen' = ANY (capabilities)
);

ALTER TABLE support_sessions DROP CONSTRAINT support_sessions_state_check;
ALTER TABLE support_sessions ADD CONSTRAINT support_sessions_state_check CHECK (state IN (
    'created', 'waiting', 'authorizing', 'awaiting_helper', 'connecting', 'connected',
    'disconnecting', 'closed', 'expired', 'rejected', 'connection_failed', 'revoked'
));

ALTER TABLE support_sessions
    -- Single use, short-lived, issued only after the browser consent of a control session.
    ADD COLUMN helper_token_hash        bytea UNIQUE,
    ADD COLUMN helper_token_expires_at  timestamptz,
    ADD COLUMN helper_attached_at       timestamptz,
    ADD COLUMN awaiting_helper_at       timestamptz;

DROP INDEX support_sessions_open;
CREATE INDEX support_sessions_open ON support_sessions (state)
    WHERE state IN ('waiting', 'authorizing', 'awaiting_helper', 'connecting', 'connected', 'disconnecting');
