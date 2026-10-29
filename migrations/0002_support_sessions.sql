-- Attended support sessions (docs/attended-support.md). Separate from devices and jobs:
-- an attended session involves no agent and can never enroll one.

CREATE TABLE support_sessions (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_by              uuid NOT NULL REFERENCES users(id),
    capabilities            text[] NOT NULL CHECK (capabilities <@ ARRAY['view_screen']::text[] AND cardinality(capabilities) > 0),
    note                    text,
    state                   text NOT NULL CHECK (state IN ('created', 'waiting', 'authorizing', 'connecting', 'connected',
                                'disconnecting', 'closed', 'expired', 'rejected', 'connection_failed', 'revoked')),
    -- Single-use invitation credentials (SHA-256). Cleared once spent or when the session ends.
    code_hash               bytea UNIQUE,
    invite_hash             bytea UNIQUE,
    -- The participant's browser credential, set when the invitation is spent. Cleared at end.
    participant_hash        bytea UNIQUE,
    participant_ip          text,
    participant_user_agent  text,
    created_at              timestamptz NOT NULL DEFAULT now(),
    invite_expires_at       timestamptz NOT NULL,
    bound_at                timestamptz,
    consented_at            timestamptz,
    connected_at            timestamptz,
    ended_at                timestamptz,
    ended_by                text,
    end_reason              text
);
CREATE INDEX support_sessions_open ON support_sessions (state)
    WHERE state IN ('waiting', 'authorizing', 'connecting', 'connected', 'disconnecting');
CREATE INDEX support_sessions_creator ON support_sessions (created_by, created_at DESC);

CREATE TABLE support_events (
    id          bigserial PRIMARY KEY,
    session_id  uuid NOT NULL REFERENCES support_sessions(id) ON DELETE RESTRICT,
    at          timestamptz NOT NULL DEFAULT now(),
    kind        text NOT NULL,
    from_state  text,
    to_state    text,
    actor       text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX support_events_session ON support_events (session_id, id);
CREATE TRIGGER support_events_append_only BEFORE UPDATE OR DELETE ON support_events
    FOR EACH ROW EXECUTE FUNCTION flyw8t_forbid_mutation();
CREATE TRIGGER support_events_no_truncate BEFORE TRUNCATE ON support_events
    FOR EACH STATEMENT EXECUTE FUNCTION flyw8t_forbid_mutation();
