ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_scopes_check;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_scopes_check
    CHECK (scopes <@ ARRAY['read', 'jobs:run', 'support:screenshot']::text[] AND cardinality(scopes) > 0);

-- Reserve an ID before releasing a capture request to the viewer. Receipts survive
-- lost HTTP responses and server restarts. No pixels, keys or ciphertext are stored.
CREATE TABLE support_screenshot_receipts (
    session_id uuid NOT NULL REFERENCES support_sessions(id),
    request_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, request_id)
);
