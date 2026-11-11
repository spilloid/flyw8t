-- Script trust (ADR-0015 build step 3): the signed trust chain, and signed approvals of revisions. The server only
-- stores and hands these out. It verifies each one before storing it, so a bad one is refused at once, but agents
-- and flyw8t-sign verify everything again and never rely on these checks.

-- One row per trust-list version. `body` is the SignedList JSON exactly as uploaded.
CREATE TABLE trust_versions (
    version        bigint PRIMARY KEY CHECK (version >= 1),
    deployment_id  uuid NOT NULL,
    hash           bytea NOT NULL UNIQUE CHECK (octet_length(hash) = 32),
    body           text NOT NULL CHECK (octet_length(body) <= 1048576),
    uploaded_by    uuid NOT NULL REFERENCES users(id),
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION trust_versions_are_permanent() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'trust versions are never changed or deleted';
END
$$;
CREATE TRIGGER trust_versions_are_permanent BEFORE UPDATE OR DELETE ON trust_versions
    FOR EACH ROW EXECUTE FUNCTION trust_versions_are_permanent();
CREATE TRIGGER trust_versions_no_truncate BEFORE TRUNCATE ON trust_versions
    FOR EACH STATEMENT EXECUTE FUNCTION trust_versions_are_permanent();

-- One signer's approval of one revision. `body` is the SignedApproval JSON exactly as uploaded.
CREATE TABLE script_approvals (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    script_id        uuid NOT NULL REFERENCES scripts(id) ON DELETE RESTRICT,
    revision_number  integer NOT NULL,
    signer_key_id    bytea NOT NULL CHECK (octet_length(signer_key_id) = 32),
    body             text NOT NULL CHECK (octet_length(body) <= 65536),
    uploaded_by      uuid NOT NULL REFERENCES users(id),
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (script_id, revision_number, signer_key_id),
    FOREIGN KEY (script_id, revision_number) REFERENCES script_revisions (script_id, number)
);

-- Script runs (build step 4) travel as jobs with action 'script.run'. A C2 or C3 run waits in state 'created' until
-- someone uploads its run authorization; the run request people sign is kept here so it cannot change meanwhile.
ALTER TABLE jobs ADD COLUMN script_request text CHECK (octet_length(script_request) <= 1048576);
ALTER TABLE jobs ADD COLUMN script_authorization text CHECK (octet_length(script_authorization) <= 65536);
