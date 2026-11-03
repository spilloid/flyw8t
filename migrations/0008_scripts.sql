-- Script library (ADR-0014 step 2): scripts and their revisions, kept for the record. Nothing here runs anything, and
-- nothing is approved yet (step 3): every revision is a draft.

CREATE TABLE scripts (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL: a global script, seen in every organization. A script never moves between organizations.
    organization_id  uuid REFERENCES organizations(id) ON DELETE RESTRICT,
    name             text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    language         text NOT NULL CHECK (language IN ('powershell', 'bash', 'python')),
    description      text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    created_by       uuid NOT NULL REFERENCES users(id),
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX scripts_name ON scripts (coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(name));

-- Every save is a new revision. The hash covers what a revision would run (script, language, risk class, parameters,
-- source); approval in step 3 signs it.
CREATE TABLE script_revisions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    script_id     uuid NOT NULL REFERENCES scripts(id) ON DELETE RESTRICT,
    number        integer NOT NULL CHECK (number >= 1),
    source        text NOT NULL CHECK (octet_length(source) BETWEEN 1 AND 262144),
    risk_class    text NOT NULL CHECK (risk_class IN ('C0', 'C1', 'C2', 'C3')),
    -- The parameter declarations as written (one per line), so they diff like the source.
    parameters    text NOT NULL DEFAULT '' CHECK (octet_length(parameters) <= 16384),
    content_hash  bytea NOT NULL CHECK (octet_length(content_hash) = 32),
    -- The syntax check made when it was saved: which checker, or none available, and what it found.
    syntax_check  jsonb NOT NULL,
    note          text NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    author        uuid NOT NULL REFERENCES users(id),
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (script_id, number)
);

-- A revision is a record: it is never changed or removed.
CREATE FUNCTION script_revisions_are_permanent() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'script revisions are never changed or deleted';
END
$$;
CREATE TRIGGER script_revisions_are_permanent BEFORE UPDATE OR DELETE ON script_revisions
    FOR EACH ROW EXECUTE FUNCTION script_revisions_are_permanent();
CREATE TRIGGER script_revisions_no_truncate BEFORE TRUNCATE ON script_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION script_revisions_are_permanent();
