-- Custom fields (ADR-0014 step 1): values set globally, per organization or per device, which scripts will read later.
-- Nothing here runs anything.

CREATE TABLE field_definitions (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- What scripts will call it: {{device.<key>}}, {{org.<key>}}, {{global.<key>}}.
    key                  text NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_]{0,39}$'),
    label                text NOT NULL CHECK (length(btrim(label)) BETWEEN 1 AND 100),
    kind                 text NOT NULL CHECK (kind IN ('text', 'number', 'boolean', 'choice', 'secret')),
    choices              text[] NOT NULL DEFAULT '{}',
    -- Where a value may be set.
    scopes               text[] NOT NULL CHECK (cardinality(scopes) >= 1 AND scopes <@ ARRAY['global', 'organization', 'device']),
    -- 'organization': every organization must set its own value. 'device': every device must resolve to one.
    required_at          text CHECK (required_at IN ('organization', 'device')),
    default_value        text,
    -- Technicians may change organization and device values (in their organizations). Global values are admin-only.
    technician_can_edit  boolean NOT NULL DEFAULT false,
    created_by           uuid NOT NULL REFERENCES users(id),
    created_at           timestamptz NOT NULL DEFAULT now(),
    archived_at          timestamptz,
    CHECK (kind <> 'secret' OR default_value IS NULL),
    CHECK (kind <> 'choice' OR cardinality(choices) >= 1)
);

-- Every change is a new row: the current value is the latest row for its field and target, and the rows before it are its
-- history. A row with neither a value nor a secret clears the value (the target then inherits again).
CREATE TABLE field_values (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    field_id         uuid NOT NULL REFERENCES field_definitions(id) ON DELETE RESTRICT,
    scope            text NOT NULL CHECK (scope IN ('global', 'organization', 'device')),
    organization_id  uuid REFERENCES organizations(id) ON DELETE CASCADE,
    device_id        uuid REFERENCES devices(id) ON DELETE CASCADE,
    value            text CHECK (value IS NULL OR length(value) <= 1000),
    -- Secret values only: AES-256-GCM, nonce || ciphertext, under the server's FLYW8T_FIELD_KEY. Never shown again.
    secret           bytea,
    set_by           uuid NOT NULL REFERENCES users(id),
    set_at           timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope = 'global' AND organization_id IS NULL AND device_id IS NULL)
        OR (scope = 'organization' AND organization_id IS NOT NULL AND device_id IS NULL)
        OR (scope = 'device' AND device_id IS NOT NULL AND organization_id IS NULL)),
    CHECK (value IS NULL OR secret IS NULL)
);
CREATE INDEX field_values_latest ON field_values (field_id, scope, organization_id, device_id, set_at DESC);
CREATE INDEX field_values_org ON field_values (organization_id) WHERE organization_id IS NOT NULL;
CREATE INDEX field_values_device ON field_values (device_id) WHERE device_id IS NOT NULL;
