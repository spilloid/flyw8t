-- Optional directory identities never attach to a local account by email.
CREATE TABLE directory_users (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
    issuer text NOT NULL,
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    active boolean NOT NULL DEFAULT true,
    managed boolean NOT NULL DEFAULT false,
    groups text[] NOT NULL DEFAULT '{}',
    directory_disabled boolean NOT NULL DEFAULT false,
    UNIQUE (issuer, subject)
);
CREATE TABLE directory_groups (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer text NOT NULL,
    external_id text NOT NULL CHECK (length(external_id) BETWEEN 1 AND 200),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    UNIQUE (issuer, external_id)
);
CREATE TABLE directory_members (
    group_id uuid NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES directory_users(user_id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE TABLE directory_mappings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer text NOT NULL,
    group_key text NOT NULL CHECK (length(group_key) BETWEEN 1 AND 200),
    role text NOT NULL CHECK (role IN ('admin','technician','readonly')),
    organization_ids uuid[] NOT NULL DEFAULT '{}',
    UNIQUE (issuer, group_key)
);
CREATE TABLE scim_credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer text NOT NULL,
    prefix text NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz
);
ALTER TABLE sessions ADD COLUMN auth_method text NOT NULL DEFAULT 'local'
    CHECK (auth_method IN ('local','oidc'));
ALTER TABLE sessions ADD COLUMN provider_authenticated_at timestamptz;
