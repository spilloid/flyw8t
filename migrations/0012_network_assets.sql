-- Network assets are observations from site-bound collectors, not enrolled agents.
CREATE TABLE network_collectors (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
    cidr text NOT NULL,
    interval_secs integer NOT NULL CHECK (interval_secs BETWEEN 30 AND 3600),
    token_hash bytea NOT NULL UNIQUE,
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    heartbeat_at timestamptz,
    inventory_at timestamptz,
    version text,
    portglass_fingerprint text,
    FOREIGN KEY (organization_id, site_id) REFERENCES sites(organization_id, id),
    UNIQUE (organization_id, site_id, id)
);
CREATE INDEX network_collectors_site ON network_collectors(site_id);

CREATE TABLE network_assets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    identity_key text NOT NULL,
    ip text NOT NULL,
    mac text,
    hostname text NOT NULL,
    vendor text NOT NULL,
    device_type text NOT NULL,
    status text NOT NULL CHECK (status IN ('up', 'down', 'unknown')),
    open_ports integer[] NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    collected_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, site_id, collector_id)
        REFERENCES network_collectors(organization_id, site_id, id),
    UNIQUE (site_id, identity_key)
);
CREATE INDEX network_assets_scope ON network_assets(organization_id, site_id);
CREATE INDEX network_assets_address ON network_assets(site_id, ip);

-- Bounded observation history, distinct from the permanent append-only audit log.
CREATE TABLE network_observations (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id uuid NOT NULL REFERENCES network_assets(id),
    collector_id uuid NOT NULL REFERENCES network_collectors(id),
    collected_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    observation jsonb NOT NULL,
    UNIQUE (asset_id, collector_id, collected_at)
);
CREATE INDEX network_observations_asset ON network_observations(asset_id, id DESC);
