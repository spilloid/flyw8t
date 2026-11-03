-- Sites as a field scope (ADR-0014): a value set on a site applies to the site's devices, between the organization's
-- value and the device's own. Resolution for a device: device, site, organization, global, default.

-- The scope checks of 0007 were unnamed; replace them by what they check.
DO $$
DECLARE c record;
BEGIN
    FOR c IN SELECT conname FROM pg_constraint
              WHERE conrelid = 'field_definitions'::regclass AND contype = 'c'
                AND pg_get_constraintdef(oid) LIKE '%scopes%'
    LOOP
        EXECUTE format('ALTER TABLE field_definitions DROP CONSTRAINT %I', c.conname);
    END LOOP;
    FOR c IN SELECT conname FROM pg_constraint
              WHERE conrelid = 'field_values'::regclass AND contype = 'c'
                AND pg_get_constraintdef(oid) LIKE '%scope%'
    LOOP
        EXECUTE format('ALTER TABLE field_values DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;

ALTER TABLE field_definitions ADD CONSTRAINT field_definitions_scopes_check
    CHECK (cardinality(scopes) >= 1 AND scopes <@ ARRAY['global', 'organization', 'site', 'device']);

ALTER TABLE field_values ADD COLUMN site_id uuid REFERENCES sites(id) ON DELETE CASCADE;
ALTER TABLE field_values ADD CONSTRAINT field_values_scope_check
    CHECK (scope IN ('global', 'organization', 'site', 'device'));
-- Exactly the one target its scope names.
ALTER TABLE field_values ADD CONSTRAINT field_values_target_check CHECK (
       (scope = 'global' AND organization_id IS NULL AND site_id IS NULL AND device_id IS NULL)
    OR (scope = 'organization' AND organization_id IS NOT NULL AND site_id IS NULL AND device_id IS NULL)
    OR (scope = 'site' AND site_id IS NOT NULL AND organization_id IS NULL AND device_id IS NULL)
    OR (scope = 'device' AND device_id IS NOT NULL AND organization_id IS NULL AND site_id IS NULL));

DROP INDEX field_values_latest;
CREATE INDEX field_values_latest ON field_values (field_id, scope, organization_id, site_id, device_id, set_at DESC);
CREATE INDEX field_values_site ON field_values (site_id) WHERE site_id IS NOT NULL;
