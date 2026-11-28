ALTER TABLE organizations ADD COLUMN automatic_agent_updates boolean NOT NULL DEFAULT true;
ALTER TABLE devices ADD COLUMN agent_updates_opt_out boolean NOT NULL DEFAULT false;

CREATE INDEX audit_organization_agent_update_policy ON audit_events (organization_id, at DESC, id DESC)
    WHERE target_type = 'organization' AND action = 'organization.agent_update_policy';
