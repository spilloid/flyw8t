-- Attended support sessions belong to an organization, like everything else a technician
-- touches: creation checks membership, and every read is scoped by it.

ALTER TABLE support_sessions ADD COLUMN organization_id uuid REFERENCES organizations(id);

-- Sessions from before this migration have no organization. End any that are still live,
-- then require one on every row written from now on.
UPDATE support_sessions
   SET state = 'revoked', ended_at = now(), ended_by = 'system',
       end_reason = 'upgrade: support sessions now belong to an organization',
       code_hash = NULL, invite_hash = NULL, participant_hash = NULL
 WHERE organization_id IS NULL
   AND state NOT IN ('closed', 'expired', 'rejected', 'connection_failed', 'revoked');

ALTER TABLE support_sessions
    ADD CONSTRAINT support_sessions_organization_required CHECK (organization_id IS NOT NULL) NOT VALID;

CREATE INDEX support_sessions_org ON support_sessions (organization_id, created_at DESC);
