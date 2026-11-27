-- An optional, technician-selected association. The participant still chooses what to share.
ALTER TABLE support_sessions
    ADD COLUMN linked_device_id uuid,
    ADD CONSTRAINT support_session_linked_device_org
        FOREIGN KEY (organization_id, linked_device_id)
        REFERENCES devices (organization_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT support_session_linked_device_view_only
        CHECK (linked_device_id IS NULL OR (organization_id IS NOT NULL AND capabilities = ARRAY['view_screen']::text[]));
