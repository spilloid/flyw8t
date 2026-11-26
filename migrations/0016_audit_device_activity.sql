-- Look up device activity and the operator events associated with its jobs.
CREATE INDEX audit_device_activity ON audit_events (target_type, target_id)
    WHERE target_type IN ('device', 'job');
