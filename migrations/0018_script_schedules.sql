ALTER TABLE jobs DROP CONSTRAINT jobs_request_channel_check;
ALTER TABLE jobs ADD CHECK (request_channel IN ('web', 'api', 'scheduler'));

CREATE TABLE script_schedules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    device_id uuid NOT NULL,
    script_id uuid NOT NULL,
    revision_number integer NOT NULL,
    parameter_values jsonb NOT NULL CHECK (jsonb_typeof(parameter_values) = 'object'),
    timeout_secs integer NOT NULL CHECK (timeout_secs BETWEEN 1 AND 3600),
    delivery_secs integer NOT NULL CHECK (delivery_secs IN (900, 3600, 86400, 604800)),
    cadence text NOT NULL CHECK (cadence IN ('once', 'daily', 'weekly')),
    first_at timestamptz NOT NULL,
    next_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid NOT NULL REFERENCES users(id),
    stopped_at timestamptz,
    stop_reason text,
    CHECK (next_at IS NULL OR next_at >= first_at),
    CHECK ((stopped_at IS NULL) = (stop_reason IS NULL)),
    CHECK (stopped_at IS NULL OR next_at IS NULL),
    FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
    FOREIGN KEY (script_id, revision_number) REFERENCES script_revisions(script_id, number)
);
CREATE INDEX script_schedules_due ON script_schedules (next_at, id) WHERE next_at IS NOT NULL;
CREATE INDEX script_schedules_device ON script_schedules (organization_id, device_id, created_at DESC);

CREATE TABLE script_schedule_occurrences (
    schedule_id uuid NOT NULL REFERENCES script_schedules(id),
    due_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    outcome text NOT NULL CHECK (outcome IN ('queued', 'missed', 'blocked')),
    reason text,
    job_id uuid UNIQUE REFERENCES jobs(id),
    PRIMARY KEY (schedule_id, due_at),
    CHECK ((outcome = 'queued') = (job_id IS NOT NULL)),
    CHECK ((outcome = 'queued') = (reason IS NULL))
);
