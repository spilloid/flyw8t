-- Device management from the console: a name people choose, notes, tags, and batches of jobs
-- run on many devices at once.

-- The hostname stays what the device reports; the display name is what people call it.
ALTER TABLE devices
    ADD COLUMN display_name text CHECK (display_name IS NULL OR length(btrim(display_name)) BETWEEN 1 AND 200),
    ADD COLUMN notes        text NOT NULL DEFAULT '' CHECK (length(notes) <= 4000);

CREATE INDEX devices_display_name ON devices (lower(display_name));

-- Free-form labels for finding and targeting devices ("kiosk", "finance", "pilot-ring").
-- Lowercase, so "Kiosk" and "kiosk" are one tag.
CREATE TABLE device_tags (
    device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tag        text NOT NULL CHECK (tag ~ '^[a-z0-9][a-z0-9._:-]{0,39}$'),
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, tag)
);
CREATE INDEX device_tags_tag ON device_tags (tag);

-- Jobs created together for many devices share a batch, so their results read as one.
ALTER TABLE jobs ADD COLUMN batch_id uuid;
CREATE INDEX jobs_batch ON jobs (batch_id) WHERE batch_id IS NOT NULL;
