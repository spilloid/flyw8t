-- Password changes: when a password last changed, and whether an administrator made it up for the person
-- (a temporary password they have not replaced yet). Existing rows: never changed, not temporary.
ALTER TABLE users ADD COLUMN password_changed_at timestamptz;
ALTER TABLE users ADD COLUMN password_temporary boolean NOT NULL DEFAULT false;
