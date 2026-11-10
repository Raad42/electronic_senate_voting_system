-- Append-only audit log (GR05). body is the canonical JSON that was hashed and signed.
CREATE TABLE events (
    seq       BIGINT PRIMARY KEY,
    body      TEXT NOT NULL,
    prev_hash CHAR(64) NOT NULL,
    hash      CHAR(64) NOT NULL UNIQUE,
    signature TEXT NOT NULL
);

-- Belt and braces: even the table owner cannot UPDATE or DELETE rows.
CREATE FUNCTION reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only';
END $$;
CREATE TRIGGER events_append_only BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER events_no_truncate BEFORE TRUNCATE ON events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_change();
