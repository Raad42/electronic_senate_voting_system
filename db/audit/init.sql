-- Audit database: append-only, hash-chained records (GR05).
-- One table and one chain per family, so the columns themselves stop an elector being recorded
-- beside a nonce or a ballot, and no chain records order across families (Section 2.7).
-- Runs once, as the superuser, on the container's first start. See db/README.md.

\set ON_ERROR_STOP on
\getenv audit_svc_password AUDIT_AUDIT_SVC_PASSWORD

CREATE ROLE audit_owner NOLOGIN;
CREATE ROLE audit_svc LOGIN PASSWORD :'audit_svc_password';

REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO audit_svc;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA audit AUTHORIZATION audit_owner;
GRANT USAGE ON SCHEMA audit TO audit_svc;

SET ROLE audit_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE audit.chain_head (
    family    text PRIMARY KEY,
    last_seq  bigint NOT NULL DEFAULT 0,
    last_hash bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
);

-- seq, occurred_minute, prev_hash and event_hash are always set by the chain_append trigger.
-- occurred_minute is rounded because records with no shared field can still be matched by
-- a precise clock (Section 2.7).

-- Who was authorised. Has no nonce or ballot column.
CREATE TABLE audit.authorisation_record (
    seq             bigint PRIMARY KEY,
    occurred_minute timestamptz NOT NULL CHECK (EXTRACT(SECOND FROM occurred_minute) = 0),
    event_type      text NOT NULL CHECK (event_type IN
                        ('AUTHORISATION_ISSUED', 'AUTHORISATION_REFUSED_ALREADY_VOTED')),
    enrolment_id    text NOT NULL,
    election_id     text NOT NULL,
    prev_hash       bytea NOT NULL,
    event_hash      bytea NOT NULL
);

-- What happened to a token. Has no enrolment or ballot column. The nonce can be NULL because a
-- token with a bad signature may not contain a readable one.
CREATE TABLE audit.nonce_record (
    seq             bigint PRIMARY KEY,
    occurred_minute timestamptz NOT NULL CHECK (EXTRACT(SECOND FROM occurred_minute) = 0),
    event_type      text NOT NULL CHECK (event_type IN
                        ('AUTHORISATION_CONSUMED', 'AUTHORISATION_EXPIRED',
                         'AUTHORISATION_REPLAY_REFUSED', 'SIGNATURE_INVALID')),
    nonce           bytea CHECK (octet_length(nonce) = 16),
    election_id     text,
    prev_hash       bytea NOT NULL,
    event_hash      bytea NOT NULL
);

CREATE TABLE audit.operator_record (
    seq              bigint PRIMARY KEY,
    occurred_minute  timestamptz NOT NULL CHECK (EXTRACT(SECOND FROM occurred_minute) = 0),
    event_type       text NOT NULL CHECK (event_type IN
                        ('OPERATOR_AUTHENTICATED', 'OPERATOR_MFA_FAILED', 'STEP_UP_ISSUED',
                         'STEP_UP_SATISFIED', 'STEP_UP_TIMEOUT', 'STEP_UP_MISMATCH',
                         'SESSION_INVALIDATED', 'POLICY_ALLOWED', 'POLICY_DENIED')),
    operator_id      text NOT NULL,
    action           text,
    attempted_action text,    -- For a mismatch, where both actions are recorded (Section 2.3).
    resource         text,
    reason           text,
    prev_hash        bytea NOT NULL,
    event_hash       bytea NOT NULL
);

CREATE TABLE audit.service_record (
    seq                     bigint PRIMARY KEY,
    occurred_minute         timestamptz NOT NULL CHECK (EXTRACT(SECOND FROM occurred_minute) = 0),
    event_type              text NOT NULL CHECK (event_type IN
                                ('SERVICE_AUTHENTICATED', 'SERVICE_CERT_REFUSED')),
    service_id              text,     -- NULL when the certificate is not on the allowlist.
    certificate_fingerprint text NOT NULL CHECK (certificate_fingerprint ~ '^[0-9a-f]{64}$'),
    prev_hash               bytea NOT NULL,
    event_hash              bytea NOT NULL
);

CREATE TABLE audit.query_record (
    seq             bigint PRIMARY KEY,
    occurred_minute timestamptz NOT NULL CHECK (EXTRACT(SECOND FROM occurred_minute) = 0),
    event_type      text NOT NULL CHECK (event_type = 'QUERY_REFUSED'),
    requester_id    text NOT NULL,
    attempted_query text NOT NULL,
    prev_hash       bytea NOT NULL,
    event_hash      bytea NOT NULL
);

-- Election, count and recount operations, with the fields from Milestone 1, Table 5.
CREATE TABLE audit.count_record (
    seq             bigint PRIMARY KEY,
    occurred_minute timestamptz NOT NULL CHECK (EXTRACT(SECOND FROM occurred_minute) = 0),
    event_type      text NOT NULL CHECK (event_type IN
                        ('NOMINATIONS_COMMITTED', 'PARTY_ORDER_FIXED', 'SNAPSHOT_CREATED',
                         'COUNT_STARTED', 'COUNT_COMPLETED', 'COUNT_FAILED', 'RECOUNT_OPENED',
                         'EXCLUSION_ENTERED', 'EXCLUSION_REFUSED', 'EXCLUSION_APPLIED')),
    actor_id        text NOT NULL,
    election_id     text NOT NULL,
    state           text,
    snapshot_digest bytea,
    config_digest   bytea,
    count_id        uuid,
    candidate_id    uuid,
    detail          text,
    prev_hash       bytea NOT NULL,
    event_hash      bytea NOT NULL
);

INSERT INTO audit.chain_head (family) VALUES
    ('authorisation_record'), ('nonce_record'), ('operator_record'),
    ('service_record'), ('query_record'), ('count_record');

-- The exact text that gets hashed. The family name stops a record being moved to another chain.
CREATE FUNCTION audit.canonical(p_family text, p_row jsonb) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
    SELECT ((p_row - 'prev_hash' - 'event_hash') || jsonb_build_object('family', p_family))::text;
$$;

-- Runs in UTC so the text of a timestamp does not depend on the caller's session settings.
-- SECURITY DEFINER because audit_svc has no write access to chain_head.
CREATE FUNCTION audit.chain_append() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, audit, pg_temp
SET timezone = 'UTC'
AS $$
BEGIN
    -- The row lock orders concurrent appends. A rollback also undoes this, so no gap is left.
    UPDATE chain_head SET last_seq = last_seq + 1 WHERE family = TG_TABLE_NAME
    RETURNING last_seq, last_hash INTO NEW.seq, NEW.prev_hash;

    NEW.occurred_minute := date_trunc('minute', clock_timestamp());
    NEW.event_hash := sha256(NEW.prev_hash || convert_to(canonical(TG_TABLE_NAME, to_jsonb(NEW)), 'UTF8'));

    UPDATE chain_head SET last_hash = NEW.event_hash WHERE family = TG_TABLE_NAME;
    RETURN NEW;
END;
$$;

CREATE FUNCTION audit.forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit.% is append-only', TG_TABLE_NAME USING ERRCODE = 'EV300';
END;
$$;

DO $$
DECLARE
    t text;
BEGIN
    FOR t IN SELECT family FROM audit.chain_head LOOP
        EXECUTE format('CREATE TRIGGER chain_append BEFORE INSERT ON audit.%I
                        FOR EACH ROW EXECUTE FUNCTION audit.chain_append()', t);
        EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON audit.%I
                        FOR EACH ROW EXECUTE FUNCTION audit.forbid_mutation()', t);
        EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON audit.%I
                        FOR EACH STATEMENT EXECUTE FUNCTION audit.forbid_mutation()', t);
        EXECUTE format('GRANT SELECT, INSERT ON audit.%I TO audit_svc', t);
    END LOOP;
END;
$$;

-- What an auditor needs to check a chain outside the database (see db/README.md):
-- event_hash = sha256(prev_hash || utf8(canonical)). The record's fields are in canonical.
CREATE FUNCTION audit.export_chain(p_family text)
RETURNS TABLE (seq bigint, canonical text, prev_hash bytea, event_hash bytea)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, audit, pg_temp
SET timezone = 'UTC'
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM chain_head WHERE family = p_family) THEN
        RAISE EXCEPTION 'unknown audit family' USING ERRCODE = 'EV301';
    END IF;
    RETURN QUERY EXECUTE format(
        'SELECT t.seq, audit.canonical(%L, to_jsonb(t)), t.prev_hash, t.event_hash
         FROM audit.%I t ORDER BY t.seq', p_family, p_family);
END;
$$;

-- Recomputes a whole chain and compares its end with chain_head, which catches a deleted tail.
-- ok is false at the first break, and first_bad_seq says where.
CREATE FUNCTION audit.verify_chain(p_family text)
RETURNS TABLE (ok boolean, records_checked bigint, first_bad_seq bigint, reason text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, audit, pg_temp
SET timezone = 'UTC'
AS $$
DECLARE
    r record;
    v_expected_seq bigint := 1;
    v_prev bytea := decode(repeat('00', 32), 'hex');
    v_head chain_head%ROWTYPE;
BEGIN
    FOR r IN SELECT * FROM export_chain(p_family) LOOP
        IF r.seq <> v_expected_seq THEN
            RETURN QUERY SELECT false, v_expected_seq - 1, v_expected_seq, 'record missing';
            RETURN;
        ELSIF r.prev_hash <> v_prev THEN
            RETURN QUERY SELECT false, v_expected_seq - 1, r.seq, 'previous hash does not match';
            RETURN;
        ELSIF r.event_hash <> sha256(r.prev_hash || convert_to(r.canonical, 'UTF8')) THEN
            RETURN QUERY SELECT false, v_expected_seq - 1, r.seq, 'record altered';
            RETURN;
        END IF;
        v_prev := r.event_hash;
        v_expected_seq := v_expected_seq + 1;
    END LOOP;

    SELECT * INTO v_head FROM chain_head WHERE family = p_family;
    IF v_head.last_seq <> v_expected_seq - 1 OR v_head.last_hash <> v_prev THEN
        RETURN QUERY SELECT false, v_expected_seq - 1, v_expected_seq, 'chain does not reach its recorded head';
        RETURN;
    END IF;
    RETURN QUERY SELECT true, v_expected_seq - 1, NULL::bigint, NULL::text;
END;
$$;

GRANT EXECUTE ON FUNCTION audit.verify_chain(text), audit.export_chain(text) TO audit_svc;

RESET ROLE;
