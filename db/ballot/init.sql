-- Ballot database. Three schemas with separate grants:
--   election  candidates, party groups and the election phase
--   ballot    the Ballot Store and Nonce Store (same database so one transaction covers both)
--   counting  the preserved snapshot, counts, results and exclusions
-- Nothing here identifies an elector. Runs once, as the superuser. See db/README.md.

\set ON_ERROR_STOP on
\getenv ballot_svc_password BALLOT_BALLOT_SVC_PASSWORD
\getenv count_svc_password BALLOT_COUNT_SVC_PASSWORD

CREATE ROLE ballot_owner NOLOGIN;
CREATE ROLE ballot_svc LOGIN PASSWORD :'ballot_svc_password';
CREATE ROLE count_svc LOGIN PASSWORD :'count_svc_password';

REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO ballot_svc, count_svc;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA election AUTHORIZATION ballot_owner;
CREATE SCHEMA ballot   AUTHORIZATION ballot_owner;
CREATE SCHEMA counting AUTHORIZATION ballot_owner;

GRANT USAGE ON SCHEMA election TO ballot_svc, count_svc;
GRANT USAGE ON SCHEMA ballot   TO ballot_svc;   -- count_svc has no access to raw ballots.
GRANT USAGE ON SCHEMA counting TO count_svc;

SET ROLE ballot_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE FUNCTION election.forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '%.% is append-only', TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = 'EV100';
END;
$$;

-- ---------------------------------------------------------------- election

CREATE TYPE election.phase AS ENUM (
    'NOMINATIONS', 'NOMINATIONS_COMMITTED', 'ORDER_FIXED',
    'POLLING', 'POLL_CLOSED', 'COUNTED', 'RECOUNT_OPEN'
);

-- One row is one state's Senate contest, so an election_id implies a state.
CREATE TABLE election.election (
    election_id text PRIMARY KEY CHECK (election_id ~ '^[A-Z0-9-]{4,32}$'),
    state       text NOT NULL CHECK (state IN ('ACT','NSW','NT','QLD','SA','TAS','VIC','WA')),
    phase       election.phase NOT NULL DEFAULT 'NOMINATIONS'
);

CREATE TABLE election.party_group (
    election_id     text NOT NULL REFERENCES election.election,
    group_id        text NOT NULL,
    name            text NOT NULL,
    ballot_position integer CHECK (ballot_position > 0),
    PRIMARY KEY (election_id, group_id),
    UNIQUE (election_id, ballot_position)
);

CREATE TABLE election.candidate (
    candidate_id      uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    election_id       text NOT NULL REFERENCES election.election,
    group_id          text,                 -- NULL for an ungrouped candidate.
    name              text NOT NULL,
    position_in_group integer CHECK (position_in_group > 0),
    UNIQUE (election_id, candidate_id),
    UNIQUE (election_id, group_id, position_in_group),
    FOREIGN KEY (election_id, group_id) REFERENCES election.party_group
);

-- Phases only move forward, except that a count can reopen for a recount.
CREATE FUNCTION election.guard_phase() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.phase = OLD.phase THEN
        RETURN NEW;
    END IF;
    IF NOT (OLD.phase::text || '>' || NEW.phase::text) = ANY (ARRAY[
        'NOMINATIONS>NOMINATIONS_COMMITTED',
        'NOMINATIONS_COMMITTED>ORDER_FIXED',
        'ORDER_FIXED>POLLING',
        'POLLING>POLL_CLOSED',
        'POLL_CLOSED>COUNTED',
        'COUNTED>RECOUNT_OPEN',
        'RECOUNT_OPEN>COUNTED'
    ]) THEN
        RAISE EXCEPTION 'illegal phase change % to %', OLD.phase, NEW.phase USING ERRCODE = 'EV101';
    END IF;
    IF NEW.phase = 'ORDER_FIXED' AND EXISTS (
        SELECT 1 FROM election.party_group
        WHERE election_id = NEW.election_id AND ballot_position IS NULL
    ) THEN
        RAISE EXCEPTION 'every party group needs a ballot position' USING ERRCODE = 'EV101';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER guard_phase BEFORE UPDATE ON election.election
    FOR EACH ROW EXECUTE FUNCTION election.guard_phase();

-- COMMIT_NOMINATIONS and FIX_PARTY_ORDER cannot be undone (Table 7).
CREATE FUNCTION election.guard_candidate() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_election text := CASE TG_OP WHEN 'DELETE' THEN OLD.election_id ELSE NEW.election_id END;
BEGIN
    IF (SELECT phase FROM election.election WHERE election_id = v_election) <> 'NOMINATIONS' THEN
        RAISE EXCEPTION 'nominations are committed' USING ERRCODE = 'EV102';
    END IF;
    RETURN CASE TG_OP WHEN 'DELETE' THEN OLD ELSE NEW END;
END;
$$;
CREATE TRIGGER guard_candidate BEFORE INSERT OR UPDATE OR DELETE ON election.candidate
    FOR EACH ROW EXECUTE FUNCTION election.guard_candidate();

CREATE FUNCTION election.guard_party_group() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_election text := CASE TG_OP WHEN 'DELETE' THEN OLD.election_id ELSE NEW.election_id END;
    v_phase election.phase;
BEGIN
    SELECT phase INTO v_phase FROM election.election WHERE election_id = v_election;
    IF v_phase = 'NOMINATIONS' THEN
        NULL;  -- Anything goes until nominations are committed.
    ELSIF v_phase = 'NOMINATIONS_COMMITTED' AND TG_OP = 'UPDATE'
          AND NEW.election_id = OLD.election_id AND NEW.group_id = OLD.group_id AND NEW.name = OLD.name THEN
        NULL;  -- Only the ballot position can still change.
    ELSE
        RAISE EXCEPTION 'party groups are locked in phase %', v_phase USING ERRCODE = 'EV102';
    END IF;
    RETURN CASE TG_OP WHEN 'DELETE' THEN OLD ELSE NEW END;
END;
$$;
CREATE TRIGGER guard_party_group BEFORE INSERT OR UPDATE OR DELETE ON election.party_group
    FOR EACH ROW EXECUTE FUNCTION election.guard_party_group();

-- ---------------------------------------------------------------- ballot store and nonce store

-- Deliberately no elector column, authorisation nonce, timestamp or sequence (Section 4.2).
CREATE TABLE ballot.ballot (
    ballot_ref  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    election_id text NOT NULL REFERENCES election.election,
    key_id      text NOT NULL,
    iv          bytea NOT NULL CHECK (octet_length(iv) = 12),
    ciphertext  bytea NOT NULL CHECK (octet_length(ciphertext) > 0)
);

-- Opaque values linked to nobody and to no ballot (Section 2.2).
CREATE TABLE ballot.used_nonce (
    nonce bytea PRIMARY KEY CHECK (octet_length(nonce) = 16)
);

CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON ballot.ballot
    FOR EACH ROW EXECUTE FUNCTION election.forbid_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON ballot.ballot
    FOR EACH STATEMENT EXECUTE FUNCTION election.forbid_mutation();
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON ballot.used_nonce
    FOR EACH ROW EXECUTE FUNCTION election.forbid_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON ballot.used_nonce
    FOR EACH STATEMENT EXECUTE FUNCTION election.forbid_mutation();

-- The only way to write a ballot: consumes the nonce and stores the ballot in one transaction.
-- Returns the new ballot_ref, or NULL if the nonce was already used (a replay).
-- Raises EV200 if the election is not polling or the token's state does not match it.
CREATE FUNCTION ballot.cast_ballot(p_nonce bytea, p_election_id text, p_state text,
                                   p_key_id text, p_iv bytea, p_ciphertext bytea)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, ballot, pg_temp
AS $$
DECLARE
    v_state election.election.state%TYPE;
    v_phase election.phase;
    v_ref uuid;
BEGIN
    -- The shared lock makes closing the poll wait for us, so no accepted ballot misses the snapshot.
    SELECT state, phase INTO v_state, v_phase
    FROM election.election WHERE election_id = p_election_id FOR SHARE;

    IF NOT FOUND OR v_state <> p_state OR v_phase <> 'POLLING' THEN
        RAISE EXCEPTION 'ballot not accepted for this election' USING ERRCODE = 'EV200';
    END IF;

    INSERT INTO used_nonce (nonce) VALUES (p_nonce) ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    INSERT INTO ballot (election_id, key_id, iv, ciphertext)
    VALUES (p_election_id, p_key_id, p_iv, p_ciphertext)
    RETURNING ballot_ref INTO v_ref;
    RETURN v_ref;
END;
$$;

-- "Read by reference" (Table 10). No login can list ballots through this.
CREATE FUNCTION ballot.get_ballot(p_ballot_ref uuid)
RETURNS TABLE (election_id text, key_id text, iv bytea, ciphertext bytea)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, ballot, pg_temp
AS $$
    SELECT b.election_id, b.key_id, b.iv, b.ciphertext FROM ballot b WHERE b.ballot_ref = p_ballot_ref;
$$;

-- ---------------------------------------------------------------- counting

CREATE TYPE counting.count_kind AS ENUM ('INITIAL', 'RECOUNT');
CREATE TYPE counting.count_status AS ENUM ('RUNNING', 'COMPLETE', 'FAILED');

-- One preserved snapshot per election, used by the count and every recount.
CREATE TABLE counting.ballot_snapshot (
    snapshot_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    election_id text NOT NULL UNIQUE REFERENCES election.election,
    ballot_count bigint NOT NULL CHECK (ballot_count >= 0),
    set_digest  bytea NOT NULL CHECK (octet_length(set_digest) = 32),
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (snapshot_id, election_id)
);

-- A shuffled copy with new random ids: it cannot be joined to ballot.ballot or ordered by casting time.
CREATE TABLE counting.snapshot_ballot (
    snapshot_id uuid NOT NULL REFERENCES counting.ballot_snapshot,
    entry_id    uuid NOT NULL DEFAULT gen_random_uuid(),
    key_id      text NOT NULL,
    iv          bytea NOT NULL,
    ciphertext  bytea NOT NULL,
    PRIMARY KEY (snapshot_id, entry_id)
);

CREATE TABLE counting.count_run (
    count_id        uuid PRIMARY KEY,   -- Allocated up front, since officials are scoped to it (Table 6).
    election_id     text NOT NULL,
    snapshot_id     uuid NOT NULL,
    kind            counting.count_kind NOT NULL,
    parent_count_id uuid REFERENCES counting.count_run,
    config_digest   bytea NOT NULL CHECK (octet_length(config_digest) = 32),
    started_by      text NOT NULL,
    status          counting.count_status NOT NULL DEFAULT 'RUNNING',
    started_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at     timestamptz,
    UNIQUE (count_id, election_id),
    FOREIGN KEY (snapshot_id, election_id) REFERENCES counting.ballot_snapshot (snapshot_id, election_id),
    CHECK ((kind = 'RECOUNT') = (parent_count_id IS NOT NULL))
);

CREATE TABLE counting.count_result (
    count_id      uuid PRIMARY KEY REFERENCES counting.count_run,
    result        jsonb NOT NULL,
    result_digest bytea NOT NULL CHECK (octet_length(result_digest) = 32)
);

CREATE TABLE counting.exclusion_ground (
    ground      text PRIMARY KEY,
    description text NOT NULL
);
-- Placeholders: see "Decisions still open" in db/README.md.
INSERT INTO counting.exclusion_ground VALUES
    ('CONSTITUTION_S44', 'Disqualified under s. 44 of the Constitution, as found by the court'),
    ('COURT_ORDER_OTHER', 'Other ground stated in the court order');

CREATE TABLE counting.exclusion (
    exclusion_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    count_id        uuid NOT NULL,
    election_id     text NOT NULL,
    candidate_id    uuid NOT NULL,
    ground          text NOT NULL REFERENCES counting.exclusion_ground,
    court_order_ref text NOT NULL CHECK (btrim(court_order_ref) <> ''),
    evidence_sha256 bytea CHECK (octet_length(evidence_sha256) = 32),
    entered_by      text NOT NULL,
    entered_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (count_id, candidate_id),
    -- Composite keys: the count and the candidate must both belong to this election (GR03).
    FOREIGN KEY (count_id, election_id) REFERENCES counting.count_run (count_id, election_id),
    FOREIGN KEY (election_id, candidate_id) REFERENCES election.candidate (election_id, candidate_id)
);

CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON counting.ballot_snapshot
    FOR EACH ROW EXECUTE FUNCTION election.forbid_mutation();
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON counting.snapshot_ballot
    FOR EACH ROW EXECUTE FUNCTION election.forbid_mutation();
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON counting.count_result
    FOR EACH ROW EXECUTE FUNCTION election.forbid_mutation();
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON counting.exclusion
    FOR EACH ROW EXECUTE FUNCTION election.forbid_mutation();

CREATE FUNCTION counting.guard_count_run() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (SELECT phase FROM election.election WHERE election_id = NEW.election_id)
           NOT IN ('POLL_CLOSED', 'RECOUNT_OPEN') THEN
            RAISE EXCEPTION 'a count cannot start in this phase' USING ERRCODE = 'EV201';
        END IF;
    ELSIF OLD.status <> 'RUNNING' THEN
        RAISE EXCEPTION 'a finished count cannot change' USING ERRCODE = 'EV201';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER guard_count_run BEFORE INSERT OR UPDATE ON counting.count_run
    FOR EACH ROW EXECUTE FUNCTION counting.guard_count_run();

CREATE FUNCTION counting.guard_exclusion() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT phase FROM election.election WHERE election_id = NEW.election_id) <> 'RECOUNT_OPEN' THEN
        RAISE EXCEPTION 'no recount is open for this election' USING ERRCODE = 'EV202';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER guard_exclusion BEFORE INSERT ON counting.exclusion
    FOR EACH ROW EXECUTE FUNCTION counting.guard_exclusion();

-- Makes the preserved, shuffled copy once the poll has closed.
-- SECURITY DEFINER because count_svc cannot read ballot.ballot itself.
CREATE FUNCTION counting.create_snapshot(p_election_id text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_phase election.phase;
    v_id uuid := gen_random_uuid();
    v_count bigint;
    v_digest bytea;
BEGIN
    SELECT phase INTO v_phase FROM election.election WHERE election_id = p_election_id FOR SHARE;
    IF NOT FOUND OR v_phase <> 'POLL_CLOSED' THEN
        RAISE EXCEPTION 'a snapshot needs a closed poll' USING ERRCODE = 'EV203';
    END IF;

    -- A digest over the sorted ballots, so it does not depend on row order. Auditors can
    -- reconcile the snapshot against this, and the audit log records it (Milestone 1, Table 5).
    SELECT count(*), sha256(COALESCE(string_agg(h, ''::bytea ORDER BY h), ''::bytea))
    INTO v_count, v_digest
    FROM (SELECT sha256(iv || ciphertext) AS h FROM ballot.ballot WHERE election_id = p_election_id) s;

    INSERT INTO counting.ballot_snapshot (snapshot_id, election_id, ballot_count, set_digest)
    VALUES (v_id, p_election_id, v_count, v_digest);

    INSERT INTO counting.snapshot_ballot (snapshot_id, key_id, iv, ciphertext)
    SELECT v_id, key_id, iv, ciphertext FROM ballot.ballot
    WHERE election_id = p_election_id
    ORDER BY gen_random_uuid();

    RETURN v_id;
END;
$$;

-- ---------------------------------------------------------------- grants

GRANT SELECT ON ALL TABLES IN SCHEMA election TO ballot_svc, count_svc;
GRANT EXECUTE ON FUNCTION ballot.cast_ballot(bytea, text, text, text, bytea, bytea),
                          ballot.get_ballot(uuid) TO ballot_svc;

-- count_svc holds election setup for now: see "Decisions still open" in db/README.md.
GRANT INSERT (election_id, state), UPDATE (phase) ON election.election TO count_svc;
GRANT INSERT, UPDATE, DELETE ON election.party_group, election.candidate TO count_svc;

GRANT SELECT ON ALL TABLES IN SCHEMA counting TO count_svc;
GRANT INSERT (count_id, election_id, snapshot_id, kind, parent_count_id, config_digest, started_by)
    ON counting.count_run TO count_svc;
GRANT UPDATE (status, finished_at) ON counting.count_run TO count_svc;
GRANT INSERT ON counting.count_result TO count_svc;
GRANT INSERT (count_id, election_id, candidate_id, ground, court_order_ref, evidence_sha256, entered_by)
    ON counting.exclusion TO count_svc;
GRANT EXECUTE ON FUNCTION counting.create_snapshot(text) TO count_svc;

RESET ROLE;
