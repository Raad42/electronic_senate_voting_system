-- Electoral Roll database. Only auth_svc can reach it (Table 10).
-- Records THAT an enrolment voted, never how. Nothing here refers to a nonce or ballot.
-- Runs once, as the superuser, on the container's first start. See db/README.md.

\set ON_ERROR_STOP on
\getenv auth_svc_password ROLL_AUTH_SVC_PASSWORD

CREATE ROLE roll_owner NOLOGIN;
CREATE ROLE auth_svc LOGIN PASSWORD :'auth_svc_password';

REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO auth_svc;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA roll AUTHORIZATION roll_owner;
GRANT USAGE ON SCHEMA roll TO auth_svc;

SET ROLE roll_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE roll.enrolment (
    enrolment_id  text PRIMARY KEY CHECK (enrolment_id ~ '^[A-Z0-9-]{6,32}$'),
    state         text NOT NULL CHECK (state IN ('ACT','NSW','NT','QLD','SA','TAS','VIC','WA')),
    password_hash text NOT NULL CHECK (password_hash LIKE '$argon2id$%')
);

-- Times are rounded to the minute so they cannot be matched against other records (Section 2.7).
CREATE TABLE roll.election_participation (
    election_id              text NOT NULL CHECK (election_id ~ '^[A-Z0-9-]{4,32}$'),
    enrolment_id             text NOT NULL REFERENCES roll.enrolment,
    authorisation_expires_at timestamptz CHECK (EXTRACT(SECOND FROM authorisation_expires_at) = 0),
    voted_at                 timestamptz CHECK (EXTRACT(SECOND FROM voted_at) = 0),
    PRIMARY KEY (election_id, enrolment_id)
);

-- Atomically applies the checks in Section 2.2 step 2 and records a live authorisation.
-- The caller issues the token only on 'ISSUED'. The nonce never reaches this database.
-- Returns ISSUED, NOT_ELIGIBLE, ALREADY_VOTED or AUTHORISATION_OUTSTANDING.
CREATE FUNCTION roll.issue_authorisation(p_enrolment_id text, p_election_id text, p_state text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, roll, pg_temp
AS $$
DECLARE
    v_state text;
    v_voted timestamptz;
    -- Tokens last 15 minutes. Rounding up means this never ends before the token does.
    v_expires timestamptz := date_trunc('minute', clock_timestamp()) + interval '16 minutes';
BEGIN
    SELECT state INTO v_state FROM enrolment WHERE enrolment_id = p_enrolment_id;
    IF NOT FOUND OR v_state <> p_state THEN
        RETURN 'NOT_ELIGIBLE';
    END IF;

    INSERT INTO election_participation AS p (election_id, enrolment_id, authorisation_expires_at)
    VALUES (p_election_id, p_enrolment_id, v_expires)
    ON CONFLICT (election_id, enrolment_id) DO UPDATE
        SET authorisation_expires_at = EXCLUDED.authorisation_expires_at
        WHERE p.voted_at IS NULL
          AND (p.authorisation_expires_at IS NULL OR p.authorisation_expires_at <= clock_timestamp());
    IF FOUND THEN
        RETURN 'ISSUED';
    END IF;

    SELECT voted_at INTO v_voted FROM election_participation
    WHERE election_id = p_election_id AND enrolment_id = p_enrolment_id;
    RETURN CASE WHEN v_voted IS NOT NULL THEN 'ALREADY_VOTED' ELSE 'AUTHORISATION_OUTSTANDING' END;
END;
$$;

-- Section 2.2 step 5. Write-once: repeating it keeps the original time.
CREATE FUNCTION roll.mark_voted(p_enrolment_id text, p_election_id text)
RETURNS void
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, roll, pg_temp
AS $$
    INSERT INTO election_participation AS p (election_id, enrolment_id, voted_at)
    VALUES (p_election_id, p_enrolment_id, date_trunc('minute', clock_timestamp()))
    ON CONFLICT (election_id, enrolment_id) DO UPDATE
        SET voted_at = COALESCE(p.voted_at, EXCLUDED.voted_at);
$$;

GRANT SELECT ON roll.enrolment, roll.election_participation TO auth_svc;
GRANT EXECUTE ON FUNCTION roll.issue_authorisation(text, text, text),
                          roll.mark_voted(text, text) TO auth_svc;

RESET ROLE;
