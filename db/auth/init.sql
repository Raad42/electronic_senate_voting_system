-- Authentication database: officials, role assignments, sessions and step-up assertions
-- (Section 2.3, Tables 6 to 8 and 11). Elector credentials live in the roll database.
-- Runs once, as the superuser, on the container's first start. See db/README.md.

\set ON_ERROR_STOP on
\getenv auth_svc_password AUTH_AUTH_SVC_PASSWORD

CREATE ROLE auth_owner NOLOGIN;
CREATE ROLE auth_svc LOGIN PASSWORD :'auth_svc_password';

REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO auth_svc;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA auth AUTHORIZATION auth_owner;
GRANT USAGE ON SCHEMA auth TO auth_svc;

SET ROLE auth_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TYPE auth.official_role AS ENUM
    ('ELECTION_OFFICIAL', 'COUNT_OPERATOR', 'RECOUNT_DELEGATE', 'AUDITOR');
CREATE TYPE auth.step_up_action AS ENUM
    ('COMMIT_NOMINATIONS', 'FIX_PARTY_ORDER', 'START_COUNT', 'ENTER_MANUAL_EXCLUSION');

CREATE TABLE auth.official (
    operator_id           text PRIMARY KEY CHECK (operator_id ~ '^AEC-[A-Z]{2,3}-[0-9]{4}$'),
    password_hash         text NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    totp_secret_encrypted bytea NOT NULL,   -- Encrypted by the service, never stored in the clear.
    last_totp_step        bigint,           -- Stops a one-time code being replayed in its window.
    failed_attempts       smallint NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until          timestamptz,
    disabled_at           timestamptz
);

-- Administrative. An official may hold several; a session activates exactly one.
-- Provisioned out of band: auth_svc can read these but cannot grant itself anything.
CREATE TABLE auth.role_assignment (
    assignment_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id   text NOT NULL REFERENCES auth.official,
    role          auth.official_role NOT NULL,
    state         text CHECK (state IN ('ACT','NSW','NT','QLD','SA','TAS','VIC','WA')),
    election_id   text,
    count_id      uuid,
    UNIQUE NULLS NOT DISTINCT (operator_id, role, state, election_id, count_id),
    -- The scope each role is limited to (Table 6).
    CONSTRAINT scope_matches_role CHECK (
        CASE role
            WHEN 'ELECTION_OFFICIAL' THEN state IS NOT NULL AND election_id IS NOT NULL AND count_id IS NULL
            WHEN 'COUNT_OPERATOR'    THEN state IS NOT NULL AND election_id IS NOT NULL AND count_id IS NOT NULL
            WHEN 'RECOUNT_DELEGATE'  THEN state IS NOT NULL AND election_id IS NOT NULL AND count_id IS NOT NULL
            WHEN 'AUDITOR'           THEN count_id IS NULL
        END
    )
);

-- Only hashes of the session and CSRF tokens are stored, so a leaked table cannot be replayed.
-- Role and scope come from assignment_id, which cannot be updated: switching role means a new session.
CREATE TABLE auth.session (
    session_id_hash     bytea PRIMARY KEY CHECK (octet_length(session_id_hash) = 32),
    assignment_id       uuid NOT NULL REFERENCES auth.role_assignment,
    csrf_token_hash     bytea NOT NULL CHECK (octet_length(csrf_token_hash) = 32),
    mfa_satisfied       boolean NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    absolute_expires_at timestamptz NOT NULL DEFAULT now() + interval '8 hours',
    revoked_at          timestamptz,
    revoked_reason      text,
    CHECK (absolute_expires_at <= created_at + interval '8 hours')
);

CREATE TABLE auth.step_up_assertion (
    assertion_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id_hash bytea NOT NULL REFERENCES auth.session,
    action          auth.step_up_action NOT NULL,
    resource        text NOT NULL CHECK (resource <> ''),
    issued_at       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL DEFAULT now() + interval '2 minutes',
    consumed_at     timestamptz,
    CHECK (expires_at <= issued_at + interval '2 minutes')
);

-- Checks a session against Table 11 and refreshes its idle timer.
-- Returns no row if it is revoked, idle for 30 minutes, past 8 hours, or its official is disabled.
CREATE FUNCTION auth.touch_session(p_session_id_hash bytea)
RETURNS TABLE (operator_id text, role auth.official_role, state text, election_id text,
               count_id uuid, mfa_satisfied boolean, csrf_token_hash bytea)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, auth, pg_temp
AS $$
    UPDATE session s
       SET last_seen_at = clock_timestamp()
      FROM role_assignment a
      JOIN official o ON o.operator_id = a.operator_id
     WHERE s.session_id_hash = p_session_id_hash
       AND a.assignment_id = s.assignment_id
       AND s.revoked_at IS NULL
       AND s.last_seen_at > clock_timestamp() - interval '30 minutes'
       AND s.absolute_expires_at > clock_timestamp()
       AND o.disabled_at IS NULL
    RETURNING a.operator_id, a.role, a.state, a.election_id, a.count_id,
              s.mfa_satisfied, s.csrf_token_hash;
$$;

-- Single use, tied to one action and one resource (Section 3.4). Presenting an assertion burns it
-- whatever the outcome, so a mismatch cannot be retried.
-- Returns OK, NOT_FOUND, ALREADY_USED, MISMATCH or EXPIRED.
CREATE FUNCTION auth.consume_step_up(p_assertion_id uuid, p_session_id_hash bytea,
                                     p_action auth.step_up_action, p_resource text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, auth, pg_temp
AS $$
DECLARE
    v step_up_assertion%ROWTYPE;
BEGIN
    SELECT * INTO v FROM step_up_assertion
    WHERE assertion_id = p_assertion_id AND session_id_hash = p_session_id_hash
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN 'NOT_FOUND';
    ELSIF v.consumed_at IS NOT NULL THEN
        RETURN 'ALREADY_USED';
    END IF;

    UPDATE step_up_assertion SET consumed_at = clock_timestamp()
    WHERE assertion_id = p_assertion_id;

    IF v.action <> p_action OR v.resource <> p_resource THEN
        RETURN 'MISMATCH';
    ELSIF v.expires_at <= clock_timestamp() THEN
        RETURN 'EXPIRED';
    END IF;
    RETURN 'OK';
END;
$$;

GRANT SELECT ON auth.official, auth.role_assignment, auth.session, auth.step_up_assertion TO auth_svc;
GRANT UPDATE (failed_attempts, locked_until, last_totp_step) ON auth.official TO auth_svc;
GRANT INSERT (session_id_hash, assignment_id, csrf_token_hash, mfa_satisfied) ON auth.session TO auth_svc;
GRANT UPDATE (revoked_at, revoked_reason) ON auth.session TO auth_svc;
GRANT INSERT (session_id_hash, action, resource) ON auth.step_up_assertion TO auth_svc;
GRANT EXECUTE ON FUNCTION auth.touch_session(bytea),
                          auth.consume_step_up(uuid, bytea, auth.step_up_action, text) TO auth_svc;

RESET ROLE;
