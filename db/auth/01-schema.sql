-- Author: Raad
-- Edits:
--
-- Auth database with officials, roles, server-side sessions and login failures
--
-- Requirements:
--     GR03 - roles are scoped, and sessions are held on the server so they can be revoked and time out
--     GR04 - the login_failures table drives the official lockout
--
-- Run:
--     Docker runs this file the first time it creates the database volume
--     .venv/bin/python scripts/demo_officials.py
--     That script sets up the demo officials eo.sa, co.sa, rd.sa and aud.demo
--
-- Output:
--     The official_roles table gets one row per role
--     For example, rd.sa is a recount delegate for the 2026 Senate election in SA, and aud.demo is
--     an auditor with no election or state scope
--
-- Officials, their roles, server-side sessions and login-failure tracking.
-- Officials are created with: docker compose exec auth python -m app.manage create-official
CREATE TABLE officials (
    username       TEXT PRIMARY KEY,                    -- the operatorId
    password_hash  TEXT NOT NULL,                       -- argon2id
    totp_secret    TEXT NOT NULL,                       -- TODO: encrypt at rest
    last_otp       TEXT,                                -- blocks replay of a code inside its window
    active         BOOLEAN NOT NULL DEFAULT TRUE
);

-- An official may hold several roles administratively; a session activates exactly one
-- (Milestone 2 Section 2.3). Every role except AUDITOR is scoped to one election and state.
CREATE TABLE official_roles (
    username       TEXT NOT NULL REFERENCES officials(username),
    role           TEXT NOT NULL CHECK (role IN ('ELECTION_OFFICIAL','COUNT_OPERATOR','RECOUNT_DELEGATE','AUDITOR')),
    scope_election TEXT,
    scope_state    TEXT CHECK (scope_state IN ('NSW','VIC','QLD','WA','SA','TAS','ACT','NT')),
    PRIMARY KEY (username, role),
    CHECK (role = 'AUDITOR' OR (scope_election IS NOT NULL AND scope_state IS NOT NULL))
);

-- Server-side sessions (Table 11): 30 min idle, 8 h absolute, revocable immediately.
-- The current step-up assertion is tracked here so it can be used exactly once.
CREATE TABLE sessions (
    session_id     TEXT PRIMARY KEY,
    username       TEXT NOT NULL REFERENCES officials(username),
    role           TEXT NOT NULL,
    csrf_token     TEXT NOT NULL,                       -- synchroniser token
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    revoked_reason TEXT,
    step_up_id     TEXT,
    step_up_used   BOOLEAN NOT NULL DEFAULT FALSE
);

-- Officials only. Electors are never locked out (Section 4.4); Nginx rate-limits instead.
CREATE TABLE login_failures (
    subject      TEXT PRIMARY KEY,                      -- 'official:<name>'
    failures     INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ
);
