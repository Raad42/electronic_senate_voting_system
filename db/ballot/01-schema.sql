-- Author: Raad
-- Edits:
--
-- Ballot database with contests, candidates, used nonces and sealed ballots
--
-- Requirements:
--     GR01 - the used_nonces primary key means one authorisation can only be spent once
--     GR02 - the ballots table holds a random ID and ciphertext only, with no voter, nonce or time
--
-- Run:
--     Docker runs this file the first time it creates the database volume
--     docker compose exec ballot_db psql -U owner -d ballot -c "SELECT * FROM ballots LIMIT 2;"
--
-- Output:
--     Each row just has a random ballot ID, senate-2026, SA and a long ciphertext string
--     There's no voter ID anywhere in the row
--
CREATE TABLE elections (
    id     TEXT PRIMARY KEY,
    name   TEXT NOT NULL
);

-- Each state's contest moves one way through its lifecycle (Milestone 2 Tables 6 and 7):
-- nominations -> nominations_committed -> order_fixed -> open -> closed -> counted.
-- 'counted' is the open recount phase: exclusions are only accepted once a result exists.
CREATE TABLE contests (
    election_id TEXT NOT NULL REFERENCES elections(id),
    state       TEXT NOT NULL CHECK (state IN ('NSW','VIC','QLD','WA','SA','TAS','ACT','NT')),
    seats       INTEGER NOT NULL CHECK (seats > 0),
    status      TEXT NOT NULL DEFAULT 'nominations'
                CHECK (status IN ('nominations','nominations_committed','order_fixed','open','closed','counted')),
    PRIMARY KEY (election_id, state)
);

CREATE TABLE groups (
    election_id TEXT NOT NULL,
    state       TEXT NOT NULL,
    code        TEXT NOT NULL,
    name        TEXT NOT NULL,
    position    INTEGER NOT NULL,
    PRIMARY KEY (election_id, state, code),
    FOREIGN KEY (election_id, state) REFERENCES contests(election_id, state)
);

CREATE TABLE candidates (
    election_id  TEXT NOT NULL,
    state        TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    name         TEXT NOT NULL,
    group_code   TEXT,                                  -- NULL = ungrouped
    position     INTEGER NOT NULL,
    PRIMARY KEY (election_id, state, candidate_id),
    FOREIGN KEY (election_id, state) REFERENCES contests(election_id, state),
    FOREIGN KEY (election_id, state, group_code) REFERENCES groups(election_id, state, code)
);

-- A nonce row is the "used" mark of a voting authorisation. Primary key = single use (GR01).
CREATE TABLE used_nonces (
    nonce       TEXT PRIMARY KEY,
    election_id TEXT NOT NULL REFERENCES elections(id)
);

-- Sealed ballots: no elector id, no nonce, no timestamp, random id (GR02).
CREATE TABLE ballots (
    ballot_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    election_id TEXT NOT NULL,
    state       TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,
    FOREIGN KEY (election_id, state) REFERENCES contests(election_id, state)
);

-- Sample election for development. Nominations are loaded; an election official commits them.
INSERT INTO elections (id, name) VALUES ('SEN2028', '2028 Senate Election');
INSERT INTO contests (election_id, state, seats) VALUES ('SEN2028', 'NSW', 2), ('SEN2028', 'VIC', 2);
INSERT INTO groups VALUES
    ('SEN2028','NSW','A','Harbour Party',1),
    ('SEN2028','NSW','B','Bush Alliance',2),
    ('SEN2028','NSW','C','Coastal Greens',3),
    ('SEN2028','VIC','A','Yarra Union',1),
    ('SEN2028','VIC','B','Bay Coalition',2);
INSERT INTO candidates VALUES
    ('SEN2028','NSW','NSW-A1','Avery Harbour','A',1),
    ('SEN2028','NSW','NSW-A2','Blake Harbour','A',2),
    ('SEN2028','NSW','NSW-B1','Casey Bush','B',3),
    ('SEN2028','NSW','NSW-B2','Drew Bush','B',4),
    ('SEN2028','NSW','NSW-C1','Emery Coast','C',5),
    ('SEN2028','NSW','NSW-C2','Finley Coast','C',6),
    ('SEN2028','NSW','NSW-U1','Gray Independent',NULL,7),
    ('SEN2028','VIC','VIC-A1','Harper Yarra','A',1),
    ('SEN2028','VIC','VIC-A2','Indy Yarra','A',2),
    ('SEN2028','VIC','VIC-B1','Jules Bay','B',3),
    ('SEN2028','VIC','VIC-B2','Kai Bay','B',4),
    ('SEN2028','VIC','VIC-U1','Lane Independent',NULL,5),
    ('SEN2028','VIC','VIC-U2','Morgan Independent',NULL,6);

-- The election the frontend uses (frontend/src/pages/BallotPage.tsx: senate-2026, SA).
-- Party order is already fixed and voting is open, so the voter flow works straight away.
-- CAND-052 is a Victorian candidate: an SA recount delegate cannot exclude them.
INSERT INTO elections (id, name) VALUES ('senate-2026', '2026 Senate Election');
INSERT INTO contests (election_id, state, seats, status) VALUES
    ('senate-2026', 'SA', 2, 'open'),
    ('senate-2026', 'VIC', 2, 'open');
INSERT INTO groups VALUES
    ('senate-2026','SA','A','Party A',1),
    ('senate-2026','SA','B','Party B',2),
    ('senate-2026','SA','C','Party C',3),
    ('senate-2026','VIC','A','Party A',1),
    ('senate-2026','VIC','B','Party B',2);
INSERT INTO candidates VALUES
    ('senate-2026','SA','CAND-041','Candidate 041','A',1),
    ('senate-2026','SA','CAND-042','Candidate 042','A',2),
    ('senate-2026','SA','CAND-043','Candidate 043','B',3),
    ('senate-2026','SA','CAND-044','Candidate 044','B',4),
    ('senate-2026','SA','CAND-063','Candidate 063','C',5),
    ('senate-2026','SA','CAND-064','Candidate 064','C',6),
    ('senate-2026','VIC','CAND-051','Candidate 051','A',1),
    ('senate-2026','VIC','CAND-052','Candidate 052','A',2),
    ('senate-2026','VIC','CAND-053','Candidate 053','B',3),
    ('senate-2026','VIC','CAND-054','Candidate 054','B',4);
