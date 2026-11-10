-- Electoral roll. Only the Auth service can reach this database (separate Docker network).
CREATE TABLE electors (
    elector_id    TEXT PRIMARY KEY,                     -- the AEC-issued voter identifier
    password_hash TEXT NOT NULL,                        -- argon2id (Milestone 2 Table 3)
    family_name   TEXT NOT NULL,
    given_names   TEXT NOT NULL,
    date_of_birth DATE NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('NSW','VIC','QLD','WA','SA','TAS','ACT','NT')),
    division      TEXT NOT NULL,
    enrolled      BOOLEAN NOT NULL DEFAULT TRUE
);

-- Records THAT an elector received a voting authorisation, nothing more: no time, no nonce,
-- so it cannot be joined to the ballot database (GR02).
CREATE TABLE issuances (
    elector_id  TEXT NOT NULL REFERENCES electors(elector_id),
    election_id TEXT NOT NULL,
    PRIMARY KEY (elector_id, election_id)
);

-- Sample electors for development (fictional people). Passwords, for the demo only:
--   NSW-0001 jane-citizen-2028   NSW-0002 alex-nguyen-2028
--   NSW-0003 sam-smith-2028      VIC-0001 riley-brown-2028
INSERT INTO electors (elector_id, password_hash, family_name, given_names, date_of_birth, state, division) VALUES
    ('NSW-0001', '$argon2id$v=19$m=65536,t=3,p=4$4piBQIbz5Mw37M/l6gG0MA$BwtBR0R/aZduhtAgzfDZOa/cJ+1W/CYYewJnLhHo9GA',
     'Citizen', 'Jane',  '1990-04-12', 'NSW', 'Sydney'),
    ('NSW-0002', '$argon2id$v=19$m=65536,t=3,p=4$jlbPY6g1ApCBbh1VPY4W1g$1FeUqfCNC99iSXqDv9ongj6L6lzDtErrLtEO6Zo8AFA',
     'Nguyen',  'Alex',  '1985-09-30', 'NSW', 'Parramatta'),
    ('NSW-0003', '$argon2id$v=19$m=65536,t=3,p=4$J+9Ej98sH3fmK2F7pFPwFg$JFtcqmtLbq+aKwEFbjtyi4Tor1rzCB6bF3YxAuBCYRo',
     'Smith',   'Sam',   '2001-01-15', 'NSW', 'Newcastle'),
    ('VIC-0001', '$argon2id$v=19$m=65536,t=3,p=4$hcjGcouixnaAs+gd5ucMVg$cDltdlkVRtiMqY5oTTi6vlqAGP6t7ByvGMhQcgZttPA',
     'Brown',   'Riley', '1978-06-02', 'VIC', 'Melbourne');

-- Electors for the frontend's election (senate-2026). Passwords, for the demo only:
--   SA-0001 sa-voter-0001   SA-0002 sa-voter-0002   SA-0003 sa-voter-0003
--   SA-0004 sa-voter-0004   SA-0005 sa-voter-0005   VIC-0002 vic-voter-0002
INSERT INTO electors (elector_id, password_hash, family_name, given_names, date_of_birth, state, division) VALUES
    ('SA-0001', '$argon2id$v=19$m=65536,t=3,p=4$DscKhQQOlvYuJ/9LPnhaVA$LYqUSned2Vs0ywI7wSt0kxcA/dngcyLRp5ow7r3kIJs',
     'Citizen', 'Jordan', '1992-03-14', 'SA', 'Adelaide'),
    ('SA-0002', '$argon2id$v=19$m=65536,t=3,p=4$SqtHL0kk1cgEWfWfbMenDQ$6V1M7ioa+mai5DQY6IPCy3IVK4Kf3oe32WbZAiHxDJE',
     'Lee', 'Morgan', '1988-07-21', 'SA', 'Sturt'),
    ('SA-0003', '$argon2id$v=19$m=65536,t=3,p=4$d9D4U04yNfz0JEBTDOvxrg$94Mx+Gcy9dAuTZeM93krOUp30p5irT5T/GBZGhiquxo',
     'Patel', 'Ari', '2000-11-02', 'SA', 'Boothby'),
    ('SA-0004', '$argon2id$v=19$m=65536,t=3,p=4$byukXn9OoHAs0TXwjWvBxQ$Ho8vJBufOircMN0uQpzVZwxNHN/njGR5WO/5oa+QI+0',
     'Okafor', 'Sam', '1975-01-30', 'SA', 'Hindmarsh'),
    ('SA-0005', '$argon2id$v=19$m=65536,t=3,p=4$4x68cO+d4BwJ8rRMfnnn3g$O67fc1CSLSfXu8YHWM3XB8FxF9kUVoVOpXoh7erqtnU',
     'Rossi', 'Taylor', '1996-05-09', 'SA', 'Makin'),
    ('VIC-0002', '$argon2id$v=19$m=65536,t=3,p=4$D5+8arzRdPseoqy5pCSsLg$e4Gx15p2XlyTIpNNSvv3AgGw282AV+0CFzH9u7anxfg',
     'Nguyen', 'Casey', '1983-08-17', 'VIC', 'Higgins');
