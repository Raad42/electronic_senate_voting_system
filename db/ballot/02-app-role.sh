#!/bin/sh
# Ballots and nonces can be added and read, never changed or deleted. Contest set-up can only
# move the lifecycle status and the ballot-paper order.
set -e
psql -v ON_ERROR_STOP=1 -v pw="$APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE app LOGIN PASSWORD :'pw';
GRANT SELECT ON elections TO app;
GRANT SELECT, UPDATE (status) ON contests TO app;
GRANT SELECT, UPDATE (position) ON groups, candidates TO app;
GRANT SELECT, INSERT ON used_nonces, ballots TO app;
SQL
