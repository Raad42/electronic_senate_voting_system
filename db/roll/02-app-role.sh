#!/bin/sh
# Auth reads electors and records issuances; it cannot change or delete either.
set -e
psql -v ON_ERROR_STOP=1 -v pw="$APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE app LOGIN PASSWORD :'pw';
GRANT SELECT ON electors TO app;
GRANT SELECT, INSERT ON issuances TO app;
SQL
