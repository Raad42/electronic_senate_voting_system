#!/bin/sh
# INSERT and SELECT only: the audit service itself cannot rewrite history.
set -e
psql -v ON_ERROR_STOP=1 -v pw="$APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE app LOGIN PASSWORD :'pw';
GRANT SELECT, INSERT ON events TO app;
SQL
