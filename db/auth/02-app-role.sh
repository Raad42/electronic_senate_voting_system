#!/bin/sh
set -e
psql -v ON_ERROR_STOP=1 -v pw="$APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE app LOGIN PASSWORD :'pw';
GRANT SELECT, INSERT, UPDATE ON officials TO app;
GRANT SELECT, INSERT ON official_roles TO app;
GRANT SELECT, INSERT, UPDATE ON sessions TO app;
GRANT SELECT, INSERT, UPDATE, DELETE ON login_failures TO app;
SQL
