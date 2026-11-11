#!/usr/bin/env bash
set -euo pipefail

# Builds the live presentation stack and leaves the official MFA codes visible.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
ENV_FILE="$ROOT_DIR/.env"
RESET_ENV=0
RESET_DATA=0

for argument in "$@"; do
  case "$argument" in
    --reset-env) RESET_ENV=1 ;;
    --reset-data) RESET_DATA=1 ;;
    *) echo "Unknown option: $argument" >&2; exit 1 ;;
  esac
done

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Missing $PYTHON_BIN. Create the project virtual environment first." >&2
  exit 1
fi

required_vars=(
  FRONTEND_DIST
  ROLL_DB_OWNER_PASSWORD ROLL_DB_APP_PASSWORD
  AUTH_DB_OWNER_PASSWORD AUTH_DB_APP_PASSWORD
  BALLOT_DB_OWNER_PASSWORD BALLOT_DB_APP_PASSWORD
  AUDIT_DB_OWNER_PASSWORD AUDIT_DB_APP_PASSWORD
)

env_is_ready() {
  local variable
  for variable in "${required_vars[@]}"; do
    grep -Eq "^${variable}=[^[:space:]]+" "$ENV_FILE" || return 1
  done
  ! grep -Eq '=(change-me|)$' "$ENV_FILE"
}

if [[ ! -f "$ENV_FILE" ]] || ! env_is_ready; then
  if [[ -f "$ENV_FILE" && "$RESET_ENV" -ne 1 ]]; then
    echo "Existing .env is missing the current presentation variables." >&2
    echo "Re-run with --reset-env to back it up and generate fresh demo values." >&2
    exit 1
  fi

  if [[ -f "$ENV_FILE" ]]; then
    backup="$ROOT_DIR/.env.backup.$(date +%Y%m%d-%H%M%S)"
    mv "$ENV_FILE" "$backup"
    echo "Backed up the previous .env to $backup"
  fi

  "$PYTHON_BIN" - "$ROOT_DIR/.env.example" "$ENV_FILE" <<'PY'
from pathlib import Path
import secrets
import sys

template_path, output_path = map(Path, sys.argv[1:])
text = template_path.read_text()
passwords = (
    "ROLL_DB_OWNER_PASSWORD", "ROLL_DB_APP_PASSWORD",
    "AUTH_DB_OWNER_PASSWORD", "AUTH_DB_APP_PASSWORD",
    "BALLOT_DB_OWNER_PASSWORD", "BALLOT_DB_APP_PASSWORD",
    "AUDIT_DB_OWNER_PASSWORD", "AUDIT_DB_APP_PASSWORD",
)
for name in passwords:
    text = text.replace(f"{name}=change-me", f"{name}={secrets.token_urlsafe(24)}")
output_path.write_text(text)
output_path.chmod(0o600)
PY
  echo "Created a presentation .env with fresh database passwords."
fi

cd "$ROOT_DIR"

if [[ "$RESET_DATA" -eq 1 ]]; then
  echo "Resetting presentation database volumes..."
  docker compose down -v --remove-orphans
fi

if [[ ! -f "$ROOT_DIR/keys/nginx/server.crt" ]]; then
  "$PYTHON_BIN" scripts/gen_keys.py
fi

echo "Building the live frontend..."
(cd frontend && npm install && npm run build)

echo "Starting the Docker stack..."
docker compose up -d --build
docker compose ps

echo
echo "Presentation logins"
echo "  Voter: SA-0001 / sa-voter-0001"
echo "  Recount delegate: rd.sa (password and live MFA code below)"
echo "  Auditor: aud.demo (password and live MFA code below)"
echo "  Count setup accounts: eo.sa and co.sa"
echo ""
echo "Open https://localhost:8443 and accept the local certificate warning."
echo "Keep the next terminal running for official passwords and MFA codes."
exec "$PYTHON_BIN" scripts/demo_officials.py
