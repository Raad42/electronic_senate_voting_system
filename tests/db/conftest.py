"""Shared helpers for the database tests. They need the databases from db/compose.dev.yaml."""
import os
import secrets
import uuid
from contextlib import contextmanager
from pathlib import Path

import psycopg
import pytest

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
HOST = os.environ.get("DB_TEST_HOST", "127.0.0.1")
PORTS = {"roll": 5541, "auth": 5542, "ballot": 5543, "audit": 5544}
PASSWORD_VARS = {
    ("roll", "postgres"): "ROLL_DB_SUPERUSER_PASSWORD",
    ("roll", "auth_svc"): "ROLL_AUTH_SVC_PASSWORD",
    ("auth", "postgres"): "AUTH_DB_SUPERUSER_PASSWORD",
    ("auth", "auth_svc"): "AUTH_AUTH_SVC_PASSWORD",
    ("ballot", "postgres"): "BALLOT_DB_SUPERUSER_PASSWORD",
    ("ballot", "ballot_svc"): "BALLOT_BALLOT_SVC_PASSWORD",
    ("ballot", "count_svc"): "BALLOT_COUNT_SVC_PASSWORD",
    ("audit", "postgres"): "AUDIT_DB_SUPERUSER_PASSWORD",
    ("audit", "audit_svc"): "AUDIT_AUDIT_SVC_PASSWORD",
}
ARGON2_PLACEHOLDER = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"


def _env_file_values() -> dict[str, str]:
    if not ENV_FILE.exists():
        return {}
    pairs = (
        line.split("=", 1)
        for line in ENV_FILE.read_text().splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    )
    return {key.strip(): value.strip() for key, value in pairs}


def connect(database: str, user: str, autocommit: bool = True) -> psycopg.Connection:
    variable = PASSWORD_VARS[(database, user)]
    password = os.environ.get(variable) or _env_file_values().get(variable)
    if not password:
        pytest.skip(f"{variable} is not set")
    try:
        return psycopg.connect(
            host=HOST, port=PORTS[database], dbname=database, user=user,
            password=password, autocommit=autocommit, connect_timeout=3,
        )
    except psycopg.OperationalError as error:
        if "password authentication failed" in str(error) or "permission denied" in str(error):
            raise
        pytest.skip(f"{database} database is not reachable: {error}")


@pytest.fixture
def db():
    """Connect as a named login. Closes everything when the test ends."""
    opened = []

    def open_connection(database: str, user: str, autocommit: bool = True):
        connection = connect(database, user, autocommit)
        opened.append(connection)
        return connection

    yield open_connection
    for connection in opened:
        connection.close()


def unique_id(prefix: str = "T") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


def new_nonce() -> bytes:
    return secrets.token_bytes(16)


@contextmanager
def raises_sqlstate(code: str):
    """Expect a database error with this SQLSTATE, such as the custom EV codes in db/*/init.sql."""
    with pytest.raises(psycopg.Error) as caught:
        yield
    assert caught.value.sqlstate == code
