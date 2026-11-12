"""
Author: Zak
Edits:

Per-account lockout for OFFICIALS after repeated failures. Nginx limits by IP address; this
limits by account, so a slow distributed guessing attack is still stopped.

Electors are deliberately never locked out (Milestone 2 Section 4.4): anyone who knew a voter
ID could otherwise lock that person out of voting.

Uses its OWN transaction: the request's transaction is rolled back when the login is
rejected, and a failure count written there would be rolled back with it.

Requirements:
    GR04 - password guessing is slowed down without letting anyone lock voters out
    GR03 - only officials holding valid credentials can act

Run:
    docker compose up -d --build
    Needs the auth database, so it gets tested through the official sign-in

Usage example:
    from app import lockout

    for _ in range(5):
        lockout.record_failure("official:eo.sa")
    lockout.is_locked("official:eo.sa")

Output:
    True
    After 5 wrong passwords or codes the account is locked for 15 minutes
    Signing in during that time gives "Too many failed attempts, try again later"
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from common.db import get_engine
from common.settings import get_settings


def _engine():
    return get_engine(get_settings().database_url)


def is_locked(subject: str) -> bool:
    with _engine().connect() as conn:
        row = conn.execute(
            text("SELECT locked_until FROM login_failures WHERE subject = :s"), {"s": subject}
        ).first()
    return bool(row and row.locked_until and row.locked_until > datetime.now(timezone.utc))


def record_failure(subject: str) -> None:
    s = get_settings()
    with _engine().begin() as conn:
        conn.execute(
            text("""
                INSERT INTO login_failures (subject, failures) VALUES (:s, 1)
                ON CONFLICT (subject) DO UPDATE SET failures = login_failures.failures + 1
            """),
            {"s": subject},
        )
        conn.execute(
            text("""
                UPDATE login_failures
                   SET locked_until = :until, failures = 0
                 WHERE subject = :s AND failures >= :max
            """),
            {
                "s": subject,
                "max": s.login_max_failures,
                "until": datetime.now(timezone.utc) + timedelta(minutes=s.login_lockout_minutes),
            },
        )


def clear_failures(subject: str) -> None:
    with _engine().begin() as conn:
        conn.execute(text("DELETE FROM login_failures WHERE subject = :s"), {"s": subject})
