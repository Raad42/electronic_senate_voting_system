"""Officials: role scope, session limits and single-use step-up (Sections 2.3, 2.5 and 3.4)."""
import hashlib
import secrets
import uuid

import psycopg
import pytest

from conftest import ARGON2_PLACEHOLDER


def digest() -> bytes:
    return hashlib.sha256(secrets.token_bytes(32)).digest()


@pytest.fixture
def operator(db):
    admin = db("auth", "postgres")
    operator_id = f"AEC-SA-{secrets.randbelow(10000):04d}"
    admin.execute(
        "INSERT INTO auth.official (operator_id, password_hash, totp_secret_encrypted) "
        "VALUES (%s, %s, '\\x00') ON CONFLICT DO NOTHING", (operator_id, ARGON2_PLACEHOLDER),
    )
    return operator_id


@pytest.fixture
def session(db, operator):
    """A live RECOUNT_DELEGATE session. Returns (session hash, operator id)."""
    admin, svc = db("auth", "postgres"), db("auth", "auth_svc")
    assignment = admin.execute(
        "INSERT INTO auth.role_assignment (operator_id, role, state, election_id, count_id) "
        "VALUES (%s, 'RECOUNT_DELEGATE', 'SA', 'EL-2028-SA', %s) RETURNING assignment_id",
        (operator, uuid.uuid4()),
    ).fetchone()[0]
    session_hash = digest()
    svc.execute(
        "INSERT INTO auth.session (session_id_hash, assignment_id, csrf_token_hash, mfa_satisfied) "
        "VALUES (%s, %s, %s, true)", (session_hash, assignment, digest()),
    )
    return session_hash, operator


def new_step_up(svc, session_hash, action="ENTER_MANUAL_EXCLUSION", resource="count-1/candidate-1"):
    svc.execute(
        "INSERT INTO auth.step_up_assertion (session_id_hash, action, resource) VALUES (%s, %s, %s)",
        (session_hash, action, resource),
    )
    return svc.execute(
        "SELECT assertion_id FROM auth.step_up_assertion WHERE session_id_hash = %s "
        "ORDER BY issued_at DESC LIMIT 1", (session_hash,),
    ).fetchone()[0]


def consume(svc, assertion, session_hash, action="ENTER_MANUAL_EXCLUSION", resource="count-1/candidate-1"):
    return svc.execute(
        "SELECT auth.consume_step_up(%s, %s, %s, %s)", (assertion, session_hash, action, resource)
    ).fetchone()[0]


@pytest.mark.parametrize("role, state, election, has_count", [
    ("ELECTION_OFFICIAL", "SA", "EL-1", True),   # Counting has not started, so no count.
    ("ELECTION_OFFICIAL", None, "EL-1", False),
    ("COUNT_OPERATOR", "SA", "EL-1", False),     # Limited to one count.
    ("RECOUNT_DELEGATE", "SA", "EL-1", False),
    ("RECOUNT_DELEGATE", "SA", None, True),
    ("AUDITOR", None, None, True),               # Read-only, never tied to a count.
])
def test_a_role_cannot_have_the_wrong_scope(db, operator, role, state, election, has_count):
    with pytest.raises(psycopg.errors.CheckViolation):
        db("auth", "postgres").execute(
            "INSERT INTO auth.role_assignment (operator_id, role, state, election_id, count_id) "
            "VALUES (%s, %s, %s, %s, %s)",
            (operator, role, state, election, uuid.uuid4() if has_count else None),
        )


def test_step_up_works_once(db, session):
    svc = db("auth", "auth_svc")
    session_hash, _ = session
    assertion = new_step_up(svc, session_hash)
    assert consume(svc, assertion, session_hash) == "OK"
    assert consume(svc, assertion, session_hash) == "ALREADY_USED"


@pytest.mark.parametrize("action, resource", [
    ("START_COUNT", "count-1/candidate-1"),            # Wrong action.
    ("ENTER_MANUAL_EXCLUSION", "count-2/candidate-1"), # Issued for another count.
])
def test_step_up_mismatch_is_refused_and_burned(db, session, action, resource):
    svc = db("auth", "auth_svc")
    session_hash, _ = session
    assertion = new_step_up(svc, session_hash)
    assert consume(svc, assertion, session_hash, action, resource) == "MISMATCH"
    assert consume(svc, assertion, session_hash) == "ALREADY_USED"


def test_expired_step_up_is_refused(db, session):
    svc, admin = db("auth", "auth_svc"), db("auth", "postgres")
    session_hash, _ = session
    assertion = new_step_up(svc, session_hash)
    admin.execute(
        "UPDATE auth.step_up_assertion SET issued_at = now() - interval '3 minutes', "
        "expires_at = now() - interval '1 minute' WHERE assertion_id = %s", (assertion,),
    )
    assert consume(svc, assertion, session_hash) == "EXPIRED"


def test_step_up_from_another_session_is_not_found(db, session):
    svc = db("auth", "auth_svc")
    session_hash, _ = session
    assertion = new_step_up(svc, session_hash)
    assert consume(svc, assertion, digest()) == "NOT_FOUND"


def test_step_up_cannot_last_longer_than_two_minutes(db, session):
    session_hash, _ = session
    with pytest.raises(psycopg.errors.CheckViolation):
        db("auth", "postgres").execute(
            "INSERT INTO auth.step_up_assertion (session_id_hash, action, resource, expires_at) "
            "VALUES (%s, 'START_COUNT', 'count-1', clock_timestamp() + interval '5 minutes')",
            (session_hash,),
        )


def test_only_the_four_irreversible_actions_can_have_a_step_up(db, session):
    session_hash, _ = session
    with pytest.raises(psycopg.errors.InvalidTextRepresentation):
        db("auth", "auth_svc").execute(
            "INSERT INTO auth.step_up_assertion (session_id_hash, action, resource) "
            "VALUES (%s, 'READ_AUDIT_LOG', 'x')", (session_hash,),
        )


def touch(svc, session_hash):
    return svc.execute("SELECT * FROM auth.touch_session(%s)", (session_hash,)).fetchone()


def test_live_session_returns_its_identity_and_one_role(db, session):
    session_hash, operator = session
    row = touch(db("auth", "auth_svc"), session_hash)
    assert row[0] == operator
    assert row[1] == "RECOUNT_DELEGATE"
    assert row[2] == "SA"


@pytest.mark.parametrize("change", [
    "revoked_at = now()",
    "last_seen_at = now() - interval '31 minutes'",
    "created_at = now() - interval '9 hours', absolute_expires_at = now() - interval '1 hour'",
])
def test_dead_sessions_return_nothing(db, session, change):
    session_hash, _ = session
    db("auth", "postgres").execute(
        f"UPDATE auth.session SET {change} WHERE session_id_hash = %s", (session_hash,)
    )
    assert touch(db("auth", "auth_svc"), session_hash) is None


def test_session_of_a_disabled_official_returns_nothing(db, session):
    session_hash, operator = session
    db("auth", "postgres").execute(
        "UPDATE auth.official SET disabled_at = now() WHERE operator_id = %s", (operator,)
    )
    assert touch(db("auth", "auth_svc"), session_hash) is None


@pytest.mark.parametrize("statement", [
    "INSERT INTO auth.role_assignment (operator_id, role) VALUES ('AEC-SA-0001', 'AUDITOR')",
    "UPDATE auth.role_assignment SET role = 'AUDITOR'",
    "UPDATE auth.session SET assignment_id = gen_random_uuid()",
    "UPDATE auth.session SET absolute_expires_at = now() + interval '1 year'",
    "UPDATE auth.session SET last_seen_at = now()",
    "UPDATE auth.session SET mfa_satisfied = true",
    "UPDATE auth.step_up_assertion SET expires_at = now() + interval '1 hour'",
    "UPDATE auth.step_up_assertion SET consumed_at = NULL",
    "UPDATE auth.official SET password_hash = 'x'",
    "UPDATE auth.official SET disabled_at = NULL",
    "DELETE FROM auth.session",
])
def test_auth_svc_cannot_widen_its_own_access(db, statement):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        db("auth", "auth_svc").execute(statement)


def test_a_password_must_be_an_argon2id_hash(db):
    with pytest.raises(psycopg.errors.CheckViolation):
        db("auth", "postgres").execute(
            "INSERT INTO auth.official (operator_id, password_hash, totp_secret_encrypted) "
            "VALUES ('AEC-SA-9999', 'plaintext', '\\x00')"
        )
