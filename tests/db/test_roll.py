"""GR01 on the electoral roll: eligibility, one live authorisation, and a write-once vote mark."""
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from conftest import ARGON2_PLACEHOLDER, connect, unique_id


@pytest.fixture
def enrolment(db):
    admin = db("roll", "postgres")
    enrolment_id = unique_id("E")
    admin.execute(
        "INSERT INTO roll.enrolment VALUES (%s, 'SA', %s)", (enrolment_id, ARGON2_PLACEHOLDER)
    )
    return enrolment_id


def issue(conn, enrolment_id, election_id, state="SA"):
    return conn.execute(
        "SELECT roll.issue_authorisation(%s, %s, %s)", (enrolment_id, election_id, state)
    ).fetchone()[0]


def test_issues_one_authorisation_then_refuses_while_it_is_live(db, enrolment):
    svc = db("roll", "auth_svc")
    election = unique_id("EL")
    assert issue(svc, enrolment, election) == "ISSUED"
    assert issue(svc, enrolment, election) == "AUTHORISATION_OUTSTANDING"


def test_can_issue_again_once_the_authorisation_has_expired(db, enrolment):
    svc, admin = db("roll", "auth_svc"), db("roll", "postgres")
    election = unique_id("EL")
    issue(svc, enrolment, election)
    admin.execute(
        "UPDATE roll.election_participation "
        "SET authorisation_expires_at = date_trunc('minute', now()) - interval '1 minute' "
        "WHERE enrolment_id = %s", (enrolment,),
    )
    assert issue(svc, enrolment, election) == "ISSUED"


def test_refuses_after_vote_is_marked_even_if_authorisation_expired(db, enrolment):
    svc, admin = db("roll", "auth_svc"), db("roll", "postgres")
    election = unique_id("EL")
    issue(svc, enrolment, election)
    svc.execute("SELECT roll.mark_voted(%s, %s)", (enrolment, election))
    admin.execute(
        "UPDATE roll.election_participation "
        "SET authorisation_expires_at = date_trunc('minute', now()) - interval '1 minute' "
        "WHERE enrolment_id = %s", (enrolment,),
    )
    assert issue(svc, enrolment, election) == "ALREADY_VOTED"


def test_voting_in_one_election_does_not_block_the_next(db, enrolment):
    svc = db("roll", "auth_svc")
    first, second = unique_id("EL"), unique_id("EL")
    svc.execute("SELECT roll.mark_voted(%s, %s)", (enrolment, first))
    assert issue(svc, enrolment, second) == "ISSUED"


def test_wrong_state_and_unknown_elector_get_the_same_answer(db, enrolment):
    svc = db("roll", "auth_svc")
    election = unique_id("EL")
    assert issue(svc, enrolment, election, state="VIC") == "NOT_ELIGIBLE"
    assert issue(svc, unique_id("E"), election) == "NOT_ELIGIBLE"


def test_concurrent_logins_get_exactly_one_authorisation(db, enrolment):
    election = unique_id("EL")

    def attempt(_):
        with connect("roll", "auth_svc") as conn:
            return issue(conn, enrolment, election)

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count("ISSUED") == 1
    assert results.count("AUTHORISATION_OUTSTANDING") == 7


def test_mark_voted_is_write_once(db, enrolment):
    svc, admin = db("roll", "auth_svc"), db("roll", "postgres")
    election = unique_id("EL")
    svc.execute("SELECT roll.mark_voted(%s, %s)", (enrolment, election))
    earlier = "2020-01-01 00:00:00+00"
    admin.execute(
        "UPDATE roll.election_participation SET voted_at = %s WHERE enrolment_id = %s",
        (earlier, enrolment),
    )
    svc.execute("SELECT roll.mark_voted(%s, %s)", (enrolment, election))
    voted_at = admin.execute(
        "SELECT voted_at = %s::timestamptz FROM roll.election_participation WHERE enrolment_id = %s",
        (earlier, enrolment),
    ).fetchone()[0]
    assert voted_at is True


def test_times_are_rounded_to_the_minute(db, enrolment):
    svc = db("roll", "auth_svc")
    election = unique_id("EL")
    issue(svc, enrolment, election)
    svc.execute("SELECT roll.mark_voted(%s, %s)", (enrolment, election))
    seconds = svc.execute(
        "SELECT EXTRACT(SECOND FROM voted_at), EXTRACT(SECOND FROM authorisation_expires_at) "
        "FROM roll.election_participation WHERE enrolment_id = %s", (enrolment,),
    ).fetchone()
    assert [float(value) for value in seconds] == [0.0, 0.0]


def test_a_precise_time_is_rejected_even_for_the_superuser(db, enrolment):
    admin = db("roll", "postgres")
    with pytest.raises(psycopg.errors.CheckViolation):
        admin.execute(
            "INSERT INTO roll.election_participation (election_id, enrolment_id, voted_at) "
            "VALUES (%s, %s, '2026-01-01 10:15:42+00')", (unique_id("EL"), enrolment),
        )


@pytest.mark.parametrize("statement", [
    "UPDATE roll.election_participation SET voted_at = NULL",
    "DELETE FROM roll.election_participation",
    "INSERT INTO roll.election_participation (election_id, enrolment_id) VALUES ('ELEC', 'E-000000')",
    "UPDATE roll.enrolment SET state = 'SA'",
    "DELETE FROM roll.enrolment",
    "TRUNCATE roll.election_participation",
])
def test_auth_svc_cannot_write_to_the_roll_directly(db, statement):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        db("roll", "auth_svc").execute(statement)


def test_roll_has_nowhere_to_store_a_nonce_or_ballot(db):
    columns = {row[0] for row in db("roll", "postgres").execute(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = 'roll'"
    )}
    assert not {c for c in columns if "nonce" in c or "ballot" in c or "token" in c}
