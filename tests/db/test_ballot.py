"""GR01, GR02 and GR03 in the ballot database: atomic casting, secrecy, snapshots and exclusions."""
import hashlib
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from conftest import connect, new_nonce, raises_sqlstate, unique_id

PHASES_TO_POLLING = ("NOMINATIONS_COMMITTED", "ORDER_FIXED", "POLLING")
EV_NOT_ACCEPTED = "EV200"


def set_phases(conn, election, *phases):
    for phase in phases:
        conn.execute("UPDATE election.election SET phase = %s WHERE election_id = %s", (phase, election))


def new_election(conn, *phases, state="SA"):
    election = unique_id("EL")
    conn.execute("INSERT INTO election.election (election_id, state) VALUES (%s, %s)", (election, state))
    set_phases(conn, election, *phases)
    return election


def cast(conn, election, nonce=None, state="SA", ciphertext=None):
    return conn.execute(
        "SELECT ballot.cast_ballot(%s, %s, %s, 'key-1', %s, %s)",
        (nonce or new_nonce(), election, state, secrets.token_bytes(12),
         ciphertext or secrets.token_bytes(64)),
    ).fetchone()[0]


@pytest.fixture
def count_svc(db):
    return db("ballot", "count_svc")


@pytest.fixture
def ballot_svc(db):
    return db("ballot", "ballot_svc")


@pytest.fixture
def polling(count_svc):
    return new_election(count_svc, *PHASES_TO_POLLING)


def total_ballots(db, election):
    return db("ballot", "postgres").execute(
        "SELECT count(*) FROM ballot.ballot WHERE election_id = %s", (election,)
    ).fetchone()[0]


# ---------------------------------------------------------------- casting (GR01)

def test_cast_stores_the_ballot_and_consumes_the_nonce(db, ballot_svc, polling):
    nonce = new_nonce()
    assert isinstance(cast(ballot_svc, polling, nonce), uuid.UUID)
    assert total_ballots(db, polling) == 1
    used = db("ballot", "postgres").execute(
        "SELECT count(*) FROM ballot.used_nonce WHERE nonce = %s", (nonce,)
    ).fetchone()[0]
    assert used == 1


def test_replayed_nonce_stores_nothing(db, ballot_svc, polling):
    nonce = new_nonce()
    assert cast(ballot_svc, polling, nonce) is not None
    assert cast(ballot_svc, polling, nonce) is None
    assert total_ballots(db, polling) == 1


def test_concurrent_submissions_of_one_token_store_one_ballot(db, polling):
    nonce = new_nonce()

    def attempt(_):
        with connect("ballot", "ballot_svc") as conn:
            return cast(conn, polling, nonce)

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert sum(result is not None for result in results) == 1
    assert total_ballots(db, polling) == 1


def test_failed_ballot_insert_also_rolls_back_the_nonce(db, ballot_svc, polling):
    nonce = new_nonce()
    with pytest.raises(psycopg.errors.CheckViolation):
        ballot_svc.execute(
            "SELECT ballot.cast_ballot(%s, %s, 'SA', 'key-1', %s, %s)",
            (nonce, polling, secrets.token_bytes(5), b"x"),  # Bad IV length.
        )
    assert cast(ballot_svc, polling, nonce) is not None


@pytest.mark.parametrize("phases", [
    (), ("NOMINATIONS_COMMITTED",), ("NOMINATIONS_COMMITTED", "ORDER_FIXED"),
    (*PHASES_TO_POLLING, "POLL_CLOSED"),
])
def test_ballot_is_refused_outside_polling(count_svc, ballot_svc, phases):
    election = new_election(count_svc, *phases)
    with raises_sqlstate(EV_NOT_ACCEPTED):
        cast(ballot_svc, election)


def test_token_for_another_state_is_refused_and_keeps_its_nonce_unused(ballot_svc, polling):
    nonce = new_nonce()
    with raises_sqlstate(EV_NOT_ACCEPTED):
        cast(ballot_svc, polling, nonce, state="VIC")
    assert cast(ballot_svc, polling, nonce) is not None


def test_unknown_election_is_refused(ballot_svc):
    with raises_sqlstate(EV_NOT_ACCEPTED):
        cast(ballot_svc, unique_id("EL"))


def test_nonce_must_be_128_bits(ballot_svc, polling):
    with pytest.raises(psycopg.errors.CheckViolation):
        cast(ballot_svc, polling, nonce=b"short")


# ---------------------------------------------------------------- secrecy (GR02)

@pytest.mark.parametrize("statement", [
    "SELECT * FROM ballot.ballot",
    "SELECT * FROM ballot.used_nonce",
    "INSERT INTO ballot.used_nonce VALUES ('\\x00000000000000000000000000000000')",
    "INSERT INTO ballot.ballot (election_id, key_id, iv, ciphertext) VALUES ('X', 'k', '\\x00', '\\x00')",
    "DELETE FROM ballot.ballot",
    "UPDATE ballot.ballot SET ciphertext = '\\x00'",
    "SELECT * FROM counting.count_run",
    "SELECT * FROM counting.snapshot_ballot",
    "INSERT INTO election.election (election_id, state) VALUES ('XXXX', 'SA')",
    "UPDATE election.election SET phase = 'POLLING'",
])
def test_ballot_svc_has_only_its_two_functions(ballot_svc, statement):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        ballot_svc.execute(statement)


@pytest.mark.parametrize("statement", [
    "SELECT * FROM ballot.ballot",
    "SELECT xmin, ctid FROM ballot.ballot",
    "SELECT * FROM ballot.used_nonce",
    "SELECT * FROM ballot.get_ballot(gen_random_uuid())",
    "SELECT ballot.cast_ballot('\\x00', 'X', 'SA', 'k', '\\x00', '\\x00')",
])
def test_count_svc_cannot_reach_raw_ballots(count_svc, statement):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        count_svc.execute(statement)


@pytest.mark.parametrize("statement", [
    "UPDATE ballot.ballot SET key_id = 'x'",
    "DELETE FROM ballot.ballot",
    "TRUNCATE ballot.ballot",
    "DELETE FROM ballot.used_nonce",
    "TRUNCATE ballot.used_nonce",
])
def test_even_the_superuser_hits_the_append_only_triggers(db, ballot_svc, polling, statement):
    cast(ballot_svc, polling)
    with raises_sqlstate("EV100"):
        db("ballot", "postgres").execute(statement)


def test_ballot_tables_have_no_identifying_or_ordering_columns(db):
    admin = db("ballot", "postgres")
    columns = {row[0]: row[1] for row in admin.execute(
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = 'ballot' AND table_name = 'ballot'"
    )}
    assert set(columns) == {"ballot_ref", "election_id", "key_id", "iv", "ciphertext"}
    assert "timestamp with time zone" not in columns.values()
    assert admin.execute(
        "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'ballot' "
        "AND (column_default LIKE 'nextval%' OR is_identity = 'YES')"
    ).fetchone()[0] == 0
    assert {row[0] for row in admin.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'ballot' AND table_name = 'used_nonce'"
    )} == {"nonce"}


def test_no_foreign_key_touches_the_nonce_store(db):
    assert db("ballot", "postgres").execute(
        "SELECT count(*) FROM pg_constraint WHERE contype = 'f' "
        "AND 'ballot.used_nonce'::regclass IN (conrelid, confrelid)"
    ).fetchone()[0] == 0


def test_no_column_in_this_database_can_hold_an_elector(db):
    columns = {row[0] for row in db("ballot", "postgres").execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema IN ('election', 'ballot', 'counting')"
    )}
    assert not {c for c in columns if "enrol" in c or "elector" in c or "voter" in c}


def test_get_ballot_reads_one_ballot_by_reference(ballot_svc, polling):
    ciphertext = secrets.token_bytes(32)
    reference = cast(ballot_svc, polling, ciphertext=ciphertext)
    rows = ballot_svc.execute("SELECT * FROM ballot.get_ballot(%s)", (reference,)).fetchall()
    assert len(rows) == 1 and bytes(rows[0][3]) == ciphertext


# ---------------------------------------------------------------- phases

def test_phases_cannot_be_skipped_or_reversed(count_svc):
    election = new_election(count_svc)
    with raises_sqlstate("EV101"):
        set_phases(count_svc, election, "POLLING")
    set_phases(count_svc, election, *PHASES_TO_POLLING, "POLL_CLOSED")
    with raises_sqlstate("EV101"):
        set_phases(count_svc, election, "POLLING")


def test_nominations_lock_once_committed(count_svc):
    election = new_election(count_svc)
    count_svc.execute("INSERT INTO election.party_group (election_id, group_id, name) VALUES (%s, 'A', 'One')", (election,))
    candidate = count_svc.execute(
        "INSERT INTO election.candidate (election_id, group_id, name, position_in_group) "
        "VALUES (%s, 'A', 'First', 1) RETURNING candidate_id", (election,),
    ).fetchone()[0]
    set_phases(count_svc, election, "NOMINATIONS_COMMITTED")

    for statement, parameters in [
        ("INSERT INTO election.candidate (election_id, name) VALUES (%s, 'Late')", (election,)),
        ("UPDATE election.candidate SET name = 'Changed' WHERE candidate_id = %s", (candidate,)),
        ("DELETE FROM election.candidate WHERE candidate_id = %s", (candidate,)),
        ("UPDATE election.party_group SET name = 'Changed' WHERE election_id = %s", (election,)),
        ("INSERT INTO election.party_group (election_id, group_id, name) VALUES (%s, 'B', 'Two')", (election,)),
    ]:
        with raises_sqlstate("EV102"):
            count_svc.execute(statement, parameters)


def test_party_order_needs_every_position_and_then_locks(count_svc):
    election = new_election(count_svc)
    count_svc.execute("INSERT INTO election.party_group (election_id, group_id, name) VALUES (%s, 'A', 'One')", (election,))
    set_phases(count_svc, election, "NOMINATIONS_COMMITTED")
    with raises_sqlstate("EV101"):
        set_phases(count_svc, election, "ORDER_FIXED")

    count_svc.execute("UPDATE election.party_group SET ballot_position = 1 WHERE election_id = %s", (election,))
    set_phases(count_svc, election, "ORDER_FIXED")
    with raises_sqlstate("EV102"):
        count_svc.execute("UPDATE election.party_group SET ballot_position = 2 WHERE election_id = %s", (election,))


# ---------------------------------------------------------------- snapshot

def closed_with_ballots(count_svc, ballot_svc, how_many):
    election = new_election(count_svc, *PHASES_TO_POLLING)
    references = [cast(ballot_svc, election) for _ in range(how_many)]
    set_phases(count_svc, election, "POLL_CLOSED")
    return election, references


def snapshot(count_svc, election):
    return count_svc.execute("SELECT counting.create_snapshot(%s)", (election,)).fetchone()[0]


def test_snapshot_has_every_ballot_in_a_different_order_with_new_ids(db, count_svc, ballot_svc):
    election, references = closed_with_ballots(count_svc, ballot_svc, 40)
    snapshot_id = snapshot(count_svc, election)

    admin = db("ballot", "postgres")
    cast_order = [bytes(row[0]) for row in admin.execute(
        "SELECT ciphertext FROM ballot.ballot WHERE election_id = %s ORDER BY ctid", (election,)
    )]
    snapshot_order = [(row[0], bytes(row[1])) for row in count_svc.execute(
        "SELECT entry_id, ciphertext FROM counting.snapshot_ballot WHERE snapshot_id = %s ORDER BY ctid",
        (snapshot_id,),
    )]
    assert sorted(c for _, c in snapshot_order) == sorted(cast_order)
    assert [c for _, c in snapshot_order] != cast_order
    assert not {entry for entry, _ in snapshot_order} & set(references)


def test_snapshot_digest_matches_a_recomputation_and_the_count(count_svc, ballot_svc):
    election, _ = closed_with_ballots(count_svc, ballot_svc, 5)
    snapshot_id = snapshot(count_svc, election)
    count, digest = count_svc.execute(
        "SELECT ballot_count, set_digest FROM counting.ballot_snapshot WHERE snapshot_id = %s", (snapshot_id,)
    ).fetchone()
    hashes = sorted(
        hashlib.sha256(bytes(row[0]) + bytes(row[1])).digest()
        for row in count_svc.execute(
            "SELECT iv, ciphertext FROM counting.snapshot_ballot WHERE snapshot_id = %s", (snapshot_id,)
        )
    )
    assert count == 5
    assert bytes(digest) == hashlib.sha256(b"".join(hashes)).digest()


def test_empty_election_still_gets_a_valid_snapshot(count_svc, ballot_svc):
    election, _ = closed_with_ballots(count_svc, ballot_svc, 0)
    assert snapshot(count_svc, election) is not None


def test_snapshot_refused_while_polling(count_svc, polling):
    with raises_sqlstate("EV203"):
        snapshot(count_svc, polling)


def test_only_one_snapshot_per_election(count_svc, ballot_svc):
    election, _ = closed_with_ballots(count_svc, ballot_svc, 1)
    snapshot(count_svc, election)
    with pytest.raises(psycopg.errors.UniqueViolation):
        snapshot(count_svc, election)


def test_snapshot_cannot_be_changed(count_svc, ballot_svc, db):
    election, _ = closed_with_ballots(count_svc, ballot_svc, 1)
    snapshot(count_svc, election)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        count_svc.execute("DELETE FROM counting.snapshot_ballot")
    with raises_sqlstate("EV100"):
        db("ballot", "postgres").execute("DELETE FROM counting.snapshot_ballot")


def test_closing_the_poll_waits_for_a_ballot_in_flight(db, count_svc, polling):
    casting = db("ballot", "ballot_svc", autocommit=False)
    cast(casting, polling)

    count_svc.execute("SET lock_timeout = '300ms'")
    with pytest.raises(psycopg.errors.LockNotAvailable):
        set_phases(count_svc, polling, "POLL_CLOSED")

    casting.commit()
    set_phases(count_svc, polling, "POLL_CLOSED")
    snapshot_id = snapshot(count_svc, polling)
    assert count_svc.execute(
        "SELECT ballot_count FROM counting.ballot_snapshot WHERE snapshot_id = %s", (snapshot_id,)
    ).fetchone()[0] == 1


# ---------------------------------------------------------------- counts and exclusions (GR03)

ZERO_DIGEST = bytes(32)


def start_count(count_svc, election, snapshot_id, kind="INITIAL", parent=None):
    count_id = uuid.uuid4()
    count_svc.execute(
        "INSERT INTO counting.count_run (count_id, election_id, snapshot_id, kind, parent_count_id, "
        "config_digest, started_by) VALUES (%s, %s, %s, %s, %s, %s, 'AEC-SA-0001')",
        (count_id, election, snapshot_id, kind, parent, ZERO_DIGEST),
    )
    return count_id


@pytest.fixture
def counted(count_svc, ballot_svc):
    """An election with a candidate and a finished count. Returns (election, candidate, snapshot, count)."""
    election = new_election(count_svc)
    candidate = count_svc.execute(
        "INSERT INTO election.candidate (election_id, name) VALUES (%s, 'Candidate') RETURNING candidate_id",
        (election,),
    ).fetchone()[0]
    set_phases(count_svc, election, *PHASES_TO_POLLING)
    cast(ballot_svc, election)
    set_phases(count_svc, election, "POLL_CLOSED")
    snapshot_id = snapshot(count_svc, election)
    count_id = start_count(count_svc, election, snapshot_id)
    count_svc.execute("UPDATE counting.count_run SET status = 'COMPLETE', finished_at = now() WHERE count_id = %s", (count_id,))
    set_phases(count_svc, election, "COUNTED")
    return election, candidate, snapshot_id, count_id


def exclude(conn, count_id, election, candidate, ground="CONSTITUTION_S44", order="HCA 1 of 2028"):
    return conn.execute(
        "INSERT INTO counting.exclusion (count_id, election_id, candidate_id, ground, court_order_ref, entered_by) "
        "VALUES (%s, %s, %s, %s, %s, 'AEC-SA-0002')", (count_id, election, candidate, ground, order),
    )


def test_exclusion_is_accepted_only_while_a_recount_is_open(count_svc, counted):
    election, candidate, _, count_id = counted
    with raises_sqlstate("EV202"):
        exclude(count_svc, count_id, election, candidate)

    set_phases(count_svc, election, "RECOUNT_OPEN")
    exclude(count_svc, count_id, election, candidate)

    set_phases(count_svc, election, "COUNTED")
    other = uuid.uuid4()
    with raises_sqlstate("EV202"):
        exclude(count_svc, other, election, candidate)


@pytest.mark.parametrize("overrides, error", [
    ({"ground": "BECAUSE_I_SAID_SO"}, psycopg.errors.ForeignKeyViolation),
    ({"order": "   "}, psycopg.errors.CheckViolation),
    ({"order": None}, psycopg.errors.NotNullViolation),
])
def test_exclusion_needs_a_listed_ground_and_court_order(count_svc, counted, overrides, error):
    election, candidate, _, count_id = counted
    set_phases(count_svc, election, "RECOUNT_OPEN")
    with pytest.raises(error):
        exclude(count_svc, count_id, election, candidate, **overrides)


def test_exclusion_cannot_reach_into_another_election(count_svc, ballot_svc, counted):
    election, candidate, _, count_id = counted
    other_election = new_election(count_svc)
    other_candidate = count_svc.execute(
        "INSERT INTO election.candidate (election_id, name) VALUES (%s, 'Other') RETURNING candidate_id",
        (other_election,),
    ).fetchone()[0]
    set_phases(count_svc, election, "RECOUNT_OPEN")

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        exclude(count_svc, count_id, election, other_candidate)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        exclude(count_svc, uuid.uuid4(), election, candidate)


def test_same_candidate_cannot_be_excluded_twice_from_a_count(count_svc, counted):
    election, candidate, _, count_id = counted
    set_phases(count_svc, election, "RECOUNT_OPEN")
    exclude(count_svc, count_id, election, candidate)
    with pytest.raises(psycopg.errors.UniqueViolation):
        exclude(count_svc, count_id, election, candidate)


def test_exclusion_cannot_be_changed_or_backdated(db, count_svc, counted):
    election, candidate, _, count_id = counted
    set_phases(count_svc, election, "RECOUNT_OPEN")
    exclude(count_svc, count_id, election, candidate)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        count_svc.execute("DELETE FROM counting.exclusion")
    with raises_sqlstate("EV100"):
        db("ballot", "postgres").execute("UPDATE counting.exclusion SET ground = 'COURT_ORDER_OTHER'")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        count_svc.execute(
            "INSERT INTO counting.exclusion (count_id, election_id, candidate_id, ground, court_order_ref, "
            "entered_by, entered_at) VALUES (%s, %s, %s, 'CONSTITUTION_S44', 'x', 'y', '2020-01-01')",
            (count_id, election, candidate),
        )


def test_count_cannot_start_while_polling_or_on_another_elections_snapshot(count_svc, counted, polling):
    election, _, snapshot_id, _ = counted
    with raises_sqlstate("EV201"):
        start_count(count_svc, polling, snapshot_id)
    set_phases(count_svc, polling, "POLL_CLOSED")
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        start_count(count_svc, polling, snapshot_id)


def test_recount_uses_the_preserved_snapshot_and_names_its_parent(count_svc, counted):
    election, _, snapshot_id, count_id = counted
    set_phases(count_svc, election, "RECOUNT_OPEN")
    with pytest.raises(psycopg.errors.CheckViolation):
        start_count(count_svc, election, snapshot_id, kind="RECOUNT")
    assert start_count(count_svc, election, snapshot_id, kind="RECOUNT", parent=count_id)


def test_finished_count_cannot_change(count_svc, counted):
    _, _, _, count_id = counted
    with raises_sqlstate("EV201"):
        count_svc.execute("UPDATE counting.count_run SET status = 'RUNNING' WHERE count_id = %s", (count_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        count_svc.execute("DELETE FROM counting.count_run")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        count_svc.execute("UPDATE counting.count_run SET started_by = 'someone-else'")
