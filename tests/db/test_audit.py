"""GR05 and the GR02 split in the audit log: tamper evidence, append-only, disjoint families."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from conftest import connect, new_nonce, raises_sqlstate, unique_id

FAMILIES = ["authorisation_record", "nonce_record", "operator_record",
            "service_record", "query_record", "count_record"]
GENESIS = bytes(32)


def add_operator_event(conn, event_type="POLICY_DENIED", operator="AEC-SA-0001", reason="test"):
    return conn.execute(
        "INSERT INTO audit.operator_record (event_type, operator_id, reason) VALUES (%s, %s, %s) "
        "RETURNING seq, prev_hash, event_hash, occurred_minute",
        (event_type, operator, reason),
    ).fetchone()


def verify(conn, family="operator_record"):
    return conn.execute("SELECT * FROM audit.verify_chain(%s)", (family,)).fetchone()


@pytest.fixture
def svc(db):
    return db("audit", "audit_svc")


def tamper_then_verify(db, svc, statements, family="operator_record"):
    """Runs a superuser attack with triggers off, checks the chain, then rolls it all back."""
    attacker = db("audit", "postgres", autocommit=False)
    attacker.execute(f"ALTER TABLE audit.{family} DISABLE TRIGGER USER")
    for statement in statements:
        attacker.execute(statement)
    result = attacker.execute("SELECT * FROM audit.verify_chain(%s)", (family,)).fetchone()
    attacker.rollback()
    return result


def test_each_record_links_to_the_one_before(svc):
    first = add_operator_event(svc)
    second = add_operator_event(svc)
    assert second[0] == first[0] + 1
    assert bytes(second[1]) == bytes(first[2])
    assert bytes(second[2]) != bytes(first[2])


def test_callers_cannot_choose_the_sequence_time_or_hashes(svc):
    row = svc.execute(
        "INSERT INTO audit.operator_record (seq, occurred_minute, prev_hash, event_hash, event_type, operator_id) "
        "VALUES (999999, '2000-01-01', '\\x00', '\\x00', 'POLICY_DENIED', 'AEC-SA-0001') "
        "RETURNING seq, occurred_minute, prev_hash, event_hash",
    ).fetchone()
    assert row[0] != 999999
    assert row[1].year != 2000
    assert len(bytes(row[2])) == 32 and len(bytes(row[3])) == 32
    assert verify(svc)[0] is True


def test_times_are_rounded_to_the_minute(svc):
    occurred = add_operator_event(svc)[3]
    assert occurred.second == 0 and occurred.microsecond == 0


@pytest.mark.parametrize("family", FAMILIES)
def test_empty_or_untampered_chains_verify(svc, family):
    assert svc.execute("SELECT ok FROM audit.verify_chain(%s)", (family,)).fetchone()[0] is True


def test_verification_does_not_depend_on_session_time_zone(svc):
    add_operator_event(svc)
    for zone in ("UTC", "Australia/Adelaide", "Asia/Kathmandu"):
        svc.execute(f"SET TIME ZONE '{zone}'")
        assert verify(svc)[0] is True


def test_an_auditor_can_verify_outside_the_database_from_the_export(svc):
    add_operator_event(svc, reason="Unicode check: é — 選")
    add_operator_event(svc)
    previous = GENESIS
    rows = svc.execute("SELECT * FROM audit.export_chain('operator_record')").fetchall()
    assert rows
    for _, canonical, prev_hash, event_hash in rows:
        assert bytes(prev_hash) == previous
        assert hashlib.sha256(previous + canonical.encode("utf-8")).digest() == bytes(event_hash)
        assert json.loads(canonical)["family"] == "operator_record"
        previous = bytes(event_hash)


def test_export_rejects_an_unknown_family(svc):
    with raises_sqlstate("EV301"):
        svc.execute("SELECT * FROM audit.export_chain('chain_head; DROP TABLE audit.chain_head')")


def test_detects_an_altered_record(db, svc):
    seq = add_operator_event(svc, reason="original")[0]
    add_operator_event(svc)
    ok, _, first_bad, reason = tamper_then_verify(
        db, svc, [f"UPDATE audit.operator_record SET reason = 'forged' WHERE seq = {seq}"]
    )
    assert ok is False and first_bad == seq and reason == "record altered"


def test_detects_a_deleted_record_in_the_middle(db, svc):
    seq = add_operator_event(svc)[0]
    add_operator_event(svc)
    ok, _, first_bad, reason = tamper_then_verify(
        db, svc, [f"DELETE FROM audit.operator_record WHERE seq = {seq}"]
    )
    assert ok is False and first_bad == seq and reason == "record missing"


def test_detects_a_deleted_tail(db, svc):
    seq = add_operator_event(svc)[0]
    ok, _, _, reason = tamper_then_verify(
        db, svc, [f"DELETE FROM audit.operator_record WHERE seq = {seq}"]
    )
    assert ok is False and reason == "chain does not reach its recorded head"


def test_detects_an_altered_record_whose_own_hash_was_recalculated(db, svc):
    """Fixing the altered record's hash still breaks the link from the record after it."""
    seq = add_operator_event(svc)[0]
    add_operator_event(svc)
    ok, _, first_bad, reason = tamper_then_verify(db, svc, [
        f"UPDATE audit.operator_record SET reason = 'forged' WHERE seq = {seq}",
        f"SET timezone = 'UTC'",
        f"UPDATE audit.operator_record t SET event_hash = sha256(t.prev_hash || convert_to("
        f"audit.canonical('operator_record', to_jsonb(t)), 'UTF8')) WHERE seq = {seq}",
    ])
    assert ok is False
    assert first_bad == seq + 1
    assert reason == "previous hash does not match"


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("template", ["UPDATE audit.{} SET seq = 0", "DELETE FROM audit.{}", "TRUNCATE audit.{}"])
def test_audit_svc_cannot_rewrite_history(svc, family, template):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        svc.execute(template.format(family))


@pytest.mark.parametrize("statement", [
    "UPDATE audit.chain_head SET last_seq = 0",
    "DELETE FROM audit.chain_head",
    "INSERT INTO audit.chain_head (family) VALUES ('x')",
])
def test_audit_svc_cannot_touch_the_chain_head(svc, statement):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        svc.execute(statement)


@pytest.mark.parametrize("statement", [
    "UPDATE audit.operator_record SET reason = 'x'",
    "DELETE FROM audit.operator_record",
    "TRUNCATE audit.operator_record",
])
def test_even_the_superuser_hits_the_append_only_triggers(db, svc, statement):
    add_operator_event(svc)
    with raises_sqlstate("EV300"):
        db("audit", "postgres").execute(statement)


def test_concurrent_appends_keep_one_unbroken_chain(svc):
    def append(_):
        with connect("audit", "audit_svc") as conn:
            add_operator_event(conn)

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(append, range(40)))
    assert verify(svc)[0] is True


def test_failed_append_leaves_no_gap(svc):
    before = add_operator_event(svc)[0]
    with pytest.raises(psycopg.errors.CheckViolation):
        add_operator_event(svc, event_type="MADE_UP_EVENT")
    assert add_operator_event(svc)[0] == before + 1
    assert verify(svc)[0] is True


# ---------------------------------------------------------------- the GR02 split

def columns_of(conn, table):
    return {row[0] for row in conn.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'audit' AND table_name = %s", (table,),
    )}


def test_authorisation_record_cannot_hold_a_nonce_or_ballot(svc):
    assert not {c for c in columns_of(svc, "authorisation_record") if "nonce" in c or "ballot" in c}


def test_nonce_record_cannot_hold_an_elector_or_ballot(svc):
    assert not {c for c in columns_of(svc, "nonce_record")
                if "enrol" in c or "elector" in c or "ballot" in c}


def test_no_audit_table_can_hold_a_ballot_reference(svc):
    for family in FAMILIES:
        assert "ballot_ref" not in columns_of(svc, family)


def test_consumption_is_recorded_without_an_enrolment(svc):
    svc.execute(
        "INSERT INTO audit.nonce_record (event_type, nonce, election_id) VALUES ('AUTHORISATION_CONSUMED', %s, %s)",
        (new_nonce(), unique_id("EL")),
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        svc.execute(
            "INSERT INTO audit.authorisation_record (event_type, enrolment_id, election_id) "
            "VALUES ('AUTHORISATION_CONSUMED', 'E-1', 'EL-1')"
        )


def test_each_family_has_its_own_chain(svc):
    heads = dict(svc.execute("SELECT seq, event_hash FROM audit.export_chain('operator_record')").fetchall())
    before = len(heads)
    svc.execute(
        "INSERT INTO audit.authorisation_record (event_type, enrolment_id, election_id) "
        "VALUES ('AUTHORISATION_ISSUED', %s, %s)", (unique_id("E"), unique_id("EL")),
    )
    assert len(svc.execute("SELECT seq FROM audit.export_chain('operator_record')").fetchall()) == before
    assert verify(svc, "authorisation_record")[0] is True


def test_family_name_is_part_of_what_gets_hashed(db):
    """Identical contents give different text per chain, so a record cannot move between them."""
    admin = db("audit", "postgres")
    row = '{"seq": 1, "event_type": "X", "prev_hash": "a", "event_hash": "b"}'
    one, other = admin.execute(
        "SELECT audit.canonical('operator_record', %s::jsonb), audit.canonical('query_record', %s::jsonb)",
        (row, row),
    ).fetchone()
    assert one != other
    assert "prev_hash" not in one and "event_hash" not in one
