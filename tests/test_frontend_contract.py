"""The endpoints the React frontend calls (frontend/src/api/client.ts): request and response
shapes, and that adapting to the frontend did not weaken any check.

Unit level only: no database or Docker. The full flow is exercised by the e2e smoke test.
"""
import json
import shutil

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from conftest import load_module

schemas = load_module("services/ballot/app/schemas.py")
grounds = load_module("services/recount/app/grounds.py")

TOKEN = "header.payload.signature"


def ballot(**overrides):
    body = {"authorisationToken": TOKEN, "electionId": "senate-2026", "state": "SA",
            "selections": [{"candidateId": "CAND-041", "rank": 1}], "configurationVersion": "cfg-abc"}
    return schemas.RankedBallot(**{**body, **overrides})


# --------------------------------------------------------------------------- ranked ballots
def test_single_choice_ballot_is_accepted():
    assert ballot().preferences() == ["CAND-041"]


def test_ranks_give_preference_order():
    b = ballot(selections=[{"candidateId": "CAND-063", "rank": 2}, {"candidateId": "CAND-041", "rank": 1}])
    assert b.preferences() == ["CAND-041", "CAND-063"]


@pytest.mark.parametrize("overrides", [
    {"selections": []},                                                         # nothing chosen
    {"selections": [{"candidateId": "CAND-041", "rank": 2}]},                   # does not start at 1
    {"selections": [{"candidateId": "CAND-041", "rank": 1},
                    {"candidateId": "CAND-042", "rank": 1}]},                   # repeated rank
    {"selections": [{"candidateId": "CAND-041", "rank": 1},
                    {"candidateId": "CAND-041", "rank": 2}]},                   # same candidate twice
    {"selections": [{"candidateId": "x; DROP TABLE", "rank": 1}]},              # bad candidate id
    {"state": "XX"},                                                            # not a state
    {"voterId": "SA-0001"},                                                     # no identity allowed in a ballot
])
def test_bad_ballots_are_rejected(overrides):
    with pytest.raises(ValidationError):
        ballot(**overrides)


# --------------------------------------------------------------------------- court order register
def test_demo_court_order_verifies(as_service):
    as_service("recount")
    document = grounds.verified_court_order("HC-2026-17")
    assert document["excluded_candidates"] == ["CAND-041"]
    assert (document["election_id"], document["state"]) == ("senate-2026", "SA")


def test_unknown_evidence_is_refused(as_service):
    as_service("recount")
    with pytest.raises(grounds.GroundsInvalid):
        grounds.verified_court_order("HC-9999-99")


def test_edited_register_entry_is_refused(as_service, keys_root, tmp_path, monkeypatch):
    """Editing the register (e.g. adding a candidate) breaks the court's signature."""
    folder = tmp_path / "recount"
    shutil.copytree(keys_root / "recount", folder)
    register = json.loads((folder / "court_orders.json").read_text())
    register["HC-2026-17"]["excluded_candidates"].append("CAND-063")
    (folder / "court_orders.json").write_text(json.dumps(register))

    as_service("recount")
    monkeypatch.setenv("SV_KEYS_DIR", str(folder))
    from common import keys, settings
    settings.get_settings.cache_clear()
    keys.clear_cache()
    with pytest.raises(grounds.GroundsInvalid):
        grounds.verified_court_order("HC-2026-17")


# --------------------------------------------------------------------------- error shape
def test_errors_use_the_frontend_shape(as_service):
    as_service("pdp")
    from common.app_factory import create_app

    app = create_app("test")

    @app.get("/limited")
    def limited():
        raise HTTPException(429, "Too many requests")

    @app.get("/denied")
    def denied():
        raise HTTPException(403, "Not allowed: outside scope")

    client = TestClient(app)
    r = client.get("/limited")
    assert r.status_code == 429 and r.headers["Retry-After"] == "60"
    assert r.json()["error"] == {"code": "RATE_LIMITED", "message": "Too many requests"}
    r = client.get("/denied")
    assert r.json()["error"]["code"] == "SCOPE_DENIED"
    assert r.json()["detail"] == "Not allowed: outside scope"   # older clients still work


# --------------------------------------------------------------------------- audit events
def test_audit_event_has_frontend_fields(as_service):
    as_service("audit")
    audit_main = load_module("services/audit/app/main.py", "svc_audit_main_contract")
    body = {"seq": 7, "recorded_at": "2026-11-10T05:01:00+00:00", "service": "count", "family": "CountRecord",
            "event_type": "COUNT_EXECUTED", "actor": "co.sa",
            "detail": {"electionId": "senate-2026", "contestState": "SA", "resultSha256": "ab" * 32}}
    event = audit_main._frontend_event(7, body, "prev", "hash", "sig")
    assert {k: event[k] for k in ("eventId", "eventType", "actorType", "actorId", "electionId", "state",
                                  "countId", "previousHash", "eventHash")} == {
        "eventId": "audit-000007", "eventType": "COUNT_EXECUTED", "actorType": "OFFICIAL", "actorId": "co.sa",
        "electionId": "senate-2026", "state": "SA", "countId": "count-senate-2026-SA",
        "previousHash": "prev", "eventHash": "hash"}


def test_ballot_events_expose_no_lookup_key(as_service):
    as_service("audit")
    audit_main = load_module("services/audit/app/main.py", "svc_audit_main_contract2")
    body = {"seq": 3, "recorded_at": "2026-11-10T05:01:00+00:00", "service": "ballot", "family": "BallotRecord",
            "event_type": "BALLOT_ACCEPTED", "actor": "anonymous", "detail": {"ballotReference": "uuid"}}
    event = audit_main._frontend_event(3, body, "p", "h", "s")
    assert event["actorType"] == "ELECTOR" and event["resourceId"] == "ballot"
