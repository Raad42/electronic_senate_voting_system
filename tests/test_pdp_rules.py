"""Milestone 2 Section 3.3: one rule per operation, default deny."""
from conftest import load_module

rules = load_module("services/pdp/app/rules.py")

NOW = 1_900_000_000
NSW = {"election_id": "SEN2028", "state": "NSW"}
VIC = {"election_id": "SEN2028", "state": "VIC"}


def official(role, step_up=None, scope=NSW, mfa=True):
    return {"principalType": "OFFICIAL", "operatorId": "x", "role": role, "scope": dict(scope or {}),
            "mfaSatisfied": mfa, "stepUpAssertion": step_up}


def assertion(action, resource, expires=NOW + 60):
    return {"id": "s1", "action": action, "resource": resource, "expiresAt": expires}


def decide(action, subject, resource):
    return rules.decide(action, subject, resource, now=NOW)


# ------------------------------------------------------------------ step-up actions
def test_start_count_allowed_with_bound_step_up():
    co = official("COUNT_OPERATOR", assertion("START_COUNT", NSW))
    assert decide("START_COUNT", co, NSW).allow


def test_step_up_required_for_the_four_irreversible_actions():
    for action, role in (("COMMIT_NOMINATIONS", "ELECTION_OFFICIAL"), ("FIX_PARTY_ORDER", "ELECTION_OFFICIAL"),
                         ("START_COUNT", "COUNT_OPERATOR")):
        d = decide(action, official(role), NSW)
        assert not d.allow and d.code == "STEP_UP_REQUIRED"


def test_step_up_for_another_action_or_resource_is_a_mismatch():
    wrong_action = official("COUNT_OPERATOR", assertion("COMMIT_NOMINATIONS", NSW))
    wrong_contest = official("COUNT_OPERATOR", assertion("START_COUNT", VIC))
    for subject in (wrong_action, wrong_contest):
        d = decide("START_COUNT", subject, NSW)
        assert not d.allow and d.code == "STEP_UP_MISMATCH"


def test_expired_step_up_times_out():
    co = official("COUNT_OPERATOR", assertion("START_COUNT", NSW, expires=NOW - 1))
    d = decide("START_COUNT", co, NSW)
    assert not d.allow and d.code == "STEP_UP_TIMEOUT"


def test_open_and_close_need_no_step_up():
    eo = official("ELECTION_OFFICIAL")
    assert decide("OPEN_VOTING", eo, NSW).allow and decide("CLOSE_VOTING", eo, NSW).allow


# ------------------------------------------------------------------ roles and scope
def test_wrong_role_denied():
    assert not decide("OPEN_VOTING", official("COUNT_OPERATOR"), NSW).allow
    assert not decide("START_COUNT", official("RECOUNT_DELEGATE", assertion("START_COUNT", NSW)), NSW).allow
    assert not decide("READ_AUDIT_LOG", official("ELECTION_OFFICIAL"), {}).allow


def test_scope_must_match_exactly():
    eo = official("ELECTION_OFFICIAL")
    d = decide("OPEN_VOTING", eo, VIC)
    assert not d.allow and d.code == "SCOPE"
    assert not decide("OPEN_VOTING", eo, {"election_id": "SEN2031", "state": "NSW"}).allow


def test_mfa_required():
    assert not decide("OPEN_VOTING", official("ELECTION_OFFICIAL", mfa=False), NSW).allow


def test_recount_delegate_step_up_names_the_candidates():
    resource = {**NSW, "candidates": ["NSW-B1", "NSW-A1"]}
    bound = assertion("ENTER_MANUAL_EXCLUSION", {**NSW, "candidates": ["NSW-A1", "NSW-B1"]})
    assert decide("ENTER_MANUAL_EXCLUSION", official("RECOUNT_DELEGATE", bound), resource).allow
    # A code issued to exclude one candidate cannot be used to exclude another.
    wider = {**NSW, "candidates": ["NSW-A1", "NSW-B1", "NSW-C1"]}
    assert decide("ENTER_MANUAL_EXCLUSION", official("RECOUNT_DELEGATE", bound), wider).code == "STEP_UP_MISMATCH"


def test_recount_delegate_other_state_denied():
    bound = assertion("ENTER_MANUAL_EXCLUSION", {**VIC, "candidates": ["VIC-A1"]})
    d = decide("ENTER_MANUAL_EXCLUSION", official("RECOUNT_DELEGATE", bound), {**VIC, "candidates": ["VIC-A1"]})
    assert not d.allow and d.code == "SCOPE"


def test_auditor_reads_but_nobody_queries_ballots_by_elector():
    assert decide("READ_AUDIT_LOG", official("AUDITOR", scope=None), {}).allow
    assert decide("VERIFY_AUDIT_LOG", official("AUDITOR", scope=None), {}).allow
    for role in ("AUDITOR", "ELECTION_OFFICIAL", "COUNT_OPERATOR", "RECOUNT_DELEGATE"):
        d = decide("QUERY_BALLOT_BY_ELECTOR_ID", official(role), {"electorId": "NSW-0001"})
        assert not d.allow and d.code == "QUERY_REFUSED"


# ------------------------------------------------------------------ electors
def test_submit_ballot_judged_on_capability_alone():
    elector = {"principalType": "ELECTOR", "state": "NSW", "authorisationNonce": "n" * 32}
    assert decide("SUBMIT_BALLOT", elector, {"state": "NSW", "status": "open"}).allow
    assert not decide("SUBMIT_BALLOT", elector, {"state": "VIC", "status": "open"}).allow
    assert not decide("SUBMIT_BALLOT", elector, {"state": "NSW", "status": "closed"}).allow
    assert not decide("SUBMIT_BALLOT", official("COUNT_OPERATOR"), {"state": "NSW", "status": "open"}).allow


def test_unknown_action_and_broken_input_denied():
    assert not decide("DELETE_EVERYTHING", official("AUDITOR"), {}).allow
    assert not decide("START_COUNT", None, None).allow
    assert not decide("ENTER_MANUAL_EXCLUSION", {**official("RECOUNT_DELEGATE"), "scope": None}, NSW).allow
