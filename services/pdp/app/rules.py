"""Policy rules: one function per operation (Milestone 2 Section 3.3). Pure Python, no I/O.

Default is DENY: an action with no rule, or a rule that does not explicitly allow, is refused.

Roles (Table 6), each scoped to one election and one state except AUDITOR:
  ELECTION_OFFICIAL   commits nominations, fixes party order, opens and closes voting
  COUNT_OPERATOR      starts the count
  RECOUNT_DELEGATE    enters court-ordered exclusions
  AUDITOR             reads and verifies the audit log, nothing else

Step-up (Table 7) is required for exactly COMMIT_NOMINATIONS, FIX_PARTY_ORDER, START_COUNT and
ENTER_MANUAL_EXCLUSION. The assertion must name this action and this exact resource, and must
not have expired. Single use is enforced by Auth when the action goes ahead.
"""
import time
from dataclasses import dataclass
from typing import Any, Callable

STATES = {"NSW", "VIC", "QLD", "WA", "SA", "TAS", "ACT", "NT"}
ROLE_NAMES = {
    "ELECTION_OFFICIAL": "an election official",
    "COUNT_OPERATOR": "a count operator",
    "RECOUNT_DELEGATE": "a recount delegate",
    "AUDITOR": "an auditor",
}


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    code: str = "DENIED"


ALLOW = Decision(True, "allowed", "ALLOWED")


def deny(reason: str, code: str = "DENIED") -> Decision:
    return Decision(False, reason, code)


def _contest(resource: dict[str, Any]) -> dict[str, str] | Decision:
    if not resource.get("election_id"):
        return deny("election_id is required")
    if resource.get("state") not in STATES:
        return deny("a valid state is required")
    return {"election_id": resource["election_id"], "state": resource["state"]}


def _official(subject: dict[str, Any], role: str, what: str) -> Decision | None:
    if subject.get("principalType") != "OFFICIAL" or subject.get("role") != role:
        return deny(f"only {ROLE_NAMES[role]} can {what}")
    if not subject.get("mfaSatisfied"):
        return deny("multi-factor authentication required")
    return None


def _in_scope(subject: dict[str, Any], contest: dict[str, str]) -> Decision | None:
    scope = subject.get("scope") or {}
    if scope.get("election_id") != contest["election_id"] or scope.get("state") != contest["state"]:
        return deny("outside this session's election and state scope", "SCOPE")
    return None


def _step_up(subject: dict[str, Any], action: str, binding: dict[str, Any], now: float) -> Decision | None:
    assertion = subject.get("stepUpAssertion")
    if not isinstance(assertion, dict):
        return deny("step-up authentication required", "STEP_UP_REQUIRED")
    if assertion.get("action") != action or assertion.get("resource") != binding:
        return deny("step-up was issued for a different action or resource", "STEP_UP_MISMATCH")
    expires = assertion.get("expiresAt")
    if not isinstance(expires, (int, float)) or expires <= now:
        return deny("step-up expired, so the action was not performed", "STEP_UP_TIMEOUT")
    return None


def _scoped_action(subject, resource, role: str, what: str) -> dict[str, str] | Decision:
    contest = _contest(resource)
    if isinstance(contest, Decision):
        return contest
    return _official(subject, role, what) or _in_scope(subject, contest) or contest


# --------------------------------------------------------------------------- rules
def submit_ballot(subject, resource, now) -> Decision:
    """Judged on the capability alone: it can't ask who is voting (Section 2.2)."""
    if subject.get("principalType") != "ELECTOR" or not subject.get("authorisationNonce"):
        return deny("an elector capability is required")
    if subject.get("state") != resource.get("state"):
        return deny("capability is for a different state")
    if resource.get("status") != "open":
        return deny("voting is not open for this contest")
    return ALLOW


def commit_nominations(subject, resource, now) -> Decision:
    contest = _scoped_action(subject, resource, "ELECTION_OFFICIAL", "commit nominations")
    if isinstance(contest, Decision):
        return contest
    return _step_up(subject, "COMMIT_NOMINATIONS", contest, now) or ALLOW


def fix_party_order(subject, resource, now) -> Decision:
    contest = _scoped_action(subject, resource, "ELECTION_OFFICIAL", "fix the party order")
    if isinstance(contest, Decision):
        return contest
    return _step_up(subject, "FIX_PARTY_ORDER", contest, now) or ALLOW


def open_voting(subject, resource, now) -> Decision:
    contest = _scoped_action(subject, resource, "ELECTION_OFFICIAL", "open voting")
    return contest if isinstance(contest, Decision) else ALLOW


def close_voting(subject, resource, now) -> Decision:
    contest = _scoped_action(subject, resource, "ELECTION_OFFICIAL", "close voting")
    return contest if isinstance(contest, Decision) else ALLOW


def start_count(subject, resource, now) -> Decision:
    contest = _scoped_action(subject, resource, "COUNT_OPERATOR", "start a count")
    if isinstance(contest, Decision):
        return contest
    return _step_up(subject, "START_COUNT", contest, now) or ALLOW


def enter_manual_exclusion(subject, resource, now) -> Decision:
    """GR03: the delegate's scope must match exactly, and the step-up names the candidates."""
    contest = _scoped_action(subject, resource, "RECOUNT_DELEGATE", "enter an exclusion")
    if isinstance(contest, Decision):
        return contest
    candidates = resource.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return deny("at least one candidate is required")
    binding = {**contest, "candidates": sorted(candidates)}
    return _step_up(subject, "ENTER_MANUAL_EXCLUSION", binding, now) or ALLOW


def read_audit_log(subject, resource, now) -> Decision:
    return _official(subject, "AUDITOR", "read the audit log") or ALLOW


def verify_audit_log(subject, resource, now) -> Decision:
    return _official(subject, "AUDITOR", "verify the audit log") or ALLOW


def query_ballot_by_elector_id(subject, resource, now) -> Decision:
    """GR02: no principal, including AUDITOR, may retrieve a ballot by elector identity."""
    return deny("ballots cannot be retrieved by elector identity", "QUERY_REFUSED")


RULES: dict[str, Callable[[dict[str, Any], dict[str, Any], float], Decision]] = {
    "SUBMIT_BALLOT": submit_ballot,
    "COMMIT_NOMINATIONS": commit_nominations,
    "FIX_PARTY_ORDER": fix_party_order,
    "OPEN_VOTING": open_voting,
    "CLOSE_VOTING": close_voting,
    "START_COUNT": start_count,
    "ENTER_MANUAL_EXCLUSION": enter_manual_exclusion,
    "READ_AUDIT_LOG": read_audit_log,
    "VERIFY_AUDIT_LOG": verify_audit_log,
    "QUERY_BALLOT_BY_ELECTOR_ID": query_ballot_by_elector_id,
}


def decide(action: str, subject: dict[str, Any], resource: dict[str, Any], now: float | None = None) -> Decision:
    rule = RULES.get(action)
    if rule is None:
        return deny(f"no rule for action '{action}'")
    try:
        return rule(subject or {}, resource or {}, time.time() if now is None else now)
    except Exception:  # a broken rule must never allow
        return deny("rule error")
