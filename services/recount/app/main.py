"""Recount service (GR03, GR05): ENTER_MANUAL_EXCLUSION.

Checks, in order: session -> PDP rule (RECOUNT_DELEGATE, exact election + state scope, step-up
bound to this action, contest and candidate list) -> court signature over the grounds -> audit
entry -> recount via the Count service (which also checks the recount phase is open) -> audit
entry -> chain verification before the result is released (Milestone 2 Figure 2).
"""
import uuid
from datetime import date
from typing import Any, Literal

import httpx
from fastapi import HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from common.app_factory import ApiError, create_app
from common.clients import AuditUnavailable, AuthUnavailable, audit, auth, pdp, service_client
from common.security import AUTH_DOWN, Official, authorise, subject_of
from common.settings import get_settings

from app.grounds import GroundsInvalid, grounds_document, verified_court_order, verify_grounds

app = create_app("Recount service")


class FrontendExclusion(BaseModel):
    """ExclusionRequest in frontend/src/types/api.ts, plus the step-up one-time code."""
    model_config = ConfigDict(extra="forbid")
    electionId: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    state: str = Field(pattern=r"^(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)$")
    candidateId: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    recountPhase: Literal["OPEN", "CLOSED"]
    exclusionGround: Literal["COURT_ORDER", "OTHER"]
    supportingEvidenceId: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    stepUpCode: str = Field(pattern=r"^\d{6}$")


def _rejected(reason: str, actor: str, record: dict[str, Any]) -> dict[str, Any]:
    """A request that was checked and refused. Nothing changed; the refusal is audited."""
    audit.try_record("CountRecord", "EXCLUSION_REFUSED", actor, {**record, "reason": reason})
    return {"status": "REJECTED", "reason": reason}


def _count(method: str, path: str, **kwargs) -> httpx.Response:
    try:
        with service_client(get_settings().count_url, "count") as client:
            return client.request(method, path, **kwargs)
    except httpx.HTTPError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Count service unavailable") from None


@app.post("/exclusions")
def frontend_exclusion(body: FrontendExclusion, official: Official) -> dict[str, Any]:
    """POST /api/recount/exclusions (frontend RecountPage).

    Order of checks, cheapest first, so a refused request never uses up a step-up code:
      1. the request asks for an open recount on a court-ordered ground;
      2. the evidence id is a registered court order with a valid court signature, for this
         election and state, naming this candidate;
      3. the contest has been counted (the recount phase is open);
      4. step-up with the one-time code, bound to ENTER_MANUAL_EXCLUSION on exactly these
         candidates; then the PDP checks role, MFA and scope, and the assertion is used up;
      5. audit, recount, audit, verify the chain, release.
    """
    actor = official["operatorId"]
    record = {"electionId": body.electionId, "contestState": body.state,
              "courtOrderRef": body.supportingEvidenceId, "excludedCandidates": [body.candidateId]}

    # Role, MFA and scope before anything else. If the only thing missing is the step-up, go on.
    precheck = pdp.decide("ENTER_MANUAL_EXCLUSION", subject_of({**official, "stepUpAssertion": None}),
                          {"election_id": body.electionId, "state": body.state, "candidates": [body.candidateId]})
    if precheck.code != "STEP_UP_REQUIRED":
        audit.try_record("CountRecord", "EXCLUSION_REFUSED", actor, {**record, "reason": precheck.reason})
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Not allowed: {precheck.reason}")

    if body.recountPhase != "OPEN":
        return _rejected("Exclusions can only be entered while the recount phase is open.", actor, record)
    if body.exclusionGround != "COURT_ORDER":
        return _rejected("Only exclusions ordered by the Court of Disputed Returns are accepted.", actor, record)
    try:
        document = verified_court_order(body.supportingEvidenceId)
    except GroundsInvalid as exc:
        return _rejected(f"Supporting evidence could not be verified: {exc}.", actor, record)
    if (document["election_id"], document["state"]) != (body.electionId, body.state):
        return _rejected(f"Court order {body.supportingEvidenceId} is for {document['state']} "
                         f"{document['election_id']}, not this contest.", actor, record)
    if body.candidateId not in document["excluded_candidates"]:
        return _rejected(f"Candidate {body.candidateId} is not named in court order "
                         f"{body.supportingEvidenceId}.", actor, record)

    r = _count("GET", f"/internal/contests/{body.electionId}/{body.state}/status")
    if r.status_code == 404:
        return _rejected("No such contest.", actor, record)
    if r.status_code != 200:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Count service error")
    if r.json().get("status") != "counted":
        return _rejected("The recount phase is not open: this contest has not been counted yet.", actor, record)

    # The court order may exclude several candidates; the recount applies all of them.
    excluded = document["excluded_candidates"]
    resource = {"election_id": body.electionId, "state": body.state, "candidates": excluded}
    try:
        code, issued = auth.issue_step_up(official["sessionId"], body.stepUpCode, "ENTER_MANUAL_EXCLUSION", resource)
    except AuthUnavailable:
        raise AUTH_DOWN from None
    if code != 200:
        message = (issued.get("error") or {}).get("message") or "Step-up failed"
        raise HTTPException(code if code in (401, 429) else 403, message)
    authorise("ENTER_MANUAL_EXCLUSION", {**official, "stepUpAssertion": issued["stepUpAssertion"]}, resource)

    outcome = _run_recount(actor, body.electionId, body.state, excluded, body.supportingEvidenceId,
                           document["issued_on"])
    return {
        "status": "APPROVED",
        "exclusionId": f"exc-{uuid.uuid4().hex[:12]}",
        "auditEventId": f"audit-{outcome['audit_seq']:06d}",
        "excludedCandidates": excluded,
        "elected": outcome["elected"],
        "chainVerified": outcome["chain_verified"],
    }


def _run_recount(actor: str, election_id: str, state: str, excluded: list[str], order_ref: str,
                 issued_on: str) -> dict[str, Any]:
    """Audit, recount through the Count service, audit, and verify the chain before release."""
    record = {"electionId": election_id, "contestState": state, "courtOrderRef": order_ref}
    try:
        entered = audit.record("CountRecord", "EXCLUSION_ENTERED", actor,
                               {**record, "excludedCandidates": excluded, "issuedOn": issued_on})
        r = _count("POST", "/internal/recounts", json={
            "election_id": election_id, "state": state, "excluded_candidates": excluded, "grounds_ref": order_ref,
        })
        if r.status_code != 200:
            raise HTTPException(r.status_code if r.status_code < 500 else 502,
                                r.json().get("detail", "Recount failed"))
        outcome = r.json()
        audit.record("CountRecord", "RECOUNT_EXECUTED", actor, {
            **record, "excludedCandidates": excluded, "elected": outcome["elected"],
            "resultSha256": outcome["result_sha256"],
        })
        chain = audit.verify_chain()
    except AuditUnavailable:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Audit log unavailable; recount refused") from None

    if not chain.get("ok"):
        audit.try_record("CountRecord", "RESULT_WITHHELD", actor, {
            **record, "reason": f"audit chain verification failed at entry {chain.get('first_bad_seq')}"})
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "INTEGRITY_FAILURE",
                       "Audit chain verification failed; the result has been withheld and reported")
    return {**outcome, "chain_verified": chain.get("checked"), "audit_seq": entered["seq"]}


class ExclusionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    election_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    state: str = Field(pattern=r"^(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)$")
    excluded_candidates: list[str] = Field(min_length=1, max_length=50)
    court_order_ref: str = Field(min_length=1, max_length=128)
    issued_on: date
    grounds_signature: str = Field(min_length=1, max_length=200)


@app.post("/recounts")
def enter_manual_exclusion(body: ExclusionRequest, official: Official) -> dict[str, Any]:
    resource = {"election_id": body.election_id, "state": body.state, "candidates": body.excluded_candidates}
    authorise("ENTER_MANUAL_EXCLUSION", official, resource)
    actor = official["operatorId"]
    record = {"electionId": body.election_id, "contestState": body.state, "courtOrderRef": body.court_order_ref}

    document = grounds_document(body.court_order_ref, body.election_id, body.state,
                                body.excluded_candidates, body.issued_on.isoformat())
    try:
        verify_grounds(document, body.grounds_signature)
    except GroundsInvalid as exc:
        audit.try_record("CountRecord", "EXCLUSION_REFUSED", actor, {**record, "reason": str(exc)})
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from None

    try:
        audit.record("CountRecord", "EXCLUSION_ENTERED", actor, {
            **record, "excludedCandidates": document["excluded_candidates"], "issuedOn": document["issued_on"],
        })
        with service_client(get_settings().count_url, "count") as client:
            r = client.post("/internal/recounts", json={
                "election_id": body.election_id,
                "state": body.state,
                "excluded_candidates": document["excluded_candidates"],
                "grounds_ref": body.court_order_ref,
            })
        if r.status_code != 200:
            raise HTTPException(r.status_code if r.status_code < 500 else 502,
                                r.json().get("detail", "Recount failed"))
        outcome = r.json()
        audit.record("CountRecord", "RECOUNT_EXECUTED", actor, {
            **record,
            "excludedCandidates": document["excluded_candidates"],
            "elected": outcome["elected"],
            "resultSha256": outcome["result_sha256"],
        })
        chain = audit.verify_chain()
    except AuditUnavailable:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Audit log unavailable; recount refused") from None
    except httpx.HTTPError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Count service unavailable") from None

    if not chain.get("ok"):
        audit.try_record("CountRecord", "RESULT_WITHHELD", actor, {
            **record, "reason": f"audit chain verification failed at entry {chain.get('first_bad_seq')}"})
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "Audit chain verification failed; the result has been withheld and reported")
    return {**outcome, "chain_verified": chain.get("checked")}
