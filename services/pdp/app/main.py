"""Policy Decision Point: answers "is this allowed?" for the other services.

Internal only (not routed by Nginx). Callers authenticate with a service token. Every refusal
is written to the audit log (Section 3.6), in the record family that fits who was refused.
"""
from typing import Any

from fastapi import Depends
from pydantic import BaseModel, ConfigDict, Field

from common.app_factory import create_app
from common.clients import audit
from common.security import require_service

from app.rules import Decision, decide

app = create_app("PDP service")


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(max_length=64)
    subject: dict[str, Any]
    resource: dict[str, Any]


def _record_refusal(body: DecisionRequest, decision: Decision) -> None:
    subject = body.subject
    if decision.code == "QUERY_REFUSED":
        audit.try_record("QueryRecord", "QUERY_REFUSED", str(subject.get("operatorId") or "unknown"),
                         {"requesterId": subject.get("operatorId"), "query": {"action": body.action, **body.resource}})
    elif subject.get("principalType") == "ELECTOR":
        # Nonce only: an elector refusal never carries an enrolment (Table 13).
        audit.try_record("NonceRecord", "AUTHORISATION_DENIED", "anonymous",
                         {"nonce": subject.get("authorisationNonce"), "reason": decision.reason})
    else:
        event = decision.code if decision.code in ("STEP_UP_TIMEOUT", "STEP_UP_MISMATCH") else "AUTHORISATION_DENIED"
        audit.try_record("OperatorRecord", event, str(subject.get("operatorId") or "unknown")[:64],
                         {"role": subject.get("role"), "action": body.action, "resource": body.resource,
                          "reason": decision.reason})


@app.post("/internal/decide")
def decide_endpoint(
    body: DecisionRequest,
    _caller: dict = Depends(require_service("auth", "ballot", "count", "recount", "audit")),
) -> dict[str, Any]:
    decision = decide(body.action, body.subject, body.resource)
    if not decision.allow:
        _record_refusal(body, decision)
    return {"allow": decision.allow, "reason": decision.reason, "code": decision.code}
