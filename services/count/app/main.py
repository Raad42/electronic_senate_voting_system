"""
Author: Raad
Edits:

Count service (GR05): START_COUNT (Milestone 2 Figure 2).

Only a COUNT_OPERATOR scoped to the contest, with a step-up assertion for START_COUNT on that
exact contest, may start it. The count is audited before and after it runs, the chain is then
re-verified, and only an intact chain releases the result. If the audit log is down the count
is refused.

Requirements:
    GR03 - only a count operator for this contest, with a step-up for START_COUNT, can start the count
    GR05 - the count is audited before and after it runs, and refused if the audit log is down

Run:
    docker compose up -d --build
    .venv/bin/python scripts/close_and_count.py

Usage example:
    Run close_and_count.py
    It signs in as co.sa, does the step-up and then asks this service to count

Output:
    The count runs and the result comes back once the audit chain checks out
    Trying before voting has closed gives "Counting starts only after voting closes"
"""
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, Field

from common.app_factory import create_app
from common.clients import AuditUnavailable, audit
from common.security import Official, authorise, require_service

from app.counting import contest_status, mark_counted, release_or_withhold, run_count

app = create_app("Count service")

ElectionId = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
State = Field(pattern=r"^(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)$")


class CountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    election_id: str = ElectionId
    state: str = State


class InternalRecountRequest(CountRequest):
    excluded_candidates: list[str] = Field(min_length=1, max_length=50)
    grounds_ref: str = Field(min_length=1, max_length=128)


def _summary(outcome: dict[str, Any]) -> dict[str, Any]:
    return {
        "electionId": outcome["election_id"],
        "contestState": outcome["state"],
        "elected": outcome["elected"],
        "quota": outcome["quota"],
        "formalBallots": outcome["formal_ballots"],
        "resultSha256": outcome["result_sha256"],
    }


@app.post("/counts")
def start_count(body: CountRequest, official: Official) -> dict[str, Any]:
    current = contest_status(body.election_id, body.state)
    if current != "closed":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "This contest has already been counted" if current == "counted"
                            else "Counting starts only after voting closes")
    contest = {"election_id": body.election_id, "state": body.state}
    authorise("START_COUNT", official, contest)
    actor = official["operatorId"]
    try:
        audit.record("CountRecord", "COUNT_STARTED", actor, {"electionId": body.election_id, "contestState": body.state})
        outcome = run_count(body.election_id, body.state)
        audit.record("CountRecord", "COUNT_EXECUTED", actor, _summary(outcome))
        released = release_or_withhold(outcome, actor)
    except AuditUnavailable:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Audit log unavailable; count refused") from None
    mark_counted(body.election_id, body.state)
    return released


@app.get("/internal/contests/{election_id}/{state}/status", dependencies=[Depends(require_service("recount"))])
def internal_contest_status(
    election_id: Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")],
    state: Annotated[str, Path(pattern=r"^(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)$")],
) -> dict[str, Any]:
    """Lets Recount check the recount phase is open BEFORE it uses up the delegate's step-up."""
    return {"status": contest_status(election_id, state)}


@app.post("/internal/recounts", dependencies=[Depends(require_service("recount"))])
def internal_recount(body: InternalRecountRequest) -> dict[str, Any]:
    """Called only by the Recount service, after it has verified the grounds and the delegate."""
    if contest_status(body.election_id, body.state) != "counted":
        raise HTTPException(status.HTTP_409_CONFLICT, "The recount phase is not open: this contest has no result yet")
    return run_count(body.election_id, body.state, set(body.excluded_candidates))
