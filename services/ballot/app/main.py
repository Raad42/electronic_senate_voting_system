"""Ballot service (GR01, GR02).

Contest set-up (Milestone 2 Table 7): an ELECTION_OFFICIAL scoped to the state commits the
nominations and fixes the party order (both irreversible, so both need step-up), then opens and
closes voting.

Casting a vote is ONE transaction: the PDP judges SUBMIT_BALLOT on the capability alone, the
nonce is consumed (primary key, so a second use fails) and the ballot is stored sealed to the
Count service's key under a random reference. Ballots hold no elector id, nonce or timestamp,
and the Ballot service cannot read them.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Path, Query, status
from sqlalchemy import Connection, text

from common.app_factory import ApiError, create_app
from common.ballot_crypto import contest_aad, encrypt_ballot
from common.clients import audit
from common.db import transaction_dependency
from common.keys import load_public
from common.security import Elector, Official, authorise, elector_from_token, require_service
from common.settings import get_settings

from app.schemas import BallotSubmission, PartyOrder, RankedBallot, check_against_contest

app = create_app("Ballot service")
DB = Annotated[Connection, Depends(transaction_dependency(lambda: get_settings().database_url))]
CountService = Depends(require_service("count"))
ElectionId = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
State = Annotated[str, Path(pattern=r"^(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)$")]

STATUS_LABEL = {
    "nominations": "taking nominations",
    "nominations_committed": "nominations committed",
    "order_fixed": "party order fixed",
    "open": "open for voting",
    "closed": "closed",
    "counted": "counted",
}
# action -> (required status, new status, audit event)
LIFECYCLE = {
    "COMMIT_NOMINATIONS": ("nominations", "nominations_committed", "NOMINATIONS_COMMITTED"),
    "FIX_PARTY_ORDER": ("nominations_committed", "order_fixed", "PARTY_ORDER_FIXED"),
    "OPEN_VOTING": ("order_fixed", "open", "VOTING_OPENED"),
    "CLOSE_VOTING": ("open", "closed", "VOTING_CLOSED"),
}


def _contest(db: Connection, election_id: str, state: str) -> dict[str, Any]:
    head = db.execute(
        text("SELECT status, seats FROM contests WHERE election_id = :e AND state = :s"),
        {"e": election_id, "s": state},
    ).first()
    if head is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such contest")
    groups = db.execute(
        text("SELECT code, name FROM groups WHERE election_id = :e AND state = :s ORDER BY position"),
        {"e": election_id, "s": state},
    ).all()
    candidates = db.execute(
        text("""SELECT candidate_id, name, group_code FROM candidates
                 WHERE election_id = :e AND state = :s ORDER BY position"""),
        {"e": election_id, "s": state},
    ).all()
    return {
        "election_id": election_id,
        "state": state,
        "status": head.status,
        "seats": head.seats,
        "groups": [
            {"code": g.code, "name": g.name,
             "candidates": [c.candidate_id for c in candidates if c.group_code == g.code]}
            for g in groups
        ],
        "candidates": [{"id": c.candidate_id, "name": c.name, "group": c.group_code} for c in candidates],
    }


# --------------------------------------------------------------------------- public
@app.get("/elections/{election_id}/contests/{state}")
def ballot_paper(election_id: ElectionId, state: State, db: DB) -> dict[str, Any]:
    """The ballot paper and lifecycle status for one state (public information)."""
    return _contest(db, election_id, state)


@app.get("/elections/{election_id}/receipts/{state}")
def published_receipts(election_id: ElectionId, state: State, db: DB) -> dict[str, Any]:
    """After close, anyone can check their receipt is in this list."""
    if _contest(db, election_id, state)["status"] not in ("closed", "counted"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Receipts are published after voting closes")
    rows = db.execute(
        text("SELECT ballot_id FROM ballots WHERE election_id = :e AND state = :s ORDER BY ballot_id"),
        {"e": election_id, "s": state},
    ).scalars().all()
    return {"receipts": [str(r) for r in rows]}


def configuration_version(contest: dict[str, Any]) -> str:
    """Fingerprint of the ballot paper (groups, candidates and their order). A ballot submitted
    against an older version is refused, so nobody votes on a paper that has since changed."""
    paper = {"election_id": contest["election_id"], "state": contest["state"], "seats": contest["seats"],
             "groups": contest["groups"], "candidates": contest["candidates"]}
    digest = hashlib.sha256(json.dumps(paper, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return f"cfg-{digest[:12]}"


# --------------------------------------------------------------------------- frontend contract
@app.get("/ballots/config")
def ballot_config(db: DB,
                  state: Annotated[str, Query(pattern=r"^(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)$")],
                  electionId: Annotated[str, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")]) -> dict[str, Any]:
    """BallotConfig in frontend/src/types/api.ts. Published only once the party order is fixed."""
    contest = _contest(db, electionId, state)
    if contest["status"] in ("nominations", "nominations_committed"):
        raise HTTPException(status.HTTP_409_CONFLICT, "The ballot paper has not been finalised yet")
    party = {g["code"]: g["name"] for g in contest["groups"]}
    return {
        "electionId": electionId,
        "state": state,
        "configurationVersion": configuration_version(contest),
        "status": contest["status"],
        "seats": contest["seats"],
        "candidates": [
            {"candidateId": c["id"], "displayName": c["name"], "party": party.get(c["group"], "Ungrouped")}
            for c in contest["candidates"]
        ],
    }


@app.post("/ballots/ranked", status_code=status.HTTP_201_CREATED)
def submit_ranked_ballot(body: RankedBallot, db: DB) -> dict[str, str]:
    """BallotSubmission in frontend/src/types/api.ts. The capability travels in the body."""
    elector = elector_from_token(body.authorisationToken)
    if body.state != elector["state"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This authorisation is for a different state")
    head = db.execute(text("SELECT status FROM contests WHERE election_id = :e AND state = :s"),
                      {"e": body.electionId, "s": body.state}).first()
    resource = {"state": body.state, "status": head.status if head else "not open"}
    authorise("SUBMIT_BALLOT", elector, resource)

    contest = _contest(db, body.electionId, body.state)
    if body.configurationVersion != configuration_version(contest):
        raise ApiError(status.HTTP_409_CONFLICT, "CONFIGURATION_CHANGED",
                       "The ballot paper has changed. Reload it and vote again; your authorisation was not used.")
    preferences = body.preferences()
    if set(preferences) - {c["id"] for c in contest["candidates"]}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Ballot refers to candidates not in this contest")

    receipt = _cast(db, elector["authorisationNonce"], body.electionId, body.state, {"below_the_line": preferences})
    # Shown to the voter only; the ballot itself is stored with no time (GR02).
    submitted = datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat()
    return {"submissionId": receipt, "status": "ACCEPTED", "submittedAt": submitted}


# --------------------------------------------------------------------------- electors
@app.post("/ballots", status_code=status.HTTP_201_CREATED)
def submit_ballot(body: BallotSubmission, elector: Elector, db: DB) -> dict[str, str]:
    state = elector["state"]
    # The election context is decided server-side: the contest now open in the capability's state.
    open_contest = db.execute(
        text("SELECT election_id FROM contests WHERE state = :s AND status = 'open'"), {"s": state}
    ).first()
    resource = {"state": state, "status": "open" if open_contest else "not open"}
    authorise("SUBMIT_BALLOT", elector, resource)
    election_id = open_contest.election_id

    contest = _contest(db, election_id, state)
    try:
        check_against_contest(body, {g["code"] for g in contest["groups"]}, {c["id"] for c in contest["candidates"]})
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None

    return {"receipt": _cast(db, elector["authorisationNonce"], election_id, state, body.model_dump(exclude_none=True))}


def _cast(db: Connection, nonce: str, election_id: str, state: str, marks: dict[str, Any]) -> str:
    """Consume the nonce and store the sealed ballot in one transaction (GR01, GR02)."""
    consumed = db.execute(
        text("""INSERT INTO used_nonces (nonce, election_id) VALUES (:n, :e)
                ON CONFLICT DO NOTHING RETURNING nonce"""),
        {"n": nonce, "e": election_id},
    ).first()
    if consumed is None:
        audit.try_record("NonceRecord", "AUTHORISATION_REPLAY_REFUSED", "anonymous", {"nonce": nonce})
        raise ApiError(status.HTTP_409_CONFLICT, "AUTHORISATION_REPLAY",
                       "Refused: this authorisation has already been used")

    sealed = encrypt_ballot(marks, load_public("count_ballot.pub"), contest_aad(election_id, state))
    ballot_id = db.execute(
        text("INSERT INTO ballots (election_id, state, ciphertext) VALUES (:e, :s, :c) RETURNING ballot_id"),
        {"e": election_id, "s": state, "c": sealed},
    ).scalar_one()
    # Separate families: the nonce record and the ballot record share no field (Table 13).
    audit.record("NonceRecord", "AUTHORISATION_CONSUMED", "anonymous", {"nonce": nonce})
    audit.record("BallotRecord", "BALLOT_ACCEPTED", "anonymous", {"ballotReference": str(ballot_id)})
    # The receipt proves the ballot is in the box without revealing how it was marked.
    return str(ballot_id)


# --------------------------------------------------------------------------- officials
def _advance(db: Connection, action: str, official: dict, election_id: str, state: str,
             extra: dict[str, Any] | None = None) -> dict[str, str]:
    required, new, event = LIFECYCLE[action]
    current = _contest(db, election_id, state)["status"]
    if current != required:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"The contest is {STATUS_LABEL[current]}; it must be {STATUS_LABEL[required]} first")
    contest = {"election_id": election_id, "state": state}
    authorise(action, official, contest)
    db.execute(
        text("UPDATE contests SET status = :new WHERE election_id = :e AND state = :s AND status = :old"),
        {"new": new, "e": election_id, "s": state, "old": required},
    )
    audit.record("OperatorRecord", event, official["operatorId"],
                 {"role": official["role"], "action": action, "resource": contest, **(extra or {})})
    return {**contest, "status": new}


@app.post("/elections/{election_id}/contests/{state}/nominations/commit")
def commit_nominations(election_id: ElectionId, state: State, official: Official, db: DB) -> dict[str, str]:
    return _advance(db, "COMMIT_NOMINATIONS", official, election_id, state)


@app.post("/elections/{election_id}/contests/{state}/party-order")
def fix_party_order(election_id: ElectionId, state: State, body: PartyOrder, official: Official,
                    db: DB) -> dict[str, str]:
    groups = [g["code"] for g in _contest(db, election_id, state)["groups"]]
    if sorted(body.group_order) != sorted(groups):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "The order must list every group exactly once")
    result = _advance(db, "FIX_PARTY_ORDER", official, election_id, state, {"groupOrder": body.group_order})
    # Groups take their new positions; candidates follow their group, ungrouped candidates last.
    for pos, code in enumerate(body.group_order, 1):
        db.execute(text("UPDATE groups SET position = :p WHERE election_id = :e AND state = :s AND code = :c"),
                   {"p": pos, "e": election_id, "s": state, "c": code})
    rank = {code: i for i, code in enumerate(body.group_order)}
    cands = db.execute(text("""SELECT candidate_id, group_code FROM candidates
                                WHERE election_id = :e AND state = :s ORDER BY position"""),
                       {"e": election_id, "s": state}).all()
    ordered = sorted(cands, key=lambda c: rank.get(c.group_code, len(rank)))
    for pos, c in enumerate(ordered, 1):
        db.execute(text("""UPDATE candidates SET position = :p
                            WHERE election_id = :e AND state = :s AND candidate_id = :c"""),
                   {"p": pos, "e": election_id, "s": state, "c": c.candidate_id})
    return result


@app.post("/elections/{election_id}/contests/{state}/open")
def open_voting(election_id: ElectionId, state: State, official: Official, db: DB) -> dict[str, str]:
    return _advance(db, "OPEN_VOTING", official, election_id, state)


@app.post("/elections/{election_id}/contests/{state}/close")
def close_voting(election_id: ElectionId, state: State, official: Official, db: DB) -> dict[str, str]:
    return _advance(db, "CLOSE_VOTING", official, election_id, state)


@app.get("/ballots/by-elector/{elector_id}")
def ballot_by_elector(elector_id: Annotated[str, Path(pattern=r"^[A-Za-z0-9-]{1,32}$")],
                      official: Official) -> None:
    """QUERY_BALLOT_BY_ELECTOR_ID (Section 3.3): denied for every principal and audited as
    QUERY_REFUSED. There is nothing to return anyway: no ballot is stored against an elector."""
    authorise("QUERY_BALLOT_BY_ELECTOR_ID", official, {"electorId": elector_id})
    raise HTTPException(status.HTTP_403_FORBIDDEN, "Not allowed")  # unreachable: the rule always denies


# --------------------------------------------------------------------------- internal: Count service only
@app.get("/internal/contests/{election_id}/{state}", dependencies=[CountService])
def internal_contest(election_id: ElectionId, state: State, db: DB) -> dict[str, Any]:
    return _contest(db, election_id, state)


@app.get("/internal/ballots/{election_id}/{state}", dependencies=[CountService])
def internal_ballots(election_id: ElectionId, state: State, db: DB) -> dict[str, Any]:
    if _contest(db, election_id, state)["status"] not in ("closed", "counted"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Ballots are only released after voting closes")
    rows = db.execute(
        text("SELECT ciphertext FROM ballots WHERE election_id = :e AND state = :s ORDER BY ballot_id"),
        {"e": election_id, "s": state},
    ).scalars().all()
    return {"election_id": election_id, "state": state, "ballots": list(rows)}


@app.post("/internal/contests/{election_id}/{state}/counted", dependencies=[CountService])
def internal_mark_counted(election_id: ElectionId, state: State, db: DB) -> dict[str, str]:
    """A published result opens the recount phase."""
    db.execute(text("""UPDATE contests SET status = 'counted'
                        WHERE election_id = :e AND state = :s AND status = 'closed'"""),
               {"e": election_id, "s": state})
    return {"status": _contest(db, election_id, state)["status"]}
