from datetime import datetime, timezone
import hashlib
import json
from uuid import UUID

import psycopg
from fastapi import FastAPI, Query
from pydantic import BaseModel, Field

from shared.common.ballot_crypto import encrypt_ballot
from shared.common.db import connection
from shared.common.http import error_response
from shared.common.tokens import TokenValidationError, verify_elector_token


app = FastAPI(title="Senate Ballot Service", version="0.1.0")


class Selection(BaseModel):
    candidateId: UUID
    rank: int = Field(ge=1, le=200)


class BallotSubmissionRequest(BaseModel):
    authorisationToken: str = Field(min_length=1)
    electionId: str = Field(min_length=4, max_length=32, pattern=r"^[A-Z0-9-]+$")
    state: str = Field(min_length=2, max_length=3)
    selections: list[Selection] = Field(min_length=1, max_length=200)
    configurationVersion: str = Field(min_length=8, max_length=128)


def configuration(conn: psycopg.Connection, election_id: str, state: str) -> dict:
    election = conn.execute(
        "SELECT election_id, state, phase::text FROM election.election WHERE election_id = %s",
        (election_id,),
    ).fetchone()
    if not election or election[1] != state:
        raise LookupError("election not found")
    candidates = conn.execute(
        "SELECT candidate_id::text, name FROM election.candidate "
        "WHERE election_id = %s ORDER BY candidate_id::text",
        (election_id,),
    ).fetchall()
    rows = [{"candidateId": row[0], "displayName": row[1]} for row in candidates]
    canonical = json.dumps({"electionId": election_id, "state": state, "phase": election[2], "candidates": rows}, separators=(",", ":"), sort_keys=True).encode()
    version = f"sha256:{hashlib.sha256(canonical).hexdigest()}"
    return {"electionId": election_id, "state": state, "phase": election[2], "configurationVersion": version, "candidates": rows}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ballot"}


@app.get("/ballots/config")
def get_ballot_config(state: str = Query(...), electionId: str = Query(...)):
    try:
        with connection("BALLOT_DATABASE_URL") as conn:
            data = configuration(conn, electionId, state)
    except LookupError:
        return error_response(404, "ELECTION_NOT_FOUND", "The requested election is not available.")
    except RuntimeError:
        return error_response(503, "BALLOT_SERVICE_UNAVAILABLE", "The ballot service is temporarily unavailable.")
    return data


@app.post("/ballots", status_code=201)
def submit_ballot(request: BallotSubmissionRequest):
    try:
        claims = verify_elector_token(request.authorisationToken)
    except (TokenValidationError, RuntimeError):
        return error_response(401, "AUTHORISATION_INVALID", "The ballot authorisation is invalid or expired.")
    if claims["state"] != request.state:
        return error_response(403, "STATE_SCOPE_DENIED", "The authorisation is not valid for this state.")
    ranks = sorted(selection.rank for selection in request.selections)
    if ranks != list(range(1, len(ranks) + 1)):
        return error_response(422, "INVALID_RANKS", "Ballot rankings must be consecutive and unique.")

    try:
        with connection("BALLOT_DATABASE_URL") as conn:
            config = configuration(conn, request.electionId, request.state)
            if config["configurationVersion"] != request.configurationVersion:
                return error_response(409, "CONFIGURATION_CHANGED", "The ballot configuration has changed. Reload the ballot.")
            allowed = {candidate["candidateId"] for candidate in config["candidates"]}
            if any(str(selection.candidateId) not in allowed for selection in request.selections):
                return error_response(422, "CANDIDATE_NOT_IN_ELECTION", "One or more selections are not valid for this election.")
            key_id, iv, ciphertext = encrypt_ballot(
                {"selections": [selection.model_dump(mode="json") for selection in request.selections]},
                request.electionId,
            )
            ballot_ref = conn.execute(
                "SELECT ballot.cast_ballot(%s, %s, %s, %s, %s, %s)",
                (claims["_nonce_bytes"], request.electionId, request.state, key_id, iv, ciphertext),
            ).fetchone()[0]
    except psycopg.Error as error:
        if error.sqlstate == "EV200":
            return error_response(422, "BALLOT_NOT_ACCEPTED", "The ballot cannot be accepted in the current election phase.")
        return error_response(503, "BALLOT_SERVICE_UNAVAILABLE", "The ballot service is temporarily unavailable.")
    except (LookupError, RuntimeError):
        return error_response(503, "BALLOT_SERVICE_UNAVAILABLE", "The ballot service is temporarily unavailable.")

    if ballot_ref is None:
        return error_response(409, "AUTHORISATION_REPLAY", "This single-use authorisation has already been consumed.")
    return {
        "submissionId": str(ballot_ref),
        "status": "ACCEPTED",
        "submittedAt": datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat(),
    }
