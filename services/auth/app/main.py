from datetime import datetime, timedelta, timezone
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import FastAPI
from pydantic import BaseModel, Field

from shared.common.db import connection
from shared.common.http import error_response
from shared.common.tokens import issue_elector_token


app = FastAPI(title="Senate Auth Service", version="0.1.0")
password_hasher = PasswordHasher()
ELECTION_ID = re.compile(r"^[A-Z0-9-]{4,32}$")
STATES = {"ACT", "NSW", "NT", "QLD", "SA", "TAS", "VIC", "WA"}


class ElectorAuthorisationRequest(BaseModel):
    enrolmentId: str = Field(min_length=6, max_length=32, pattern=r"^[A-Z0-9-]+$")
    password: str = Field(min_length=1, max_length=256)
    electionId: str = Field(min_length=4, max_length=32, pattern=r"^[A-Z0-9-]+$")
    state: str = Field(min_length=2, max_length=3)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "auth"}


@app.post("/auth/elector/authorisation", status_code=200)
def issue_authorisation(request: ElectorAuthorisationRequest):
    if request.state not in STATES or not ELECTION_ID.fullmatch(request.electionId):
        return error_response(400, "INVALID_ELECTION_CONTEXT", "The election context is invalid.")

    try:
        with connection("ROLL_DATABASE_URL") as conn:
            row = conn.execute(
                "SELECT password_hash, state FROM roll.enrolment WHERE enrolment_id = %s",
                (request.enrolmentId,),
            ).fetchone()
            if not row or row[1] != request.state:
                return error_response(401, "AUTHENTICATION_FAILED", "The supplied credentials could not be verified.")
            try:
                password_hasher.verify(row[0], request.password)
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return error_response(401, "AUTHENTICATION_FAILED", "The supplied credentials could not be verified.")

            result = conn.execute(
                "SELECT roll.issue_authorisation(%s, %s, %s)",
                (request.enrolmentId, request.electionId, request.state),
            ).fetchone()[0]
    except RuntimeError:
        return error_response(503, "AUTH_SERVICE_UNAVAILABLE", "Authorisation is temporarily unavailable.")

    if result != "ISSUED":
        return error_response(401, "AUTHENTICATION_FAILED", "The supplied credentials could not be verified.")

    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(minutes=15)
    try:
        token = issue_elector_token(secrets.token_bytes(16), request.state, issued_at, expires_at)
    except RuntimeError:
        return error_response(503, "AUTH_SERVICE_UNAVAILABLE", "Authorisation is temporarily unavailable.")

    return {
        "authorisationToken": token,
        "state": request.state,
        "expiresAt": expires_at.isoformat(),
    }
