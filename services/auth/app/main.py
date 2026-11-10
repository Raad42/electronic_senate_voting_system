"""Auth service: the only service that authenticates anyone (Milestone 2 Section 2).

Electors (2.2): AEC voter ID + password for a state. On success the roll records THAT an
authorisation was issued, and the elector gets a single-use capability carrying only a random
nonce and the state. Electors hold no session and are never locked out (4.4).

Officials (2.3): password + one-time code, one active role per session. The session is held
server-side here (Table 11) and the signed token pointing at it travels in an HttpOnly,
Secure, SameSite=Strict cookie. Irreversible actions need a step-up assertion bound to that
action and resource, valid for two minutes, usable once.
"""
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import Connection, text

from common.app_factory import ApiError, create_app, error_body
from common.clients import audit
from common.db import transaction_dependency
from common.security import SESSION_COOKIE, STEP_UP_ACTIONS, csrf_from, official_claims, require_service
from common.settings import get_settings
from common.tokens import issue_elector_token, issue_official_token

from app import lockout

app = create_app("Auth service")
hasher = PasswordHasher()
# Verified when the account does not exist, so response time does not reveal valid names.
DUMMY_HASH = hasher.hash("not-a-real-password")

AuthDB = Annotated[Connection, Depends(transaction_dependency(lambda: get_settings().database_url))]
RollDB = Annotated[Connection, Depends(transaction_dependency(lambda: get_settings().roll_database_url))]

ROLES = r"^(ELECTION_OFFICIAL|COUNT_OPERATOR|RECOUNT_DELEGATE|AUDITOR)$"
STATES = r"^(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)$"
INVALID_LOGIN = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
LOCKED = HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts, try again later")
SESSION_ENDED = "Session has ended, sign in again"


class OfficialLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    otp: str = Field(pattern=r"^\d{6}$")
    role: str = Field(pattern=ROLES)


class StepUpResource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    election_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    state: str = Field(pattern=STATES)
    candidates: list[str] | None = Field(default=None, max_length=50)


class StepUpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    otp: str = Field(pattern=r"^\d{6}$")
    action: str
    resource: StepUpResource

    @model_validator(mode="after")
    def _known_action(self) -> "StepUpRequest":
        if self.action not in STEP_UP_ACTIONS:
            raise ValueError("Step-up is only issued for COMMIT_NOMINATIONS, FIX_PARTY_ORDER, START_COUNT "
                             "and ENTER_MANUAL_EXCLUSION")
        if (self.action == "ENTER_MANUAL_EXCLUSION") != bool(self.resource.candidates):
            raise ValueError("Candidates are named for ENTER_MANUAL_EXCLUSION, and only for it")
        return self


class ElectorAuthorise(BaseModel):
    model_config = ConfigDict(extra="forbid")
    voter_id: str = Field(min_length=4, max_length=32, pattern=r"^[A-Za-z0-9-]+$")
    password: str = Field(min_length=1, max_length=256)
    state: str = Field(pattern=STATES)
    election_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


class ElectorAuthorisation(BaseModel):
    """Frontend contract (frontend/src/api/client.ts: obtainElectorAuthorisation)."""
    model_config = ConfigDict(extra="forbid")
    state: str = Field(pattern=STATES)
    voterId: str = Field(min_length=4, max_length=32, pattern=r"^[A-Za-z0-9-]+$")
    password: str = Field(min_length=1, max_length=256)
    electionId: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


class StepUpIssue(BaseModel):
    """Internal: lets Recount run step-up inside the exclusion request (the recount screen
    collects the one-time code in the same form)."""
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(max_length=128)
    otp: str = Field(pattern=r"^\d{6}$")
    action: str
    resource: StepUpResource

    @model_validator(mode="after")
    def _known_action(self) -> "StepUpIssue":
        if self.action not in STEP_UP_ACTIONS:
            raise ValueError("unknown step-up action")
        return self


class SessionCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(max_length=128)
    csrf_token: str | None = Field(default=None, max_length=128)


class StepUpConsume(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(max_length=128)
    step_up_id: str = Field(max_length=128)


# --------------------------------------------------------------------------- helpers
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _otp_ok(conn: Connection, username: str, secret: str, otp: str, last_used: str | None) -> bool:
    """Valid TOTP code that has not been used before (blocks replay inside the time window)."""
    if not pyotp.TOTP(secret).verify(otp, valid_window=1) or otp == last_used:
        return False
    conn.execute(text("UPDATE officials SET last_otp = :o WHERE username = :u"), {"o": otp, "u": username})
    return True


def _password_ok(stored_hash: str, password: str) -> bool:
    try:
        return hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def _set_cookie(response: Response, token: str, expires: datetime) -> None:
    response.set_cookie(SESSION_COOKIE, token, expires=expires, path="/",
                        secure=True, httponly=True, samesite="strict")


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")


def _revoke(db: Connection, session_id: str, username: str, reason: str) -> None:
    db.execute(text("""UPDATE sessions SET revoked_at = now(), revoked_reason = :r
                        WHERE session_id = :s AND revoked_at IS NULL"""), {"s": session_id, "r": reason})
    audit.try_record("OperatorRecord", "SESSION_INVALIDATED", username, {"reason": reason})


def _live_session(db: Connection, session_id: str, csrf: str | None) -> tuple[Any, str]:
    """(row, "ok") for a live session, else (None, reason). Ends idle and expired sessions."""
    s = get_settings()
    row = db.execute(text("""
        SELECT s.session_id, s.username, s.role, s.csrf_token, s.last_seen, s.expires_at, s.revoked_at,
               s.step_up_id, s.step_up_used, r.scope_election, r.scope_state
          FROM sessions s JOIN official_roles r ON r.username = s.username AND r.role = s.role
         WHERE s.session_id = :s"""), {"s": session_id}).first()
    if row is None or row.revoked_at is not None:
        return None, "revoked"
    now = _now()
    if now >= row.expires_at:
        _revoke(db, session_id, row.username, "absolute timeout")
        return None, "expired"
    if now - row.last_seen > timedelta(minutes=s.session_idle_minutes):
        _revoke(db, session_id, row.username, "idle timeout")
        return None, "idle"
    if csrf is not None and not hmac.compare_digest(csrf, row.csrf_token):
        return None, "csrf"
    db.execute(text("UPDATE sessions SET last_seen = :n WHERE session_id = :s"), {"n": now, "s": session_id})
    return row, "ok"


def _scope(row) -> dict[str, str]:
    return {"election_id": row.scope_election, "state": row.scope_state} if row.scope_election else {}


def _session_view(row, step_up: dict | None = None) -> dict[str, Any]:
    return {
        "operatorId": row.username,
        "role": row.role,
        "scope": _scope(row),
        "csrfToken": row.csrf_token,
        "expiresAt": row.expires_at.isoformat(),
        "idleMinutes": get_settings().session_idle_minutes,
        "stepUpAssertion": step_up,
    }


def _ended(reason: str = SESSION_ENDED, code: int = status.HTTP_401_UNAUTHORIZED) -> JSONResponse:
    """Returned (not raised) so the request's transaction still commits any revocation."""
    response = JSONResponse(error_body(code, reason), status_code=code)
    _clear_cookie(response)
    return response


def _issue_step_up(db: Connection, row, otp: str, action: str, resource: StepUpResource) -> dict[str, Any] | None:
    """Checks a fresh one-time code and records a step-up assertion bound to this action and
    resource. Returns None (and ends the session, Table 11) if the code is wrong."""
    official = db.execute(text("SELECT totp_secret, last_otp FROM officials WHERE username = :u AND active"),
                          {"u": row.username}).first()
    if not official or not _otp_ok(db, row.username, official.totp_secret, otp, official.last_otp):
        lockout.record_failure(f"official:{row.username.lower()}")
        audit.try_record("OperatorRecord", "OPERATOR_MFA_FAILED", row.username,
                         {"role": row.role, "action": action, "reason": "step-up code rejected"})
        _revoke(db, row.session_id, row.username, "step-up failure")
        return None
    binding: dict[str, Any] = {"election_id": resource.election_id, "state": resource.state}
    if resource.candidates:
        binding["candidates"] = sorted(resource.candidates)
    step_up = {
        "id": secrets.token_urlsafe(16),
        "action": action,
        "resource": binding,
        "expiresAt": int((_now() + timedelta(seconds=get_settings().stepup_seconds)).timestamp()),
    }
    db.execute(text("UPDATE sessions SET step_up_id = :i, step_up_used = FALSE WHERE session_id = :s"),
               {"i": step_up["id"], "s": row.session_id})
    audit.record("OperatorRecord", "STEP_UP_ISSUED", row.username, {"action": action, "resource": binding})
    return step_up


# --------------------------------------------------------------------------- officials
@app.post("/officials/login")
def official_login(body: OfficialLogin, db: AuthDB, response: Response) -> dict[str, Any]:
    subject = f"official:{body.username.lower()}"
    if lockout.is_locked(subject):
        audit.try_record("OperatorRecord", "OPERATOR_MFA_FAILED", body.username, {"role": body.role, "reason": "locked"})
        raise LOCKED

    row = db.execute(
        text("""SELECT o.username, o.password_hash, o.totp_secret, o.last_otp, r.role, r.scope_election, r.scope_state
                  FROM officials o JOIN official_roles r ON r.username = o.username
                 WHERE o.username = :u AND r.role = :r AND o.active"""),
        {"u": body.username, "r": body.role},
    ).first()
    # Same work and the same answer whether the account, the role, the password or the code is wrong.
    password_ok = _password_ok(row.password_hash if row else DUMMY_HASH, body.password)
    if not row or not password_ok or not _otp_ok(db, row.username, row.totp_secret, body.otp, row.last_otp):
        lockout.record_failure(subject)
        audit.try_record("OperatorRecord", "OPERATOR_MFA_FAILED", body.username, {"role": body.role})
        raise INVALID_LOGIN

    lockout.clear_failures(subject)
    session_id, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    expires = _now() + timedelta(hours=get_settings().session_absolute_hours)
    db.execute(
        text("""INSERT INTO sessions (session_id, username, role, csrf_token, expires_at)
                VALUES (:s, :u, :r, :c, :e)"""),
        {"s": session_id, "u": row.username, "r": row.role, "c": csrf, "e": expires},
    )
    audit.record("OperatorRecord", "OPERATOR_AUTHENTICATED", row.username, {"role": row.role})
    _set_cookie(response, issue_official_token(row.username, row.role, _scope(row), session_id, expires), expires)
    return {
        "operatorId": row.username,
        "role": row.role,
        "scope": _scope(row),
        "csrfToken": csrf,
        "expiresAt": expires.isoformat(),
        "idleMinutes": get_settings().session_idle_minutes,
        "stepUpAssertion": None,
    }


@app.get("/officials/session")
def current_session(request: Request, db: AuthDB):
    """Lets the page pick the session back up after a reload (the cookie itself is unreadable to it)."""
    claims = official_claims(request)
    row, _reason = _live_session(db, claims["sessionId"], None)
    if row is None:
        return _ended()
    step_up = claims.get("stepUpAssertion") if not row.step_up_used else None
    return _session_view(row, step_up)


@app.post("/officials/step-up")
def official_step_up(body: StepUpRequest, request: Request, db: AuthDB):
    claims = official_claims(request)
    row, reason = _live_session(db, claims["sessionId"], csrf_from(request))
    if row is None:
        return _ended("CSRF token does not match", 403) if reason == "csrf" else _ended()

    if lockout.is_locked(f"official:{row.username.lower()}"):
        raise LOCKED
    step_up = _issue_step_up(db, row, body.otp, body.action, body.resource)
    if step_up is None:
        # Table 11: a failed step-up ends the session immediately.
        return _ended("Invalid code. For safety your session has been ended; sign in again.")

    token = issue_official_token(row.username, row.role, _scope(row), row.session_id, row.expires_at, step_up)
    response = JSONResponse(_session_view(row, step_up))
    _set_cookie(response, token, row.expires_at)
    return response


@app.post("/officials/logout")
def official_logout(request: Request, db: AuthDB):
    claims = official_claims(request)
    row, reason = _live_session(db, claims["sessionId"], csrf_from(request))
    if reason == "csrf":
        return _ended("CSRF token does not match", 403)
    if row is not None:
        _revoke(db, row.session_id, row.username, "logout")
    response = JSONResponse({"detail": "Signed out"})
    _clear_cookie(response)
    return response


@app.get("/session")
def frontend_session(request: Request, db: AuthDB):
    """Frontend contract (OfficialSession in frontend/src/types/api.ts). Also returns the CSRF
    token, which the page must echo in X-CSRF-Token on every state-changing request."""
    claims = official_claims(request)
    row, _reason = _live_session(db, claims["sessionId"], None)
    if row is None:
        return _ended()
    scope = _scope(row)
    return {
        "role": row.role,
        "sessionExpiresAt": row.expires_at.isoformat(),
        "scope": {
            "state": scope.get("state"),
            "electionId": scope.get("election_id"),
            # One count per contest in this prototype, so the count is named after the contest.
            "countId": f"count-{scope['election_id']}-{scope['state']}" if scope else None,
        },
        "operatorId": row.username,
        "csrfToken": row.csrf_token,
        "idleMinutes": get_settings().session_idle_minutes,
    }


# --------------------------------------------------------------------------- internal (other services)
@app.post("/internal/sessions/check", dependencies=[Depends(require_service("ballot", "count", "recount", "audit"))])
def check_session(body: SessionCheck, db: AuthDB) -> dict[str, Any]:
    row, reason = _live_session(db, body.session_id, body.csrf_token)
    return {"valid": row is not None, "reason": reason}


@app.post("/internal/step-ups/consume", dependencies=[Depends(require_service("ballot", "count", "recount"))])
def consume_step_up(body: StepUpConsume, db: AuthDB):
    used = db.execute(
        text("""UPDATE sessions SET step_up_used = TRUE
                 WHERE session_id = :s AND step_up_id = :i AND NOT step_up_used AND revoked_at IS NULL
             RETURNING username"""),
        {"s": body.session_id, "i": body.step_up_id},
    ).first()
    if used is None:
        return JSONResponse(error_body(409, "Step-up assertion already used"), status_code=409)
    audit.try_record("OperatorRecord", "STEP_UP_SATISFIED", used.username, {})
    return {"consumed": True}


@app.post("/internal/step-ups/issue", dependencies=[Depends(require_service("recount"))])
def internal_issue_step_up(body: StepUpIssue, db: AuthDB):
    """Step-up inside one request: same checks and same single-use assertion as /officials/step-up."""
    row, _reason = _live_session(db, body.session_id, None)
    if row is None:
        return JSONResponse(error_body(401, SESSION_ENDED), status_code=401)
    if lockout.is_locked(f"official:{row.username.lower()}"):
        return JSONResponse(error_body(429, "Too many failed attempts, try again later"), status_code=429)
    step_up = _issue_step_up(db, row, body.otp, body.action, body.resource)
    if step_up is None:
        return JSONResponse(error_body(401, "Invalid code. For safety your session has been ended; sign in again."),
                            status_code=401)
    return {"stepUpAssertion": step_up}


# --------------------------------------------------------------------------- electors
@app.post("/electors/authorise")
def elector_authorise(body: ElectorAuthorise, roll: RollDB) -> dict[str, Any]:
    return _authorise_elector(roll, body.voter_id, body.password, body.state, body.election_id)


@app.post("/elector/authorisation")
def frontend_elector_authorisation(body: ElectorAuthorisation, roll: RollDB) -> dict[str, Any]:
    """Frontend contract: {state, voterId, password, electionId?} -> {authorisationToken, state, expiresAt}."""
    election_id = body.electionId or get_settings().default_election_id
    result = _authorise_elector(roll, body.voterId, body.password, body.state, election_id)
    expires = _now() + timedelta(minutes=result["expires_in_minutes"])
    return {
        "authorisationToken": result["ballot_token"],
        "state": result["state"],
        "electionId": election_id,
        "expiresAt": expires.isoformat(),
    }


def _authorise_elector(roll: Connection, voter_id: str, password: str, state: str, election_id: str) -> dict[str, Any]:
    voter_id = voter_id.upper()
    # Only elections Auth knows are running. Without this, a voter could request one
    # authorisation per invented election id and vote several times (GR01).
    if election_id not in get_settings().active_election_ids:
        audit.try_record("AuthorisationRecord", "AUTHORISATION_REFUSED_UNKNOWN_ELECTION", "elector",
                         {"electionId": election_id, "state": state})
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No election with that id is running")
    elector = roll.execute(
        text("SELECT elector_id, password_hash, state, enrolled FROM electors WHERE elector_id = :id"),
        {"id": voter_id},
    ).first()
    password_ok = _password_ok(elector.password_hash if elector else DUMMY_HASH, password)
    # One generic answer for an unknown voter ID, a wrong password, or the wrong state (Table 12).
    if not (elector and password_ok and elector.enrolled and elector.state == state):
        audit.try_record("AuthorisationRecord", "AUTHORISATION_REFUSED_INVALID_CREDENTIALS", "elector",
                         {"enrolmentId": voter_id, "electionId": election_id, "state": state})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Voter ID or password is incorrect")

    issued = roll.execute(
        text("""INSERT INTO issuances (elector_id, election_id) VALUES (:id, :e)
                ON CONFLICT DO NOTHING RETURNING elector_id"""),
        {"id": elector.elector_id, "e": election_id},
    ).first()
    if issued is None:
        audit.try_record("AuthorisationRecord", "AUTHORISATION_REFUSED_ALREADY_VOTED", "elector",
                         {"enrolmentId": elector.elector_id, "electionId": election_id})
        raise ApiError(status.HTTP_409_CONFLICT, "ALREADY_VOTED", "A vote is already recorded against this enrolment")

    # Enrolment only, never the nonce: this record can't be joined to the ballot it leads to.
    audit.record("AuthorisationRecord", "AUTHORISATION_ISSUED", "elector",
                 {"enrolmentId": elector.elector_id, "electionId": election_id, "state": elector.state})
    return {
        "ballot_token": issue_elector_token(elector.state),
        "token_type": "bearer",  # nosec B105 - OAuth token type, not a secret
        "state": elector.state,
        "election_id": election_id,
        "expires_in_minutes": get_settings().ballot_token_minutes,
    }
