"""
Author: Zak
Edits:

FastAPI dependencies that turn a request into a checked caller (Milestone 2 Sections 2 and 3).

Officials: the signed token arrives in an HttpOnly cookie. Its signature is checked here, then
Auth confirms the server-side session is still live (idle / absolute timeout, revocation) and,
for state-changing requests, that the CSRF synchroniser token matches.

Electors: a single-use capability in the Authorization header. No cookie, no session.

Requirements:
    GR02 - an elector passed to the PDP carries no identity at all
    GR03 - every official request has its session, CSRF token and PDP decision checked, and a step-up works only once

Run:
    python -m pytest tests/test_tokens.py -v
    The tests cover the token checks
    The rest of this file runs inside each service once Docker is up

Usage example:
    @app.get("/events")
    def list_events(official: Official):
        authorise("READ_AUDIT_LOG", official, {})

Output:
    No session cookie gives "Invalid or expired credentials"
    A POST that has the cookie but no X-CSRF-Token header gives "Missing CSRF token"
"""
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from common.clients import AuthUnavailable, audit, auth, pdp
from common.tokens import TokenError, TokenExpired, verify_elector_token, verify_official_token, verify_service_token

SESSION_COOKIE = "__Host-sv_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Exactly these four actions need step-up (Milestone 2 Table 7 and Section 3.4).
STEP_UP_ACTIONS = {"COMMIT_NOMINATIONS", "FIX_PARTY_ORDER", "START_COUNT", "ENTER_MANUAL_EXCLUSION"}

bearer = HTTPBearer(auto_error=False)
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]

UNAUTHORISED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or expired credentials",
    headers={"WWW-Authenticate": "Bearer"},
)
FORBIDDEN = HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")
AUTH_DOWN = HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Authentication service unavailable")


# --------------------------------------------------------------------------- officials
def official_claims(request: Request) -> dict[str, Any]:
    """Signature and shape only. Auth uses this directly, since it holds the sessions itself."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise UNAUTHORISED
    try:
        return verify_official_token(token)
    except TokenError:
        raise UNAUTHORISED from None


def csrf_from(request: Request) -> str | None:
    if request.method in SAFE_METHODS:
        return None
    token = request.headers.get(CSRF_HEADER)
    if not token:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing CSRF token")
    return token


def current_official(request: Request) -> dict[str, Any]:
    claims = official_claims(request)
    csrf = csrf_from(request)
    try:
        session = auth.check_session(claims["sessionId"], csrf)
    except AuthUnavailable:
        raise AUTH_DOWN from None
    if not session.get("valid"):
        if session.get("reason") == "csrf":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token does not match")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session has ended, sign in again")
    return claims


Official = Annotated[dict[str, Any], Depends(current_official)]


# --------------------------------------------------------------------------- electors
def elector_capability(credentials: Credentials) -> dict[str, Any]:
    if credentials is None:
        raise UNAUTHORISED
    return elector_from_token(credentials.credentials)


def elector_from_token(token: str) -> dict[str, Any]:
    """Verifies an elector capability wherever it arrives (header or, for the frontend, the body)."""
    try:
        return verify_elector_token(token)
    except TokenExpired as exc:
        audit.try_record("NonceRecord", "AUTHORISATION_EXPIRED", "anonymous",
                         {"nonce": exc.claims.get("authorisationNonce")})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authorisation expired, please re-authenticate") from None
    except TokenError:
        audit.try_record("NonceRecord", "SIGNATURE_INVALID", "anonymous", {})
        raise UNAUTHORISED from None


Elector = Annotated[dict[str, Any], Depends(elector_capability)]


# --------------------------------------------------------------------------- services
def require_service(*allowed: str) -> Callable[..., dict[str, Any]]:
    """Internal endpoints: only the named services may call."""

    def dependency(credentials: Credentials) -> dict[str, Any]:
        if credentials is None:
            raise FORBIDDEN
        try:
            return verify_service_token(credentials.credentials, allowed)
        except TokenError:
            raise FORBIDDEN from None

    return dependency


# --------------------------------------------------------------------------- policy
def subject_of(claims: dict[str, Any]) -> dict[str, Any]:
    """The claims the PDP judges. An elector subject carries no identity at all (GR02)."""
    if claims.get("principalType") == "ELECTOR":
        return {"principalType": "ELECTOR", "state": claims["state"],
                "authorisationNonce": claims["authorisationNonce"]}
    return {
        "principalType": "OFFICIAL",
        "operatorId": claims["operatorId"],
        "role": claims["role"],
        "scope": claims.get("scope") or {},
        "mfaSatisfied": bool(claims.get("mfaSatisfied")),
        "stepUpAssertion": claims.get("stepUpAssertion"),
    }


def authorise(action: str, claims: dict[str, Any], resource: dict[str, Any]) -> None:
    """Ask the PDP; raise unless it explicitly allows. Step-up assertions are then used up."""
    decision = pdp.decide(action, subject_of(claims), resource)
    if not decision.allow:
        code = status.HTTP_408_REQUEST_TIMEOUT if decision.code == "STEP_UP_TIMEOUT" else status.HTTP_403_FORBIDDEN
        raise HTTPException(code, f"Not allowed: {decision.reason}")
    if action in STEP_UP_ACTIONS:
        try:
            fresh = auth.consume_step_up(claims["sessionId"], claims["stepUpAssertion"]["id"])
        except AuthUnavailable:
            raise AUTH_DOWN from None
        if not fresh:
            audit.try_record("OperatorRecord", "STEP_UP_MISMATCH", claims["operatorId"],
                             {"action": action, "reason": "step-up assertion already used"})
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Not allowed: step-up assertion already used")
