"""
Author: Zak
Edits:

Signed tokens (EdDSA / Ed25519), following Milestone 2 Section 2.1.

Electors and officials get the same envelope (Table 4):
  iss = aec-auth, aud = senate-voting-api, a `kid` header naming the signing key, alg EdDSA
  only, principalType (ELECTOR or OFFICIAL), and iat / nbf / exp.

Then exactly one claim shape:
  ELECTOR  (Table 5) authorisationNonce + state, and nothing else: no elector identity (GR02).
  OFFICIAL (Table 8) operatorId, role, scope, mfaSatisfied, stepUpAssertion, sessionId. The
           session itself lives server-side in Auth; the token only points at it.

Only Auth holds the private signing key; every other service verifies with the public key.
Service-to-service tokens are separate: each service signs with its own key.

Requirements:
    GR01 - an elector token can be used once, because the Ballot service uses up its nonce
    GR02 - the elector token holds only a nonce and a state, never the voter's identity
    GR03 - official tokens carry the role, scope and step-up, and only EdDSA signatures are accepted

Run:
    python -m pytest tests/test_tokens.py -v

Usage example:
    token = issue_elector_token("SA")
    verify_elector_token(token)
    verify_official_token(token)

Output:
    verify_elector_token gives back the claims, which are just the issuer, audience, times, a
    random nonce and the state SA
    Passing it to verify_official_token raises SignatureInvalid because an elector token can't
    be used as an official one
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import jwt
from cryptography.hazmat.primitives import serialization

from common.keys import load_private, load_public, load_service_public
from common.settings import get_settings

ALGORITHM = "EdDSA"
AUDIENCE = "senate-voting-api"
ENVELOPE = {"iss", "aud", "iat", "nbf", "exp", "principalType"}
ELECTOR_CLAIMS = ENVELOPE | {"authorisationNonce", "state"}
OFFICIAL_CLAIMS = ENVELOPE | {"operatorId", "role", "scope", "mfaSatisfied", "stepUpAssertion", "sessionId"}


class TokenError(Exception):
    """Raised for any invalid, expired, mis-scoped or wrongly-shaped token."""


class SignatureInvalid(TokenError):
    """Bad signature, issuer, audience, algorithm or key id."""


class TokenExpired(TokenError):
    """Signature is fine but the token has expired. `claims` lets the caller audit the nonce."""

    def __init__(self, claims: dict[str, Any]):
        super().__init__("Token expired")
        self.claims = claims


def _now() -> datetime:
    return datetime.now(timezone.utc)


def key_id(public_key) -> str:
    """kid = first 16 hex chars of SHA-256 over the raw public key, so rotation needs no registry."""
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def _sign(claims: dict[str, Any]) -> str:
    key = load_private("auth_signing.key")
    return jwt.encode(claims, key, algorithm=ALGORITHM, headers={"kid": key_id(key.public_key())})


def _verify(token: str, verify_exp: bool = True) -> dict[str, Any]:
    public = load_public("auth_signing.pub")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise SignatureInvalid(str(exc)) from None
    if header.get("alg") != ALGORITHM or header.get("kid") != key_id(public):
        raise SignatureInvalid("Unknown algorithm or signing key")
    try:
        return jwt.decode(
            token,
            public,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=get_settings().token_issuer,
            options={"require": sorted(ENVELOPE), "verify_exp": verify_exp},
        )
    except jwt.ExpiredSignatureError:
        raise TokenError("Token expired") from None
    except jwt.PyJWTError as exc:
        raise SignatureInvalid(str(exc)) from None


def _envelope(principal_type: str, expires: datetime, issued: datetime | None = None) -> dict[str, Any]:
    issued = issued or _now()
    return {
        "iss": get_settings().token_issuer,
        "aud": AUDIENCE,
        "principalType": principal_type,
        "iat": issued,
        "nbf": issued,
        "exp": expires,
    }


# --------------------------------------------------------------------------- #
# Electors (Section 2.2)
# --------------------------------------------------------------------------- #
def issue_elector_token(state: str) -> str:
    now = _now()
    # Issue time rounded down to the hour, so it can't be matched against ballot arrival times.
    issued = now.replace(minute=0, second=0, microsecond=0)
    claims = _envelope("ELECTOR", now + timedelta(minutes=get_settings().ballot_token_minutes), issued)
    claims.update({"authorisationNonce": secrets.token_hex(16), "state": state})  # 128-bit nonce
    return _sign(claims)


def verify_elector_token(token: str) -> dict[str, Any]:
    claims = _verify(token, verify_exp=False)
    if claims.get("principalType") != "ELECTOR" or set(claims) != ELECTOR_CLAIMS:
        raise SignatureInvalid("Not an elector capability")
    if claims["exp"] <= _now().timestamp():
        raise TokenExpired(claims)
    return claims


# --------------------------------------------------------------------------- #
# Officials (Section 2.3)
# --------------------------------------------------------------------------- #
def issue_official_token(
    operator_id: str,
    role: str,
    scope: dict[str, str],
    session_id: str,
    expires: datetime,
    step_up: dict[str, Any] | None = None,
) -> str:
    claims = _envelope("OFFICIAL", expires)
    claims.update({
        "operatorId": operator_id,
        "role": role,
        "scope": scope,
        "mfaSatisfied": True,  # only issued after password + one-time code
        "stepUpAssertion": step_up,
        "sessionId": session_id,
    })
    return _sign(claims)


def verify_official_token(token: str) -> dict[str, Any]:
    claims = _verify(token)
    if claims.get("principalType") != "OFFICIAL" or set(claims) != OFFICIAL_CLAIMS:
        raise SignatureInvalid("Not an official token")
    return claims


# --------------------------------------------------------------------------- #
# Service-to-service
# --------------------------------------------------------------------------- #
def issue_service_token(audience: str) -> str:
    s = get_settings()
    now = _now()
    claims = {
        "iss": s.service_name,
        "aud": audience,
        "typ": "service",
        "iat": now,
        "exp": now + timedelta(seconds=s.service_token_seconds),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(claims, load_private("service.key"), algorithm=ALGORITHM)


def verify_service_token(token: str, allowed_callers: Iterable[str]) -> dict[str, Any]:
    try:
        caller = jwt.decode(token, options={"verify_signature": False}).get("iss", "")
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from None
    if caller not in set(allowed_callers):
        raise TokenError("Caller is not allowed to use this endpoint")
    try:
        key = load_service_public(caller)
    except Exception:
        raise TokenError("Unknown calling service") from None
    try:
        claims = jwt.decode(token, key, algorithms=[ALGORITHM], audience=get_settings().service_name,
                            issuer=caller, options={"require": ["iss", "aud", "iat", "exp", "jti", "typ"]})
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from None
    if claims.get("typ") != "service":
        raise TokenError("Not a service token")
    return claims
