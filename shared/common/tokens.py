"""RS256 capability-token helpers.

The elector token intentionally contains no enrolment identifier. Configure
AUTH_PRIVATE_KEY_FILE for the auth service and AUTH_PUBLIC_KEY_FILE for the
ballot service. Services fail closed when keys are missing.
"""

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any

import jwt


ISSUER = os.environ.get("AUTH_TOKEN_ISSUER", "aec-auth")
AUDIENCE = os.environ.get("AUTH_TOKEN_AUDIENCE", "senate-voting-api")
KEY_ID = os.environ.get("AUTH_KEY_ID", "auth-key-1")


class TokenValidationError(ValueError):
    pass


def _key_from_env(file_variable: str, pem_variable: str) -> bytes:
    pem = os.environ.get(pem_variable)
    if pem:
        return pem.replace("\\n", "\n").encode()
    path = os.environ.get(file_variable)
    if path:
        return Path(path).read_bytes()
    raise RuntimeError(f"{file_variable} or {pem_variable} is not configured")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_elector_token(nonce: bytes, state: str, issued_at: datetime, expires_at: datetime) -> str:
    claims: dict[str, Any] = {
        "principalType": "ELECTOR",
        "authorisationNonce": _b64(nonce),
        "state": state,
        "issuedAt": issued_at.isoformat(),
        "expiresAt": expires_at.isoformat(),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    key = _key_from_env("AUTH_PRIVATE_KEY_FILE", "AUTH_PRIVATE_KEY_PEM")
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": KEY_ID, "typ": "JWT"})


def verify_elector_token(token: str) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or header.get("kid") != KEY_ID:
            raise TokenValidationError("untrusted token header")
        key = _key_from_env("AUTH_PUBLIC_KEY_FILE", "AUTH_PUBLIC_KEY_PEM")
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER)
        if claims.get("principalType") != "ELECTOR":
            raise TokenValidationError("wrong principal type")
        if claims.get("state") not in {"ACT", "NSW", "NT", "QLD", "SA", "TAS", "VIC", "WA"}:
            raise TokenValidationError("invalid state")
        nonce = _unb64(str(claims.get("authorisationNonce", "")))
        if len(nonce) != 16:
            raise TokenValidationError("invalid nonce")
        claims["_nonce_bytes"] = nonce
        return claims
    except (jwt.PyJWTError, ValueError, TypeError, KeyError) as error:
        raise TokenValidationError("invalid capability token") from error
