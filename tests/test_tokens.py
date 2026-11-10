import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from common import tokens
from common.tokens import SignatureInvalid, TokenError, TokenExpired

LATER = datetime.now(timezone.utc) + timedelta(hours=8)
NSW = {"election_id": "SEN2028", "state": "NSW"}


def official(role="COUNT_OPERATOR", step_up=None):
    return tokens.issue_official_token("co.nsw", role, NSW, "session-1", LATER, step_up)


def test_official_token_envelope_and_claims(as_service):
    """Milestone 2 Tables 4 and 8."""
    as_service("auth")
    token = official()
    as_service("ballot")
    claims = tokens.verify_official_token(token)
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "EdDSA" and len(header["kid"]) == 16
    assert claims["iss"] == "aec-auth" and claims["aud"] == "senate-voting-api"
    assert claims["principalType"] == "OFFICIAL"
    assert claims["operatorId"] == "co.nsw" and claims["role"] == "COUNT_OPERATOR"
    assert claims["mfaSatisfied"] is True and claims["stepUpAssertion"] is None
    assert claims["sessionId"] == "session-1" and "nbf" in claims


def test_elector_token_carries_only_nonce_and_state(as_service):
    """Table 5: the envelope plus two claims, and nothing that identifies the elector."""
    as_service("auth")
    token = tokens.issue_elector_token("NSW")
    as_service("ballot")
    claims = tokens.verify_elector_token(token)
    assert set(claims) == tokens.ELECTOR_CLAIMS
    assert claims["principalType"] == "ELECTOR" and claims["state"] == "NSW"
    assert len(claims["authorisationNonce"]) == 32  # 128 bits, hex


def test_edited_role_is_rejected(as_service):
    as_service("auth")
    header, payload, sig = official("AUDITOR").split(".")
    forged = jwt.utils.base64url_encode(
        jwt.utils.base64url_decode(payload).replace(b'"AUDITOR"', b'"COUNT_OPERATOR"')).decode()
    with pytest.raises(SignatureInvalid):
        tokens.verify_official_token(f"{header}.{forged}.{sig}")


def test_alg_none_and_hs256_are_rejected(as_service):
    s = as_service("auth")
    now = datetime.now(timezone.utc)
    claims = {"iss": "aec-auth", "aud": "senate-voting-api", "principalType": "OFFICIAL", "operatorId": "x",
              "role": "AUDITOR", "scope": {}, "mfaSatisfied": True, "stepUpAssertion": None, "sessionId": "s",
              "iat": now, "nbf": now, "exp": now + timedelta(minutes=5)}
    # Classic key-confusion attack: HMAC-sign with the PUBLIC key as the secret.
    pub_pem = (s.keys_dir / "auth_signing.pub").read_bytes()
    b64 = lambda d: jwt.utils.base64url_encode(json.dumps(d, default=lambda t: int(t.timestamp())).encode()).decode()  # noqa: E731
    signing_input = f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64(claims)}"
    mac = jwt.utils.base64url_encode(hmac.new(pub_pem, signing_input.encode(), hashlib.sha256).digest()).decode()
    for token in (jwt.encode(claims, None, algorithm="none"), f"{signing_input}.{mac}"):
        with pytest.raises(TokenError):
            tokens.verify_official_token(token)


def test_wrong_issuer_or_audience_rejected(as_service, keys_root):
    as_service("auth")
    key = serialization.load_pem_private_key((keys_root / "auth" / "auth_signing.key").read_bytes(), None)
    kid = tokens.key_id(key.public_key())
    now = datetime.now(timezone.utc)
    base = {"principalType": "ELECTOR", "authorisationNonce": "a" * 32, "state": "NSW",
            "iat": now, "nbf": now, "exp": now + timedelta(minutes=5)}
    for iss, aud in (("someone-else", "senate-voting-api"), ("aec-auth", "another-api")):
        token = jwt.encode({**base, "iss": iss, "aud": aud}, key, algorithm="EdDSA", headers={"kid": kid})
        with pytest.raises(SignatureInvalid):
            tokens.verify_elector_token(token)


def test_unknown_kid_rejected(as_service, keys_root):
    as_service("auth")
    key = serialization.load_pem_private_key((keys_root / "auth" / "auth_signing.key").read_bytes(), None)
    now = datetime.now(timezone.utc)
    token = jwt.encode({"iss": "aec-auth", "aud": "senate-voting-api", "principalType": "ELECTOR",
                        "authorisationNonce": "a" * 32, "state": "NSW", "iat": now, "nbf": now,
                        "exp": now + timedelta(minutes=5)}, key, algorithm="EdDSA", headers={"kid": "retired-key"})
    with pytest.raises(SignatureInvalid):
        tokens.verify_elector_token(token)


def test_expired_elector_token_reports_its_nonce(as_service, monkeypatch):
    s = as_service("auth")
    monkeypatch.setattr(s, "ballot_token_minutes", -1)
    token = tokens.issue_elector_token("NSW")
    with pytest.raises(TokenExpired) as exc:
        tokens.verify_elector_token(token)
    assert len(exc.value.claims["authorisationNonce"]) == 32  # so the refusal can be audited by nonce


def test_tokens_cannot_cross_principal_types(as_service):
    as_service("auth")
    elector, off = tokens.issue_elector_token("NSW"), official()
    with pytest.raises(TokenError):
        tokens.verify_official_token(elector)
    with pytest.raises(TokenError):
        tokens.verify_elector_token(off)


def test_service_token_allowed_caller(as_service):
    as_service("count")
    token = tokens.issue_service_token("ballot")
    as_service("ballot")
    assert tokens.verify_service_token(token, ["count"])["iss"] == "count"


def test_ballot_service_may_check_sessions_with_auth(as_service):
    as_service("ballot")
    token = tokens.issue_service_token("auth")
    as_service("auth")
    assert tokens.verify_service_token(token, ["ballot"])["iss"] == "ballot"


def test_service_token_wrong_caller_or_audience(as_service):
    as_service("recount")
    to_ballot = tokens.issue_service_token("ballot")
    to_count = tokens.issue_service_token("count")
    as_service("ballot")
    with pytest.raises(TokenError):
        tokens.verify_service_token(to_ballot, ["count"])  # recount may not call ballot
    as_service("count")
    with pytest.raises(TokenError):
        tokens.verify_service_token(to_ballot, ["recount"])  # audience is ballot, not count
    assert tokens.verify_service_token(to_count, ["recount"])["iss"] == "recount"


def test_service_cannot_impersonate_another(as_service, keys_root):
    """recount signs a token claiming to be count: signature check against count.pub fails."""
    recount_key = serialization.load_pem_private_key((keys_root / "recount" / "service.key").read_bytes(), None)
    now = datetime.now(timezone.utc)
    forged = jwt.encode({"iss": "count", "aud": "ballot", "typ": "service", "iat": now,
                         "exp": now + timedelta(seconds=60), "jti": "x"}, recount_key, algorithm="EdDSA")
    as_service("ballot")
    with pytest.raises(TokenError):
        tokens.verify_service_token(forged, ["count"])
