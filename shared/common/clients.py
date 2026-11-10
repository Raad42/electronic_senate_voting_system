"""Calls between services: mutual TLS for the connection, a signed service token for identity.

Every client FAILS CLOSED: if the PDP cannot be reached the answer is "deny", if Auth cannot
confirm a session the request is refused, and if the audit log cannot record a required event
the operation is refused.
"""
import ssl
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import httpx

from common.settings import get_settings
from common.tokens import issue_service_token


@lru_cache
def _tls_context() -> ssl.SSLContext:
    """Trust only the project CA, and present this service's certificate (mutual TLS)."""
    tls = get_settings().keys_dir / "tls"
    ctx = ssl.create_default_context(cafile=str(tls / "ca.crt"))
    ctx.load_cert_chain(str(tls / "service.crt"), str(tls / "service.key"))
    return ctx


def service_client(base_url: str, audience: str) -> httpx.Client:
    s = get_settings()
    return httpx.Client(
        base_url=s.scheme_url(base_url),
        timeout=s.http_timeout_seconds,
        headers={"Authorization": f"Bearer {issue_service_token(audience)}"},
        verify=_tls_context() if s.tls_enabled else True,
    )


# --------------------------------------------------------------------------- audit
class AuditUnavailable(RuntimeError):
    pass


class AuditClient:
    """Appends to the audit log. `family` is one of the record families in Milestone 2 Table 13."""

    def record(self, family: str, event_type: str, actor: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
        s = get_settings()
        try:
            with service_client(s.audit_url, "audit") as client:
                r = client.post("/internal/events", json={
                    "family": family,
                    "event_type": event_type,
                    "actor": actor,
                    "detail": detail or {},
                })
                r.raise_for_status()
                return r.json()
        except httpx.HTTPError as exc:
            raise AuditUnavailable(f"Audit log unavailable: {type(exc).__name__}") from None

    def try_record(self, family: str, event_type: str, actor: str, detail: dict[str, Any] | None = None) -> None:
        """For security events where the request is being rejected anyway."""
        try:
            self.record(family, event_type, actor, detail)
        except AuditUnavailable:
            pass

    def verify_chain(self) -> dict[str, Any]:
        """Figure 2: re-check the whole chain after a privileged action."""
        s = get_settings()
        try:
            with service_client(s.audit_url, "audit") as client:
                r = client.get("/internal/verify")
                r.raise_for_status()
                return r.json()
        except httpx.HTTPError as exc:
            raise AuditUnavailable(f"Audit log unavailable: {type(exc).__name__}") from None


# --------------------------------------------------------------------------- policy
@dataclass
class Decision:
    allow: bool
    reason: str
    code: str = "DENIED"


class PdpClient:
    def decide(self, action: str, subject: dict[str, Any], resource: dict[str, Any]) -> Decision:
        s = get_settings()
        try:
            with service_client(s.pdp_url, "pdp") as client:
                r = client.post("/internal/decide", json={
                    "action": action,
                    "subject": subject,
                    "resource": resource,
                })
                r.raise_for_status()
                body = r.json()
                return Decision(bool(body.get("allow")), str(body.get("reason", "")), str(body.get("code", "DENIED")))
        except (httpx.HTTPError, ValueError):
            return Decision(False, "policy service unavailable", "UNAVAILABLE")


# --------------------------------------------------------------------------- auth (sessions)
class AuthUnavailable(RuntimeError):
    pass


class AuthClient:
    """Server-side official sessions (Milestone 2 Table 11) live in Auth's database."""

    def _post(self, path: str, body: dict[str, Any]) -> httpx.Response:
        try:
            with service_client(get_settings().auth_url, "auth") as client:
                return client.post(path, json=body)
        except httpx.HTTPError as exc:
            raise AuthUnavailable(f"Authentication service unavailable: {type(exc).__name__}") from None

    def check_session(self, session_id: str, csrf_token: str | None) -> dict[str, Any]:
        """{"valid": bool, "reason": str}. Refreshes the idle timer when valid."""
        r = self._post("/internal/sessions/check", {"session_id": session_id, "csrf_token": csrf_token})
        if r.status_code != 200:
            raise AuthUnavailable("Authentication service error")
        return r.json()

    def issue_step_up(self, session_id: str, otp: str, action: str, resource: dict[str, Any]) -> tuple[int, dict]:
        """Step-up inside one request (used by Recount). Returns (status, body): 200 with
        {"stepUpAssertion": {...}}, or 401 / 429 with an error body (the session is ended on a wrong code)."""
        r = self._post("/internal/step-ups/issue",
                       {"session_id": session_id, "otp": otp, "action": action, "resource": resource})
        if r.status_code not in (200, 401, 422, 429):
            raise AuthUnavailable("Authentication service error")
        try:
            return r.status_code, r.json()
        except ValueError:
            raise AuthUnavailable("Authentication service error") from None

    def consume_step_up(self, session_id: str, step_up_id: str) -> bool:
        """Marks a step-up assertion used. False if it was already used (single use)."""
        r = self._post("/internal/step-ups/consume", {"session_id": session_id, "step_up_id": step_up_id})
        if r.status_code not in (200, 409):
            raise AuthUnavailable("Authentication service error")
        return r.status_code == 200


audit = AuditClient()
pdp = PdpClient()
auth = AuthClient()
