"""Builds every service's FastAPI app with the same safety defaults:

- no /docs or /openapi.json in production
- request bodies over max_body_bytes rejected with 413 before they are parsed
- unexpected errors return a generic 500 (details go to the log, never to the client)
- RecursionError from hostile JSON returns 400 instead of crashing the request
- security headers on every response, and /health for Docker health checks
"""
import logging
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from common.clients import AuditUnavailable
from common.settings import get_settings

log = logging.getLogger("senate")

# Error codes the frontend understands (frontend/src/pages/ResiliencePage.tsx).
ERROR_CODES = {
    400: "BAD_REQUEST",
    401: "AUTHENTICATION_REQUIRED",
    403: "SCOPE_DENIED",
    404: "NOT_FOUND",
    408: "STEP_UP_TIMEOUT",
    409: "CONFLICT",
    413: "PAYLOAD_TOO_LARGE",
    422: "VALIDATION_FAILED",
    429: "RATE_LIMITED",
    500: "INTERNAL_ERROR",
    502: "UPSTREAM_ERROR",
    503: "SERVICE_UNAVAILABLE",
}
RETRY_AFTER_SECONDS = 60


class ApiError(HTTPException):
    """An HTTP error with a specific machine-readable code, e.g. ApiError(409, "AUTHORISATION_REPLAY", "...")."""

    def __init__(self, status_code: int, code: str, message: str, headers: dict[str, str] | None = None):
        super().__init__(status_code, message, headers)
        self.code = code


def error_body(status_code: int, message: str, code: str | None = None, **extra: Any) -> dict[str, Any]:
    """{"error": {"code", "message"}} for the frontend, plus "detail" for older clients and tests."""
    return {"error": {"code": code or ERROR_CODES.get(status_code, f"HTTP_{status_code}"), "message": message},
            "detail": message, **extra}


def error_response(status_code: int, message: str, code: str | None = None,
                   headers: dict[str, str] | None = None, **extra: Any) -> JSONResponse:
    headers = dict(headers or {})
    if status_code == 429:
        headers.setdefault("Retry-After", str(RETRY_AFTER_SECONDS))
    return JSONResponse(error_body(status_code, message, code, **extra), status_code=status_code, headers=headers)


class BodySizeLimit(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        limit = get_settings().max_body_bytes
        declared = request.headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            return error_response(413, "Request body too large")
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()  # covers chunked bodies with no content-length
            if len(body) > limit:
                return error_response(413, "Request body too large")
        return await call_next(request)


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


def create_app(title: str) -> FastAPI:
    s = get_settings()
    docs = not s.is_production
    app = FastAPI(
        title=title,
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.add_middleware(SecurityHeaders)
    app.add_middleware(BodySizeLimit)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException):
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return error_response(exc.status_code, message, getattr(exc, "code", None), exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_request: Request, exc: RequestValidationError):
        errors = exc.errors()
        first = errors[0].get("msg", "Invalid request") if errors else "Invalid request"
        # Only messages and locations go back, never the submitted values.
        details = [{"loc": list(e.get("loc", ())), "msg": e.get("msg", "")} for e in errors]
        return JSONResponse({"error": {"code": "VALIDATION_FAILED", "message": first}, "detail": details},
                            status_code=422)

    @app.exception_handler(AuditUnavailable)
    async def _audit_down(_request: Request, _exc: AuditUnavailable):
        # Fail closed: an action that must be audited does not happen without its audit entry.
        return error_response(503, "Audit log unavailable; action refused")

    @app.exception_handler(RecursionError)
    async def _too_deep(_request: Request, _exc: RecursionError):
        return error_response(400, "Request is nested too deeply")

    @app.exception_handler(Exception)
    async def _unexpected(_request: Request, exc: Exception):
        ref = uuid.uuid4().hex[:12]
        log.exception("Unhandled error ref=%s", ref, exc_info=exc)
        return error_response(500, "Internal server error", ref=ref)

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok", "service": s.service_name}

    return app
