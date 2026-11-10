from typing import Any

from fastapi.responses import JSONResponse


def error_response(status: int, code: str, message: str, **headers: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "retryable": status in {429, 500, 503}}},
        headers=headers or None,
    )
