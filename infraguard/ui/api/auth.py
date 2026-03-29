"""Bearer token authentication for the API."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse


def check_auth(request: Request, expected_token: str | None) -> JSONResponse | None:
    """Validate bearer token. Returns error response or None if valid."""
    if not expected_token:
        return None  # Auth disabled

    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse({"error": "Missing authorization header"}, status_code=401)

    token = auth[7:]
    if token != expected_token:
        return JSONResponse({"error": "Invalid token"}, status_code=403)

    return None
