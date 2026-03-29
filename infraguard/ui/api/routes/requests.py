"""Request log API routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.tracking.stats import StatsQuery


async def get_requests(request: Request) -> JSONResponse:
    """GET /api/requests - paginated request log."""
    stats_query: StatsQuery = request.app.state.stats_query
    limit = min(int(request.query_params.get("limit", "50")), 200)
    domain = request.query_params.get("domain")

    rows = await stats_query.recent_requests(limit=limit, domain=domain)
    return JSONResponse({"requests": rows, "count": len(rows)})
