"""Request log API routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.tracking.stats import StatsQuery


async def get_requests(request: Request) -> JSONResponse:
    """GET /api/requests - paginated request log.

    Query params:
      * ``limit`` (1..500) - cap, default 50
      * ``domain`` - filter by domain
      * ``filter_result`` - a single verdict or comma-separated list
        (``canary_hit``, ``block``, ``decoy``, ``tarpit``, ...). Lets
        the Decoys page's Canary Hits panel pull just the rows it
        needs instead of scanning the top-N window.
    """
    stats_query: StatsQuery = request.app.state.stats_query
    try:
        limit = min(max(int(request.query_params.get("limit", "50")), 1), 500)
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid limit"}, status_code=400)
    domain = request.query_params.get("domain")
    filter_result = request.query_params.get("filter_result")

    rows = await stats_query.recent_requests(
        limit=limit, domain=domain, filter_result=filter_result,
    )
    return JSONResponse({"requests": rows, "count": len(rows)})
