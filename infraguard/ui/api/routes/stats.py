"""Statistics API routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.tracking.stats import StatsQuery


async def get_stats(request: Request) -> JSONResponse:
    """GET /api/stats - overview statistics."""
    stats_query: StatsQuery = request.app.state.stats_query
    hours = int(request.query_params.get("hours", "24"))
    stats = await stats_query.overview(hours=hours)

    return JSONResponse({
        "total_requests": stats.total_requests,
        "allowed_requests": stats.allowed_requests,
        "blocked_requests": stats.blocked_requests,
        "unique_ips": stats.unique_ips,
        "domains": [
            {
                "domain": d.domain,
                "total": d.total_requests,
                "allowed": d.allowed_requests,
                "blocked": d.blocked_requests,
                "unique_ips": d.unique_ips,
                "block_rate": round(d.block_rate, 3),
            }
            for d in stats.domains
        ],
        "top_blocked_ips": [
            {"ip": ip, "count": count} for ip, count in stats.top_blocked_ips
        ],
    })
