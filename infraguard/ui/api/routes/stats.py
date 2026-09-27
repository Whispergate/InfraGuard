"""Statistics API routes."""

from __future__ import annotations

from ipaddress import ip_address

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.intel.feeds import get_feed_status
from infraguard.tracking.stats import StatsQuery


def _enrich_top_blocked_ips(top_blocked, app_state) -> list[dict]:
    """Attach country / lat / lon / asn to each top-blocked-IP row via
    the proxy's ``IntelManager`` GeoIP databases. The Command Post's
    Fleet Map uses these coordinates to plot blocked sources.
    """
    # Prefer the router's IntelManager (proxy in-process), fall back to
    # the standalone dashboard's own IntelManager which
    # ``dashboard_cmd`` attaches as ``intel_manager``.
    intel = getattr(getattr(app_state, "router", None), "intel", None)
    if intel is None:
        intel = getattr(app_state, "intel_manager", None)
    geoip = getattr(intel, "geoip", None) if intel is not None else None
    out: list[dict] = []
    for ip, count in top_blocked:
        row: dict = {"ip": ip, "count": count}
        if geoip is not None:
            try:
                # Validate the IP is well-formed before hitting the
                # MaxMind reader; the lookup itself takes a string.
                ip_address(ip)
                info = geoip.lookup(ip)
                if info is not None:
                    if info.latitude is not None and info.longitude is not None:
                        row["lat"] = float(info.latitude)
                        row["lon"] = float(info.longitude)
                    if info.country_code:
                        row["country"] = info.country_code
                    if info.asn:
                        row["asn"] = info.asn
                    if info.city:
                        row["city"] = info.city
            except Exception:
                pass
        out.append(row)
    return out


async def get_content_stats(request: Request) -> JSONResponse:
    """GET /api/stats/content -- content delivery statistics."""
    stats_query: StatsQuery = request.app.state.stats_query
    try:
        hours = int(request.query_params.get("hours", "24"))
        hours = max(1, min(hours, 8760))  # Clamp to 1 hour - 1 year
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid hours parameter"}, status_code=400)
    rows = await stats_query.content_stats(hours=hours)
    return JSONResponse({"content_routes": rows, "count": len(rows)})


async def get_stats(request: Request) -> JSONResponse:
    """GET /api/stats - overview statistics.

    Includes a `filter_reasons` bucket (reason string -> count) so the
    Overview dashboard's Filter Pipeline scorecard can show which filter
    is doing the work without a second request.
    """
    stats_query: StatsQuery = request.app.state.stats_query
    try:
        hours = int(request.query_params.get("hours", "24"))
        hours = max(1, min(hours, 8760))  # Clamp to 1 hour - 1 year
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid hours parameter"}, status_code=400)
    stats = await stats_query.overview(hours=hours)

    # Aggregate filter_reason counts from the request log. Kept as a
    # separate query so the overview() dataclass stays untouched.
    filter_reasons: dict[str, int] = {}
    try:
        db = request.app.state.db
        rows = await db.fetchall(
            "SELECT filter_reason, COUNT(*) AS n "
            "FROM requests "
            "WHERE timestamp > datetime('now', ?) "
            "  AND filter_reason IS NOT NULL AND filter_reason != '' "
            "GROUP BY filter_reason "
            "ORDER BY n DESC "
            "LIMIT 50",
            (f"-{hours} hours",),
        )
        for row in rows:
            filter_reasons[row["filter_reason"]] = row["n"]
    except Exception:
        pass

    return JSONResponse({
        "total_requests": stats.total_requests,
        "allowed_requests": stats.allowed_requests,
        "blocked_requests": stats.blocked_requests,
        "decoy_requests": stats.decoy_requests,
        "tarpit_requests": stats.tarpit_requests,
        "redirect_requests": stats.redirect_requests,
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
        "top_blocked_ips": _enrich_top_blocked_ips(
            stats.top_blocked_ips, request.app.state,
        ),
        "filter_reasons": filter_reasons,
        "feed_status": get_feed_status(),
    })
