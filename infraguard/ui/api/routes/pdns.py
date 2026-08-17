"""Passive DNS monitoring API routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.intel.passive_dns import PassiveDNSMonitor

_PDNS_UNAVAILABLE = JSONResponse(
    {"error": "Passive DNS monitoring not available"}, status_code=503
)


def _get_pdns(request: Request) -> PassiveDNSMonitor | None:
    """Return the PassiveDNSMonitor or None if not initialised."""
    return getattr(request.app.state, "pdns_monitor", None)


async def get_pdns_status(request: Request) -> JSONResponse:
    """GET /api/intel/pdns/status - PDNS monitor overview."""
    monitor = _get_pdns(request)
    if monitor is None:
        return _PDNS_UNAVAILABLE
    return JSONResponse(monitor.get_status())


async def get_pdns_events(request: Request) -> JSONResponse:
    """GET /api/intel/pdns/events - recent PDNS alert events."""
    monitor = _get_pdns(request)
    if monitor is None:
        return _PDNS_UNAVAILABLE
    try:
        limit = int(request.query_params.get("limit", "50"))
        limit = max(1, min(limit, 200))
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid limit parameter"}, status_code=400)
    events = monitor.get_events(limit=limit)
    return JSONResponse({"events": events, "count": len(events)})


async def get_pdns_history(request: Request) -> JSONResponse:
    """GET /api/intel/pdns/history/{domain} - DNS record history for a domain."""
    monitor = _get_pdns(request)
    if monitor is None:
        return _PDNS_UNAVAILABLE
    domain = request.path_params.get("domain", "").lower().strip()
    if not domain:
        return JSONResponse({"error": "Missing domain"}, status_code=400)
    history = monitor.get_history(domain)
    return JSONResponse({"domain": domain, "records": history, "count": len(history)})


async def clear_pdns_history(request: Request) -> JSONResponse:
    """DELETE /api/intel/pdns/history - clear PDNS history (re-baseline).

    Body: {"domain": "example.com"} to clear one domain, or omit/empty to
    clear all. Used after intentional DNS changes so the monitor stops
    alerting on records the operator just deployed.
    """
    monitor = _get_pdns(request)
    if monitor is None:
        return _PDNS_UNAVAILABLE
    try:
        body = await request.json()
    except Exception:
        body = {}
    domain = (body.get("domain") or "").strip() or None
    monitor.clear_history(domain)
    return JSONResponse({
        "status": "ok",
        "cleared": domain if domain else "all",
    })
