"""IP intelligence API routes."""

from __future__ import annotations

from ipaddress import ip_address

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.intel.manager import IntelManager


async def classify_ip(request: Request) -> JSONResponse:
    """POST /api/intel/classify - classify an IP address."""
    intel: IntelManager = request.app.state.intel_manager
    body = await request.json()
    ip_str = body.get("ip", "")

    try:
        ip = ip_address(ip_str)
    except ValueError:
        return JSONResponse({"error": f"Invalid IP: {ip_str}"}, status_code=400)

    result = await intel.classify(ip)
    return JSONResponse({
        "ip": result.ip,
        "is_blocked": result.is_blocked,
        "is_whitelisted": result.is_whitelisted,
        "reason": result.reason,
        "rdns": result.rdns,
        "geo": {
            "country_code": result.geo.country_code if result.geo else None,
            "country_name": result.geo.country_name if result.geo else None,
            "city": result.geo.city if result.geo else None,
            "asn": result.geo.asn if result.geo else None,
            "org": result.geo.org if result.geo else None,
        } if result.geo else None,
    })


async def add_blocklist(request: Request) -> JSONResponse:
    """POST /api/intel/blocklist - add CIDRs to the blocklist."""
    intel: IntelManager = request.app.state.intel_manager
    body = await request.json()
    cidrs = body.get("cidrs", [])
    intel.blocklist.add_many(cidrs)
    return JSONResponse({"status": "ok", "blocklist_size": intel.blocklist.size})


async def remove_blocklist(request: Request) -> JSONResponse:
    """DELETE /api/intel/blocklist - remove an IP/CIDR from the blocklist."""
    intel: IntelManager = request.app.state.intel_manager
    body = await request.json()
    ip_str = body.get("ip", "")

    # Normalize to CIDR if it's a single IP
    cidr = ip_str if "/" in ip_str else f"{ip_str}/32"

    removed = intel.blocklist.remove(cidr)
    return JSONResponse({
        "status": "ok" if removed else "not_found",
        "ip": ip_str,
        "removed": removed,
        "blocklist_size": intel.blocklist.size,
    })


async def add_whitelist(request: Request) -> JSONResponse:
    """POST /api/intel/whitelist - dynamically whitelist an IP."""
    intel: IntelManager = request.app.state.intel_manager
    body = await request.json()
    ip_str = body.get("ip", "")

    try:
        ip_address(ip_str)
    except ValueError:
        return JSONResponse({"error": f"Invalid IP: {ip_str}"}, status_code=400)

    # Add to dynamic whitelist (survives for session, not persisted to config)
    intel.dynamic_whitelist._whitelisted.add(ip_str)

    return JSONResponse({
        "status": "ok",
        "ip": ip_str,
        "whitelisted": True,
    })
