"""Starlette handlers for Command Post's intel-sharing endpoints.

Wire from ``ui/command_post/app.py`` by registering the routes here.
Every handler operates against the module-level :data:`SHARED_INTEL`
singleton so all replicas that hit this Command Post see the same
state.
"""

from __future__ import annotations

import time

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from infraguard.ui.command_post.intel_sharing import SHARED_INTEL
from infraguard.ui.command_post.stix_publisher import make_bundle

# TAXII 2.1 requires a well-known collection id per feed. Keep it
# short and predictable so subscribers can hard-code it.
_TAXII_COLLECTION_ID = "infraguard-scanners"


async def post_intel_push(request: Request) -> JSONResponse:
    """POST /api/intel/push: a proxy node reports an IoC.

    Body: ``{"kind": "ip"|"ja3"|"ua", "value": "...",
             "source_node": "proxy-a", "reason": "..."}``
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid-json"}, status_code=400)
    kind = body.get("kind")
    value = body.get("value")
    source_node = body.get("source_node")
    if kind not in ("ip", "ja3", "ua") or not value or not source_node:
        return JSONResponse({"error": "missing-fields"}, status_code=400)
    entry = SHARED_INTEL.push(
        kind=kind,
        value=str(value),
        source_node=str(source_node),
        reason=str(body.get("reason", ""))[:500],
    )
    return JSONResponse({
        "status": "ok",
        "first_seen": entry.first_seen,
        "source_node": entry.source_node,
    })


async def get_intel_pull(request: Request) -> JSONResponse:
    """GET /api/intel/pull?since=<epoch>&kinds=ip,ja3.

    Returns every IoC added after ``since``. Peer proxies call this on
    a timer to pull the fleet-wide blocklist.
    """
    try:
        since = float(request.query_params.get("since", "0"))
    except ValueError:
        since = 0.0
    kinds_raw = request.query_params.get("kinds", "")
    kinds = [k.strip() for k in kinds_raw.split(",") if k.strip()] or None
    entries = SHARED_INTEL.pull_since(since, kinds=kinds)  # type: ignore[arg-type]
    return JSONResponse({
        "now": time.time(),
        "count": len(entries),
        "entries": [
            {
                "kind": e.kind,
                "value": e.value,
                "source_node": e.source_node,
                "first_seen": e.first_seen,
                "reason": e.reason,
            }
            for e in entries
        ],
    })


async def get_taxii_collection(request: Request) -> Response:
    """GET /taxii2/collections/{id}/objects/  (STIX 2.1 bundle).

    Publishes the fleet's IP indicators as a TAXII bundle. Subscribers
    poll this endpoint the same way they would a commercial threat
    feed. Only the fixed ``_TAXII_COLLECTION_ID`` is served; a proper
    multi-collection setup is a follow-up.
    """
    coll = request.path_params.get("collection_id")
    if coll != _TAXII_COLLECTION_ID:
        return JSONResponse({"error": "unknown-collection"}, status_code=404)
    ips = sorted({e.value for e in SHARED_INTEL.entries if e.kind == "ip"})
    bundle = make_bundle(ips, org_name="InfraGuard Command Post")
    return JSONResponse(
        bundle,
        headers={"content-type": "application/taxii+json;version=2.1"},
    )


__all__ = ["get_intel_pull", "get_taxii_collection", "post_intel_push"]
