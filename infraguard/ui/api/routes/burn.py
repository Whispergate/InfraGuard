"""Burn confidence scoring API routes."""

from __future__ import annotations

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.intel.burn_scorer import BurnScorer

log = structlog.get_logger()


def _get_burn_scorer(request: Request) -> BurnScorer | None:
    """Return the burn scorer or None if not initialised."""
    return getattr(request.app.state, "burn_scorer", None)


async def _forward_burn(request: Request, path: str) -> JSONResponse | None:
    """Forward to the proxy when this process is the standalone
    dashboard container (no in-memory ``BurnScorer``). Same pattern as
    the health / config forwarders."""
    proxy_url = getattr(request.app.state, "proxy_api_url", None)
    if not proxy_url:
        return None
    import httpx
    url = proxy_url.rstrip("/") + path
    fwd_headers = {"Content-Type": "application/json"}
    if "authorization" in request.headers:
        fwd_headers["Authorization"] = request.headers["authorization"]
    else:
        cfg = getattr(getattr(request.app.state, "config", None), "api", None)
        tok = getattr(cfg, "auth_token", None) if cfg is not None else None
        if tok:
            fwd_headers["Authorization"] = f"Bearer {tok}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            resp = await client.get(
                url, headers=fwd_headers,
                cookies=dict(request.cookies),
                params=dict(request.query_params),
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
    except Exception as exc:
        log.debug("burn_forward_failed", url=url, error=str(exc))
        return None


_SCORER_UNAVAILABLE = JSONResponse(
    {"error": "Burn scoring subsystem not available"}, status_code=503
)


async def get_burn_score(request: Request) -> JSONResponse:
    """GET /api/burn/score/{domain} - get burn confidence score for one domain."""
    scorer = _get_burn_scorer(request)
    if scorer is None:
        domain = request.path_params.get("domain", "")
        forwarded = await _forward_burn(request, f"/api/burn/score/{domain}")
        if forwarded is not None:
            return forwarded
        return _SCORER_UNAVAILABLE

    domain = request.path_params.get("domain", "")
    if not domain:
        return JSONResponse({"error": "domain path parameter required"}, status_code=400)

    result = await scorer.compute_score(domain)
    return JSONResponse({
        "domain": result.domain,
        "score": result.score,
        "action": result.action,
        "signals": [
            {
                "signal_type": s.signal_type,
                "description": s.description,
                "weight": s.weight,
                "detected_at": s.detected_at,
            }
            for s in result.signals
        ],
        "evaluated_at": result.evaluated_at,
    })


async def get_burn_scores(request: Request) -> JSONResponse:
    """GET /api/burn/scores - get burn confidence scores for all configured domains."""
    scorer = _get_burn_scorer(request)
    if scorer is None:
        forwarded = await _forward_burn(request, "/api/burn/scores")
        if forwarded is not None:
            return forwarded
        return _SCORER_UNAVAILABLE

    config = request.app.state.config
    domains = list(config.domains.keys())
    results = await scorer.compute_all_scores(domains)

    return JSONResponse({
        "scores": {
            d: {
                "score": r.score,
                "action": r.action,
                "signal_count": len(r.signals),
                "evaluated_at": r.evaluated_at,
            }
            for d, r in results.items()
        },
    })
