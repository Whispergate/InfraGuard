"""Burn confidence scoring API routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.intel.burn_scorer import BurnScorer


def _get_burn_scorer(request: Request) -> BurnScorer | None:
    """Return the burn scorer or None if not initialised."""
    return getattr(request.app.state, "burn_scorer", None)


_SCORER_UNAVAILABLE = JSONResponse(
    {"error": "Burn scoring subsystem not available"}, status_code=503
)


async def get_burn_score(request: Request) -> JSONResponse:
    """GET /api/burn/score/{domain} - get burn confidence score for one domain."""
    scorer = _get_burn_scorer(request)
    if scorer is None:
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
