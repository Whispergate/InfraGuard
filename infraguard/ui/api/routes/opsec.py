"""OPSEC auditor API route."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.config.schema import InfraGuardConfig
from infraguard.intel.opsec_auditor import run_audit


async def get_opsec_audit(request: Request) -> JSONResponse:
    """GET /api/health/opsec - run the OPSEC auditor against the live config."""
    config: InfraGuardConfig = request.app.state.config
    result = run_audit(config)
    return JSONResponse(result.to_dict())
