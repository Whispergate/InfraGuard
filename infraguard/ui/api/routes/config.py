"""Configuration API routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.config.schema import InfraGuardConfig


async def get_config(request: Request) -> JSONResponse:
    """GET /api/config - return current configuration (sanitized)."""
    config: InfraGuardConfig = request.app.state.config

    # Sanitize: don't expose auth tokens
    config_dict = config.model_dump()
    if "api" in config_dict and "auth_token" in config_dict["api"]:
        config_dict["api"]["auth_token"] = "***" if config_dict["api"]["auth_token"] else None

    return JSONResponse(config_dict)


async def get_domains(request: Request) -> JSONResponse:
    """GET /api/config/domains - list configured domains."""
    config: InfraGuardConfig = request.app.state.config
    domains = {}
    for name, dc in config.domains.items():
        domains[name] = {
            "upstream": dc.upstream,
            "profile_type": dc.profile_type.value,
            "profile_path": dc.profile_path,
            "whitelist_cidrs": dc.whitelist_cidrs,
            "drop_action": dc.drop_action.model_dump(),
        }
    return JSONResponse({"domains": domains})
