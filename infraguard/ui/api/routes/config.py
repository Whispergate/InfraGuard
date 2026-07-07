"""Configuration API routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.config.schema import InfraGuardConfig


def _sanitize_config(obj):
    """Recursively redact sensitive fields (token, secret, password, key)."""
    _SENSITIVE_PATTERNS = ("token", "secret", "password", "key")
    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            if any(p in k.lower() for p in _SENSITIVE_PATTERNS):
                sanitized[k] = "***" if v else None
            else:
                sanitized[k] = _sanitize_config(v)
        return sanitized
    elif isinstance(obj, list):
        return [_sanitize_config(item) for item in obj]
    return obj


async def get_config(request: Request) -> JSONResponse:
    """GET /api/config - return current configuration (sanitized)."""
    config: InfraGuardConfig = request.app.state.config

    # Sanitize: don't expose auth tokens
    config_dict = config.model_dump()
    if "api" in config_dict and "auth_token" in config_dict["api"]:
        config_dict["api"]["auth_token"] = "***" if config_dict["api"]["auth_token"] else None

    config_dict = _sanitize_config(config_dict)

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
