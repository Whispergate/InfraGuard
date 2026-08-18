"""Configuration API routes."""

from __future__ import annotations

from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.config.schema import InfraGuardConfig
from infraguard.models.common import (
    PHISHING_PROFILE_TYPES,
    TUNNEL_PROFILE_TYPES,
    DropActionType,
    ProfileType,
)


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
    router = getattr(request.app.state, "router", None)
    domains = {}
    for name, dc in config.domains.items():
        uris = []
        if router:
            route = router.routes.get(name)
            if route and route.profile:
                uris = route.profile.all_uris()
        domains[name] = {
            "upstream": dc.upstream,
            "profile_type": dc.profile_type.value,
            "profile_path": dc.profile_path,
            "whitelist_cidrs": dc.whitelist_cidrs,
            "drop_action": dc.drop_action.model_dump(),
            "uris": uris,
        }
    return JSONResponse({"domains": domains})


async def update_drop_action(request: Request) -> JSONResponse:
    """PATCH /api/config/domains/{domain}/drop-action - update drop action at runtime."""
    config: InfraGuardConfig = request.app.state.config
    domain = request.path_params["domain"]

    dc = config.domains.get(domain)
    if not dc:
        return JSONResponse({"error": f"Domain '{domain}' not found"}, status_code=404)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid request body"}, status_code=400)

    new_type = None
    if "type" in body:
        try:
            new_type = DropActionType(body["type"])
        except ValueError:
            valid = [t.value for t in DropActionType]
            return JSONResponse(
                {"error": f"Invalid drop action type. Valid: {valid}"},
                status_code=400,
            )

    effective_type = new_type if new_type is not None else dc.drop_action.type

    if "target" in body:
        target = body["target"]
        if not isinstance(target, str) or not target:
            return JSONResponse({"error": "Target must be a non-empty string"}, status_code=400)

        if effective_type == DropActionType.DECOY:
            pages_root = Path(config.decoy_pages_dir).resolve()
            target_path = (pages_root / target).resolve()
            try:
                target_path.relative_to(pages_root)
            except ValueError:
                return JSONResponse({"error": "Access denied"}, status_code=403)
            if not target_path.is_dir():
                return JSONResponse(
                    {"error": f"Decoy page folder '{target}' not found"},
                    status_code=400,
                )
        elif effective_type in (DropActionType.REDIRECT, DropActionType.PROXY):
            if not target.startswith(("http://", "https://")):
                return JSONResponse(
                    {"error": "Target must be an HTTP(S) URL"},
                    status_code=400,
                )

    canary_update = body.get("canary")
    if canary_update is not None:
        if not isinstance(canary_update, dict):
            return JSONResponse({"error": "canary must be an object"}, status_code=400)
        canary_fields = ("enabled", "tracking_pixel", "honeypot_link", "honeypot_form")
        for field in canary_fields:
            if field in canary_update and not isinstance(canary_update[field], bool):
                return JSONResponse(
                    {"error": f"canary.{field} must be a boolean"},
                    status_code=400,
                )

    if new_type is not None:
        dc.drop_action.type = new_type
    if "target" in body:
        dc.drop_action.target = body["target"]
    if canary_update:
        for field in ("enabled", "tracking_pixel", "honeypot_link", "honeypot_form"):
            if field in canary_update:
                setattr(dc.drop_action.canary, field, canary_update[field])

    return JSONResponse({
        "status": "ok",
        "domain": domain,
        "drop_action": dc.drop_action.model_dump(),
    })


_PROFILE_EXTENSIONS = {".profile", ".json", ".yaml", ".yml", ".toml"}


async def list_profiles(request: Request) -> JSONResponse:
    """GET /api/profiles - list available C2 profile files."""
    from infraguard.deploy.profile_detect import detect_profile_type

    config: InfraGuardConfig = request.app.state.config

    search_dirs = {Path("."), Path("profiles"), Path("examples")}
    for dc in config.domains.values():
        if dc.profile_path:
            search_dirs.add(Path(dc.profile_path).parent)

    seen: set[str] = set()
    profiles = []
    for d in sorted(search_dirs):
        if not d.exists() or not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if not f.is_file() or f.suffix.lower() not in _PROFILE_EXTENSIONS:
                continue
            rel = str(f)
            if rel in seen:
                continue
            seen.add(rel)
            try:
                ptype = detect_profile_type(f).value
            except (ValueError, Exception):
                ptype = "unknown"
            profiles.append({"path": rel, "name": f.name, "type": ptype})

    return JSONResponse({"profiles": profiles})


async def swap_profile(request: Request) -> JSONResponse:
    """PATCH /api/config/domains/{domain}/profile - hot-swap a domain's C2 profile."""
    from infraguard.core.router import DomainRouter
    from infraguard.deploy.profile_detect import detect_profile_type

    config: InfraGuardConfig = request.app.state.config
    domain = request.path_params["domain"]

    router = getattr(request.app.state, "router", None)
    if router is None:
        return JSONResponse(
            {"error": "Profile swap unavailable in standalone dashboard mode"},
            status_code=501,
        )

    dc = config.domains.get(domain)
    if not dc:
        return JSONResponse({"error": f"Domain '{domain}' not found"}, status_code=404)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid request body"}, status_code=400)

    profile_path_str = body.get("profile_path")
    if not profile_path_str or not isinstance(profile_path_str, str):
        return JSONResponse({"error": "profile_path is required"}, status_code=400)

    profile_path = Path(profile_path_str)
    if not profile_path.is_file():
        return JSONResponse(
            {"error": f"Profile file not found: {profile_path_str}"},
            status_code=400,
        )

    profile_type_str = body.get("profile_type")
    if profile_type_str:
        try:
            profile_type = ProfileType(profile_type_str)
        except ValueError:
            valid = [t.value for t in ProfileType]
            return JSONResponse(
                {"error": f"Invalid profile type. Valid: {valid}"},
                status_code=400,
            )
    else:
        try:
            profile_type = detect_profile_type(profile_path)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    if profile_type in PHISHING_PROFILE_TYPES:
        return JSONResponse(
            {"error": "Phishing profiles cannot be hot-swapped. Use config reload instead."},
            status_code=400,
        )
    if profile_type in TUNNEL_PROFILE_TYPES:
        return JSONResponse(
            {"error": "Tunnel profiles cannot be hot-swapped. Use config reload instead."},
            status_code=400,
        )

    old_path = dc.profile_path
    old_type = dc.profile_type
    dc.profile_path = str(profile_path)
    dc.profile_type = profile_type
    try:
        new_profile = DomainRouter._load_profile(dc)
    except Exception as e:
        dc.profile_path = old_path
        dc.profile_type = old_type
        return JSONResponse(
            {"error": f"Failed to parse profile: {e}"},
            status_code=400,
        )

    route = router.routes.get(domain)
    if not route:
        dc.profile_path = old_path
        dc.profile_type = old_type
        return JSONResponse(
            {"error": f"Domain '{domain}' not found in router"},
            status_code=404,
        )

    route.profile = new_profile

    return JSONResponse({
        "status": "ok",
        "domain": domain,
        "profile": {
            "name": new_profile.name,
            "type": profile_type.value,
            "path": str(profile_path),
            "uris": new_profile.all_uris(),
        },
    })
