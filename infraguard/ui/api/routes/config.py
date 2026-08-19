"""Configuration API routes."""

from __future__ import annotations

import os
from pathlib import Path

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.config.schema import InfraGuardConfig
from infraguard.models.common import (
    PHISHING_PROFILE_TYPES,
    TUNNEL_PROFILE_TYPES,
    DropActionType,
    ProfileType,
)

log = structlog.get_logger()


async def _forward_to_proxy(request: Request, path: str) -> JSONResponse | None:
    """Forward a mutation request to the proxy's embedded API.

    Returns the proxied JSONResponse, or None if forwarding is not
    configured / not possible (caller should fall back to local handling
    or return a 501).
    """
    proxy_url = getattr(request.app.state, "proxy_api_url", None)
    if not proxy_url:
        return None

    import httpx

    url = proxy_url.rstrip("/") + path
    try:
        body = await request.body()
        cookies = dict(request.cookies)
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            resp = await client.request(
                method=request.method,
                url=url,
                content=body,
                headers={"Content-Type": "application/json"},
                cookies=cookies,
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
    except Exception as exc:
        log.warning("proxy_forward_failed", url=url, error=str(exc))
        return JSONResponse(
            {"error": f"Failed to forward request to proxy: {exc}"},
            status_code=502,
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

    router = getattr(request.app.state, "router", None)
    if router is None:
        forwarded = await _forward_to_proxy(
            request, f"/api/config/domains/{domain}/drop-action",
        )
        if forwarded is not None:
            return forwarded

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

    search_dirs = {Path("profiles"), Path("examples"), Path("data/profiles")}
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
        forwarded = await _forward_to_proxy(
            request, f"/api/config/domains/{domain}/profile",
        )
        if forwarded is not None:
            return forwarded
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


# ── Content-based profile type detection (for import without filename) ──

_CONTENT_DETECTORS: list[tuple[str, str]] = [
    ("cobalt_strike", "http-get"),
    ("cobalt_strike", "http-post"),
    ("havoc", "[[kaine"),
    ("poshc2", "GET_Requests"),
    ("poshc2", "POST_Requests"),
]


def _detect_profile_type_from_content(content: str, filename: str | None = None) -> str | None:
    """Guess profile type from raw content when no file extension is available."""
    import json as _json

    stripped = content.strip()

    # Check filename extension first
    if filename:
        ext = Path(filename).suffix.lower()
        if ext == ".profile":
            return "cobalt_strike"
        if ext == ".toml":
            return "havoc"
        if ext in (".yml", ".yaml"):
            if "GET_Requests" in content or "POST_Requests" in content:
                return "poshc2"
            return None

    # DSL / TOML / YAML markers
    for ptype, marker in _CONTENT_DETECTORS:
        if marker in stripped:
            return ptype

    # JSON key inspection
    if stripped.startswith("{"):
        try:
            data = _json.loads(stripped)
            if "listeners" in data and "c2_handler" in data:
                return "brute_ratel"
            if "implant_config" in data and "server_config" in data:
                return "sliver"
            if "listener" in data and "implant" in data:
                listener = data.get("listener", {})
                if isinstance(listener, dict) and "http" in listener:
                    return "nighthawk"
            if "instances" in data and isinstance(data["instances"], list):
                return "mythic_http"
            if "get" in data or "post" in data:
                return "mythic"
        except Exception:
            pass

    return None


_PROFILES_DIR = Path("data/profiles")


def _safe_filename(filename: str) -> Path | None:
    """Validate filename and return safe path inside data/profiles/."""
    if "/" in filename or "\\" in filename or ".." in filename:
        return None
    name = Path(filename).name
    if not name or name.startswith("."):
        return None
    resolved = (_PROFILES_DIR / name).resolve()
    try:
        resolved.relative_to(_PROFILES_DIR.resolve())
    except ValueError:
        return None
    return resolved


async def upload_profile(request: Request) -> JSONResponse:
    """POST /api/profiles/upload — import a profile from pasted/uploaded content."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid request body"}, status_code=400)

    content = body.get("content", "")
    filename = body.get("filename", "")
    profile_type_str = body.get("profile_type", "")
    dry_run = body.get("dry_run", False)

    if not content or not content.strip():
        return JSONResponse({"error": "Profile content is required"}, status_code=400)

    # Detect type
    if profile_type_str:
        try:
            ProfileType(profile_type_str)
        except ValueError:
            return JSONResponse({"error": f"Invalid profile type: {profile_type_str}"}, status_code=400)
        detected = profile_type_str
    else:
        detected = _detect_profile_type_from_content(content, filename or None)
        if not detected:
            return JSONResponse(
                {"error": "Could not auto-detect profile type. Please specify profile_type."},
                status_code=400,
            )

    # Validate by parsing
    try:
        _validate_profile_content(detected, content)
    except Exception as e:
        return JSONResponse(
            {"error": f"Profile validation failed: {e}"},
            status_code=400,
        )

    if dry_run:
        return JSONResponse({"status": "ok", "type": detected, "valid": True})

    # Save to disk
    if not filename:
        ext_map = {
            "cobalt_strike": ".profile",
            "havoc": ".toml",
            "poshc2": ".yaml",
        }
        ext = ext_map.get(detected, ".json")
        filename = f"imported-profile{ext}"

    safe_path = _safe_filename(filename)
    if safe_path is None:
        return JSONResponse({"error": "Invalid filename"}, status_code=400)

    _PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(content, encoding="utf-8")
    log.info("profile_uploaded", path=str(safe_path), type=detected)

    return JSONResponse({
        "status": "ok",
        "path": str(safe_path),
        "type": detected,
        "name": safe_path.name,
    })


async def generate_profile_endpoint(request: Request) -> JSONResponse:
    """POST /api/profiles/generate — generate a new profile from wizard params."""
    from infraguard.profiles.generators import generate_profile

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid request body"}, status_code=400)

    profile_type_str = body.get("profile_type", "")
    params = body.get("params", {})
    filename = body.get("filename", "")
    dry_run = body.get("dry_run", False)

    if not profile_type_str:
        return JSONResponse({"error": "profile_type is required"}, status_code=400)

    try:
        content = generate_profile(profile_type_str, params)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse(
            {"error": f"Profile generation failed: {e}"},
            status_code=400,
        )

    if dry_run:
        return JSONResponse({"status": "ok", "type": profile_type_str, "content": content})

    # Save to disk
    if not filename:
        ext_map = {
            "cobalt_strike": ".profile",
            "havoc": ".toml",
            "poshc2": ".yaml",
        }
        ext = ext_map.get(profile_type_str, ".json")
        name = params.get("name", "generated").replace(" ", "-").lower()
        filename = f"{name}{ext}"

    safe_path = _safe_filename(filename)
    if safe_path is None:
        return JSONResponse({"error": "Invalid filename"}, status_code=400)

    _PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(content, encoding="utf-8")
    log.info("profile_generated", path=str(safe_path), type=profile_type_str)

    return JSONResponse({
        "status": "ok",
        "path": str(safe_path),
        "type": profile_type_str,
        "content": content,
        "name": safe_path.name,
    })


def _validate_profile_content(profile_type: str, content: str) -> None:
    """Parse profile content to validate it. Raises on failure."""
    if profile_type == "cobalt_strike":
        from infraguard.profiles.cobalt_strike import parse_cobalt_strike_profile
        parse_cobalt_strike_profile(content)
    elif profile_type == "sliver":
        from infraguard.profiles.sliver import parse_sliver_profile
        parse_sliver_profile(content)
    elif profile_type == "brute_ratel":
        from infraguard.profiles.brute_ratel import parse_brute_ratel_profile
        parse_brute_ratel_profile(content)
    elif profile_type == "havoc":
        from infraguard.profiles.havoc import parse_havoc_profile
        parse_havoc_profile(content)
    elif profile_type == "nighthawk":
        from infraguard.profiles.nighthawk import NighthawkParser
        NighthawkParser().parse(content)
    elif profile_type == "poshc2":
        from infraguard.profiles.poshc2 import PoshC2Parser
        PoshC2Parser().parse(content)
    elif profile_type == "mythic_http":
        from infraguard.profiles.mythic_http import parse_mythic_http_profile
        parse_mythic_http_profile(content)
    elif profile_type == "mythic":
        from infraguard.profiles.mythic import parse_mythic_profile
        parse_mythic_profile(content)
    else:
        raise ValueError(f"Unknown profile type: {profile_type}")
