"""Decoy page management API routes."""

from __future__ import annotations

from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.config.schema import InfraGuardConfig


async def list_decoys(request: Request) -> JSONResponse:
    """GET /api/decoys - list decoy directories per domain."""
    config: InfraGuardConfig = request.app.state.config
    decoys = {}
    for name, dc in config.domains.items():
        if dc.decoy_dir:
            decoy_path = Path(dc.decoy_dir)
            files = []
            if decoy_path.exists():
                files = [f.name for f in decoy_path.iterdir() if f.is_file()]
            decoys[name] = {"dir": dc.decoy_dir, "files": files}
    return JSONResponse({"decoys": decoys})


async def get_decoy_file(request: Request) -> JSONResponse:
    """GET /api/decoys/{domain}/{filename} - read a decoy file."""
    config: InfraGuardConfig = request.app.state.config
    domain = request.path_params["domain"]
    filename = request.path_params["filename"]

    dc = config.domains.get(domain)
    if not dc or not dc.decoy_dir:
        return JSONResponse({"error": "Domain or decoy dir not found"}, status_code=404)

    file_path = Path(dc.decoy_dir) / filename
    if not file_path.exists() or not file_path.is_file():
        return JSONResponse({"error": "File not found"}, status_code=404)

    # Security: ensure the path is within the decoy directory
    try:
        file_path.resolve().relative_to(Path(dc.decoy_dir).resolve())
    except ValueError:
        return JSONResponse({"error": "Access denied"}, status_code=403)

    content = file_path.read_text(encoding="utf-8", errors="replace")
    return JSONResponse({"domain": domain, "filename": filename, "content": content})


async def update_decoy_file(request: Request) -> JSONResponse:
    """PUT /api/decoys/{domain}/{filename} - update a decoy file."""
    config: InfraGuardConfig = request.app.state.config
    domain = request.path_params["domain"]
    filename = request.path_params["filename"]

    dc = config.domains.get(domain)
    if not dc or not dc.decoy_dir:
        return JSONResponse({"error": "Domain or decoy dir not found"}, status_code=404)

    file_path = Path(dc.decoy_dir) / filename
    try:
        file_path.resolve().relative_to(Path(dc.decoy_dir).resolve())
    except ValueError:
        return JSONResponse({"error": "Access denied"}, status_code=403)

    body = await request.json()
    content = body.get("content", "")
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")

    return JSONResponse({"status": "ok", "domain": domain, "filename": filename})
