"""Decoy page management API routes."""

from __future__ import annotations

from pathlib import Path

from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse

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

    if '/' in filename or '\\' in filename or filename in ('.', '..'):
        return JSONResponse({"error": "Invalid filename"}, status_code=400)

    dc = config.domains.get(domain)
    if not dc or not dc.decoy_dir:
        return JSONResponse({"error": "Domain or decoy dir not found"}, status_code=404)

    # Security: resolve and validate path BEFORE checking existence
    # This prevents TOCTOU attacks where the file is swapped between check and read
    decoy_root = Path(dc.decoy_dir).resolve()
    file_path = (decoy_root / filename).resolve()

    # Ensure the resolved path is within the decoy directory
    try:
        file_path.relative_to(decoy_root)
    except ValueError:
        return JSONResponse({"error": "Access denied"}, status_code=403)

    # Now check existence on the resolved path
    if not file_path.exists() or not file_path.is_file():
        return JSONResponse({"error": "File not found"}, status_code=404)

    content = file_path.read_text(encoding="utf-8", errors="replace")
    return JSONResponse({"domain": domain, "filename": filename, "content": content})


async def update_decoy_file(request: Request) -> JSONResponse:
    """PUT /api/decoys/{domain}/{filename} - update a decoy file."""
    config: InfraGuardConfig = request.app.state.config
    domain = request.path_params["domain"]
    filename = request.path_params["filename"]

    if '/' in filename or '\\' in filename or filename in ('.', '..'):
        return JSONResponse({"error": "Invalid filename"}, status_code=400)

    dc = config.domains.get(domain)
    if not dc or not dc.decoy_dir:
        return JSONResponse({"error": "Domain or decoy dir not found"}, status_code=404)

    # Security: resolve and validate path BEFORE any file operations
    decoy_root = Path(dc.decoy_dir).resolve()
    file_path = (decoy_root / filename).resolve()

    # Ensure the resolved path is within the decoy directory
    try:
        file_path.relative_to(decoy_root)
    except ValueError:
        return JSONResponse({"error": "Access denied"}, status_code=403)

    try:
        body = await request.json()
    except (ValueError, Exception):
        return JSONResponse({"error": "Invalid request body"}, status_code=400)
    content = body.get("content", "")
    if len(content) > 1_000_000:
        return JSONResponse({"error": "Content too large"}, status_code=413)

    # Create parent dirs only after path validation
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")

    return JSONResponse({"status": "ok", "domain": domain, "filename": filename})


async def list_decoy_pages(request: Request) -> JSONResponse:
    """GET /api/decoys/pages - list available decoy page templates."""
    config: InfraGuardConfig = request.app.state.config
    pages_dir = Path(config.decoy_pages_dir)

    pages = []
    if pages_dir.exists() and pages_dir.is_dir():
        for entry in sorted(pages_dir.iterdir()):
            if entry.is_dir():
                pages.append({
                    "name": entry.name,
                    "has_index": (entry / "index.html").is_file(),
                })

    return JSONResponse({
        "pages_dir": config.decoy_pages_dir,
        "pages": pages,
    })


async def preview_decoy_page(request: Request) -> FileResponse | JSONResponse:
    """GET /api/decoys/pages/{page_name}/preview - preview a decoy page."""
    config: InfraGuardConfig = request.app.state.config
    page_name = request.path_params["page_name"]

    pages_root = Path(config.decoy_pages_dir).resolve()
    page_dir = (pages_root / page_name).resolve()

    try:
        page_dir.relative_to(pages_root)
    except ValueError:
        return JSONResponse({"error": "Access denied"}, status_code=403)

    index_path = page_dir / "index.html"
    if not index_path.is_file():
        return JSONResponse({"error": "Page not found"}, status_code=404)

    return FileResponse(str(index_path), media_type="text/html")
