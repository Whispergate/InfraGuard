"""Content delivery backends for serving payloads, decoys, and static files.

Each backend implements the ``ContentBackend`` protocol and can serve
HTTP responses for content routes that are evaluated before the C2
profile filter pipeline.
"""

from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx
import structlog
from starlette.requests import Request
from starlette.responses import FileResponse, RedirectResponse, Response

from infraguard.config.schema import ContentBackendConfig, ContentRouteConfig

log = structlog.get_logger()


@dataclass
class RouteMatch:
    """Result of matching a request against a content route."""

    route: ContentRouteConfig
    path_remainder: str
    domain: str = ""


class ContentBackend(Protocol):
    """Interface for content delivery backends."""

    async def serve(self, request: Request, match: RouteMatch) -> Response: ...
    async def close(self) -> None: ...


class PwnDropBackend:
    """Proxy requests to a PwnDrop instance.

    Forwards the matched path to PwnDrop, preserving the remainder.
    Optionally adds an authorization header for PwnDrop API access.
    """

    def __init__(self, config: ContentBackendConfig):
        self._target = config.target.rstrip("/")
        self._auth_token = config.auth_token
        self._extra_headers = config.headers
        self._client: httpx.AsyncClient | None = None

    async def serve(self, request: Request, match: RouteMatch) -> Response:
        if not self._client:
            self._client = httpx.AsyncClient(
                timeout=30.0, verify=False, follow_redirects=True
            )

        upstream_url = f"{self._target}/{match.path_remainder.lstrip('/')}"
        if request.url.query:
            upstream_url += f"?{request.url.query}"

        headers = dict(request.headers)
        headers.update(self._extra_headers)
        if self._auth_token:
            headers["Authorization"] = self._auth_token
        # Remove hop-by-hop
        for h in ("host", "connection", "transfer-encoding"):
            headers.pop(h, None)

        try:
            resp = await self._client.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                content=await request.body() or None,
            )
            resp_headers = {
                k: v
                for k, v in resp.headers.items()
                if k.lower() not in ("transfer-encoding", "content-encoding", "content-length", "connection")
            }
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=resp_headers,
            )
        except Exception:
            log.exception("pwndrop_backend_error", target=self._target)
            return Response(status_code=502, content=b"Bad Gateway")

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()


class FilesystemBackend:
    """Serve static files from a local directory.

    Includes path traversal protection to prevent escaping the root.
    """

    def __init__(self, config: ContentBackendConfig):
        self._root = Path(config.target).resolve()

    async def serve(self, request: Request, match: RouteMatch) -> Response:
        remainder = match.path_remainder.lstrip("/")
        if not remainder:
            return Response(status_code=404, content=b"Not Found")

        file_path = (self._root / remainder).resolve()

        # Path traversal protection
        try:
            file_path.relative_to(self._root)
        except ValueError:
            log.warning("path_traversal_blocked", path=str(file_path), root=str(self._root))
            return Response(status_code=403, content=b"Forbidden")

        if not file_path.is_file():
            return Response(status_code=404, content=b"Not Found")

        content_type, _ = mimetypes.guess_type(str(file_path))
        return FileResponse(str(file_path), media_type=content_type)

    async def close(self) -> None:
        pass


class HttpProxyBackend:
    """Generic reverse proxy to any upstream URL."""

    def __init__(self, config: ContentBackendConfig):
        self._target = config.target.rstrip("/")
        self._extra_headers = config.headers
        self._client: httpx.AsyncClient | None = None

    async def serve(self, request: Request, match: RouteMatch) -> Response:
        if not self._client:
            self._client = httpx.AsyncClient(
                timeout=30.0, verify=False, follow_redirects=True
            )

        upstream_url = f"{self._target}/{match.path_remainder.lstrip('/')}"
        if request.url.query:
            upstream_url += f"?{request.url.query}"

        headers = dict(request.headers)
        headers.update(self._extra_headers)
        for h in ("host", "connection", "transfer-encoding"):
            headers.pop(h, None)

        try:
            resp = await self._client.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                content=await request.body() or None,
            )
            resp_headers = {
                k: v
                for k, v in resp.headers.items()
                if k.lower() not in ("transfer-encoding", "content-encoding", "content-length", "connection")
            }
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=resp_headers,
            )
        except Exception:
            log.exception("http_proxy_backend_error", target=self._target)
            return Response(status_code=502, content=b"Bad Gateway")

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()


def create_backend(config: ContentBackendConfig) -> ContentBackend:
    """Factory: create the right backend based on config type."""
    from infraguard.models.common import ContentBackendType

    if config.type == ContentBackendType.PWNDROP:
        return PwnDropBackend(config)
    elif config.type == ContentBackendType.FILESYSTEM:
        return FilesystemBackend(config)
    elif config.type == ContentBackendType.HTTP_PROXY:
        return HttpProxyBackend(config)
    else:
        raise ValueError(f"Unknown content backend type: {config.type}")
