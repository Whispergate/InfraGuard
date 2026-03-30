"""Tests for content delivery routes and backends."""

import tempfile
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from infraguard.config.schema import ContentBackendConfig, ContentRouteConfig
from infraguard.core.content import (
    FilesystemBackend,
    HttpProxyBackend,
    PwnDropBackend,
    RouteMatch,
    create_backend,
)
from infraguard.core.content_router import ContentRouteResolver
from infraguard.models.common import ContentBackendType


# ── Content route resolver ────────────────────────────────────────────

class TestContentRouteResolver:
    def test_exact_match(self):
        routes = [ContentRouteConfig(
            path="/file.exe",
            backend=ContentBackendConfig(type=ContentBackendType.FILESYSTEM, target="/tmp"),
        )]
        resolver = ContentRouteResolver(routes)
        req = MagicMock()
        req.url.path = "/file.exe"
        req.method = "GET"
        match = resolver.match(req)
        assert match is not None
        assert match.path_remainder == ""

    def test_exact_no_match(self):
        routes = [ContentRouteConfig(
            path="/file.exe",
            backend=ContentBackendConfig(type=ContentBackendType.FILESYSTEM, target="/tmp"),
        )]
        resolver = ContentRouteResolver(routes)
        req = MagicMock()
        req.url.path = "/other.exe"
        req.method = "GET"
        assert resolver.match(req) is None

    def test_prefix_glob_match(self):
        routes = [ContentRouteConfig(
            path="/downloads/*",
            backend=ContentBackendConfig(type=ContentBackendType.FILESYSTEM, target="/tmp"),
        )]
        resolver = ContentRouteResolver(routes)
        req = MagicMock()
        req.url.path = "/downloads/payload.exe"
        req.method = "GET"
        match = resolver.match(req)
        assert match is not None
        assert match.path_remainder == "payload.exe"

    def test_prefix_glob_no_match(self):
        routes = [ContentRouteConfig(
            path="/downloads/*",
            backend=ContentBackendConfig(type=ContentBackendType.FILESYSTEM, target="/tmp"),
        )]
        resolver = ContentRouteResolver(routes)
        req = MagicMock()
        req.url.path = "/uploads/file.txt"
        req.method = "GET"
        assert resolver.match(req) is None

    def test_method_filtering(self):
        routes = [ContentRouteConfig(
            path="/api/*",
            backend=ContentBackendConfig(type=ContentBackendType.HTTP_PROXY, target="http://test"),
            methods=["POST"],
        )]
        resolver = ContentRouteResolver(routes)
        req = MagicMock()
        req.url.path = "/api/data"
        req.method = "GET"
        assert resolver.match(req) is None
        req.method = "POST"
        assert resolver.match(req) is not None

    def test_first_match_wins(self):
        routes = [
            ContentRouteConfig(
                path="/downloads/special.exe",
                backend=ContentBackendConfig(type=ContentBackendType.HTTP_PROXY, target="http://special"),
            ),
            ContentRouteConfig(
                path="/downloads/*",
                backend=ContentBackendConfig(type=ContentBackendType.FILESYSTEM, target="/tmp"),
            ),
        ]
        resolver = ContentRouteResolver(routes)
        req = MagicMock()
        req.url.path = "/downloads/special.exe"
        req.method = "GET"
        match = resolver.match(req)
        assert match.route.backend.target == "http://special"


# ── FilesystemBackend ─────────────────────────────────────────────────

class TestFilesystemBackend:
    @pytest.mark.asyncio
    async def test_serve_existing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "test.txt").write_text("hello")
            backend = FilesystemBackend(
                ContentBackendConfig(type=ContentBackendType.FILESYSTEM, target=tmpdir)
            )
            req = MagicMock()
            match = RouteMatch(
                route=MagicMock(),
                path_remainder="test.txt",
                domain="test",
            )
            resp = await backend.serve(req, match)
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_serve_missing_file_404(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = FilesystemBackend(
                ContentBackendConfig(type=ContentBackendType.FILESYSTEM, target=tmpdir)
            )
            req = MagicMock()
            match = RouteMatch(route=MagicMock(), path_remainder="nonexistent.txt", domain="test")
            resp = await backend.serve(req, match)
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_path_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = FilesystemBackend(
                ContentBackendConfig(type=ContentBackendType.FILESYSTEM, target=tmpdir)
            )
            req = MagicMock()
            match = RouteMatch(route=MagicMock(), path_remainder="../../etc/passwd", domain="test")
            resp = await backend.serve(req, match)
            assert resp.status_code in (403, 404)

    @pytest.mark.asyncio
    async def test_empty_remainder_404(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = FilesystemBackend(
                ContentBackendConfig(type=ContentBackendType.FILESYSTEM, target=tmpdir)
            )
            req = MagicMock()
            match = RouteMatch(route=MagicMock(), path_remainder="", domain="test")
            resp = await backend.serve(req, match)
            assert resp.status_code == 404


# ── Backend factory ───────────────────────────────────────────────────

class TestCreateBackend:
    def test_create_filesystem(self):
        cfg = ContentBackendConfig(type=ContentBackendType.FILESYSTEM, target="/tmp")
        backend = create_backend(cfg)
        assert isinstance(backend, FilesystemBackend)

    def test_create_http_proxy(self):
        cfg = ContentBackendConfig(type=ContentBackendType.HTTP_PROXY, target="http://test")
        backend = create_backend(cfg)
        assert isinstance(backend, HttpProxyBackend)

    def test_create_pwndrop(self):
        cfg = ContentBackendConfig(type=ContentBackendType.PWNDROP, target="http://pwndrop:80")
        backend = create_backend(cfg)
        assert isinstance(backend, PwnDropBackend)
