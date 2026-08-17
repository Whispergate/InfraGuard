"""Plugin testing framework for InfraGuard.

Provides harnesses and mock factories for unit-testing plugins outside
a running InfraGuard instance.

Usage::

    import pytest
    from infraguard.plugins.sdk.testing import PluginTestHarness

    class TestMyPlugin:
        @pytest.fixture
        def harness(self):
            from my_plugin import Plugin
            return PluginTestHarness(Plugin())

        @pytest.mark.asyncio
        async def test_blocks_bad_ua(self, harness):
            ctx = harness.make_request_context(
                headers={"user-agent": "curl/7.0 bad"}
            )
            result = await harness.plugin.on_request(ctx)
            assert result is not None
            assert result.action.value == "block"
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from starlette.requests import Request
from starlette.responses import Response

from infraguard.config.schema import EventFilterConfig, PluginSettings
from infraguard.models.common import FilterAction, FilterResult
from infraguard.models.events import RequestEvent
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin, InfraGuardPlugin
from infraguard.plugins.sdk.types import validate_plugin, detect_capabilities


# ---------------------------------------------------------------------------
# Mock factories
# ---------------------------------------------------------------------------

def make_mock_request(
    method: str = "GET",
    path: str = "/",
    headers: dict[str, str] | None = None,
    client_ip: str = "192.168.1.100",
    query_string: str = "",
) -> MagicMock:
    """Create a mock Starlette Request for testing."""
    req = MagicMock(spec=Request)
    req.method = method
    req.url.path = path
    req.url.query = query_string
    req.query_params = {}
    if query_string:
        for pair in query_string.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                req.query_params[k] = v
    req.headers = headers or {}
    req.client.host = client_ip
    req.client.port = 12345
    return req


def make_request_context(
    method: str = "GET",
    path: str = "/",
    domain: str = "test.example.com",
    client_ip: str = "192.168.1.100",
    headers: dict[str, str] | None = None,
    metadata: dict[str, Any] | None = None,
    domain_config: Any = None,
    profile: Any = None,
) -> RequestContext:
    """Build a RequestContext suitable for testing plugins.

    Uses mocks for ``request``, ``domain_config``, and ``profile`` if not
    explicitly provided.
    """
    mock_request = make_mock_request(
        method=method, path=path, headers=headers, client_ip=client_ip
    )

    if domain_config is None:
        domain_config = MagicMock()
        domain_config.domain = domain

    if profile is None:
        profile = MagicMock()

    return RequestContext(
        request=mock_request,
        client_ip=IPv4Address(client_ip),
        domain_config=domain_config,
        profile=profile,
        metadata=metadata or {},
        domain=domain,
    )


def make_request_event(
    domain: str = "test.example.com",
    client_ip: str = "192.168.1.100",
    method: str = "GET",
    uri: str = "/",
    user_agent: str = "TestAgent/1.0",
    filter_result: str = "allow",
    filter_reason: str | None = None,
    filter_score: float = 0.0,
    response_status: int = 200,
    duration_ms: float = 1.5,
    **overrides: Any,
) -> RequestEvent:
    """Create a RequestEvent for testing."""
    defaults: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc),
        "domain": domain,
        "client_ip": client_ip,
        "method": method,
        "uri": uri,
        "user_agent": user_agent,
        "filter_result": filter_result,
        "filter_reason": filter_reason,
        "filter_score": filter_score,
        "response_status": response_status,
        "duration_ms": duration_ms,
    }
    defaults.update(overrides)
    return RequestEvent(**defaults)


def make_plugin_settings(
    enabled: bool = True,
    options: dict[str, Any] | None = None,
    event_filter: EventFilterConfig | None = None,
) -> PluginSettings:
    """Create PluginSettings for testing."""
    return PluginSettings(
        enabled=enabled,
        event_filter=event_filter or EventFilterConfig(),
        options=options or {},
    )


def make_response(
    status_code: int = 200,
    body: str = "OK",
    headers: dict[str, str] | None = None,
) -> Response:
    """Create a Starlette Response for testing."""
    return Response(
        content=body,
        status_code=status_code,
        headers=headers or {},
    )


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

@dataclass
class HookCall:
    """Record of a single hook invocation."""

    hook: str
    args: tuple[Any, ...] = ()
    kwargs: dict[str, Any] = field(default_factory=dict)
    result: Any = None


class PluginTestHarness:
    """Wraps a plugin with test utilities: mock factories, call tracking,
    and lifecycle management.

    Parameters
    ----------
    plugin:
        The plugin instance to test.
    settings:
        Optional PluginSettings to configure the plugin with.
    """

    def __init__(
        self,
        plugin: InfraGuardPlugin,
        settings: PluginSettings | None = None,
    ):
        self.plugin = plugin
        self.call_log: list[HookCall] = []
        self._original_methods: dict[str, Any] = {}
        self._started = False

        # Validate on construction
        self.validation_errors = validate_plugin(plugin)

        # Configure if settings provided
        if settings and hasattr(plugin, "configure"):
            plugin.configure(settings)

    # -- Factories (delegate to module-level) --------------------------------

    @staticmethod
    def make_request_context(**kwargs: Any) -> RequestContext:
        return make_request_context(**kwargs)

    @staticmethod
    def make_request_event(**kwargs: Any) -> RequestEvent:
        return make_request_event(**kwargs)

    @staticmethod
    def make_plugin_settings(**kwargs: Any) -> PluginSettings:
        return make_plugin_settings(**kwargs)

    @staticmethod
    def make_response(**kwargs: Any) -> Response:
        return make_response(**kwargs)

    # -- Lifecycle helpers ---------------------------------------------------

    async def startup(self) -> None:
        """Call ``on_startup`` and track it."""
        await self.plugin.on_startup()
        self._started = True
        self.call_log.append(HookCall(hook="on_startup"))

    async def shutdown(self) -> None:
        """Call ``on_shutdown`` and track it."""
        await self.plugin.on_shutdown()
        self._started = False
        self.call_log.append(HookCall(hook="on_shutdown"))

    # -- Instrumented hook calls ----------------------------------------------

    async def call_on_request(self, ctx: RequestContext) -> FilterResult | None:
        """Call ``on_request`` and record the invocation."""
        result = await self.plugin.on_request(ctx)
        self.call_log.append(
            HookCall(hook="on_request", args=(ctx,), result=result)
        )
        return result

    async def call_on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response | None:
        """Call ``on_response`` and record the invocation."""
        result = await self.plugin.on_response(ctx, response)
        self.call_log.append(
            HookCall(hook="on_response", args=(ctx, response), result=result)
        )
        return result

    async def call_on_event(self, event: RequestEvent) -> None:
        """Call ``on_event`` and record the invocation."""
        await self.plugin.on_event(event)
        self.call_log.append(
            HookCall(hook="on_event", args=(event,))
        )

    # -- Assertions ------------------------------------------------------------

    def assert_valid(self) -> None:
        """Assert that the plugin passes protocol validation."""
        assert not self.validation_errors, (
            f"Plugin validation failed: {self.validation_errors}"
        )

    def assert_hook_called(self, hook_name: str, min_times: int = 1) -> None:
        """Assert a hook was called at least *min_times* times."""
        count = sum(1 for c in self.call_log if c.hook == hook_name)
        assert count >= min_times, (
            f"Expected '{hook_name}' to be called >= {min_times} time(s), "
            f"got {count}"
        )

    def assert_hook_not_called(self, hook_name: str) -> None:
        """Assert a hook was never called."""
        count = sum(1 for c in self.call_log if c.hook == hook_name)
        assert count == 0, (
            f"Expected '{hook_name}' to not be called, but it was called "
            f"{count} time(s)"
        )

    def get_hook_results(self, hook_name: str) -> list[Any]:
        """Return all results from calls to *hook_name*."""
        return [c.result for c in self.call_log if c.hook == hook_name]

    def clear_log(self) -> None:
        """Reset the call log."""
        self.call_log.clear()

    # -- Introspection ---------------------------------------------------------

    @property
    def capabilities(self) -> list[Any]:
        """Detected capabilities of the wrapped plugin."""
        return detect_capabilities(self.plugin)

    @property
    def is_started(self) -> bool:
        return self._started


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------

async def run_plugin_lifecycle(
    plugin: InfraGuardPlugin,
    settings: PluginSettings | None = None,
    events: list[RequestEvent] | None = None,
) -> PluginTestHarness:
    """Convenience: configure, start, feed events, and shut down a plugin.

    Returns the harness for further assertions.
    """
    harness = PluginTestHarness(plugin, settings=settings)
    harness.assert_valid()
    await harness.startup()

    for event in events or []:
        await harness.call_on_event(event)

    await harness.shutdown()
    return harness
