"""Type stubs and protocols for the InfraGuard Plugin SDK.

Defines the structural types that plugin authors can use for type checking
and validation, plus runtime helpers for validating plugin conformance.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Literal,
    Protocol,
    Union,
    runtime_checkable,
)

from starlette.requests import Request
from starlette.responses import Response

from infraguard.models.common import FilterResult
from infraguard.models.events import RequestEvent
from infraguard.pipeline.base import RequestContext


# ---------------------------------------------------------------------------
# Hook type aliases
# ---------------------------------------------------------------------------

RequestHook = Callable[[RequestContext], Awaitable[FilterResult | None]]
"""Signature for the ``on_request`` hook."""

ResponseHook = Callable[[RequestContext, Response], Awaitable[Response | None]]
"""Signature for the ``on_response`` hook."""

EventHook = Callable[[RequestEvent], Awaitable[None]]
"""Signature for the ``on_event`` hook."""

StartupHook = Callable[[], Awaitable[None]]
"""Signature for the ``on_startup`` hook."""

ShutdownHook = Callable[[], Awaitable[None]]
"""Signature for the ``on_shutdown`` hook."""

HookName = Literal["on_request", "on_response", "on_event", "on_startup", "on_shutdown"]
"""Names of all plugin lifecycle hooks."""


# ---------------------------------------------------------------------------
# Plugin capabilities
# ---------------------------------------------------------------------------

class PluginCapability(str, enum.Enum):
    """Capabilities a plugin can declare."""

    REQUEST_FILTER = "request_filter"
    """Intercepts and filters incoming requests."""

    RESPONSE_FILTER = "response_filter"
    """Modifies outgoing responses."""

    EVENT_FORWARDER = "event_forwarder"
    """Forwards events to external systems."""

    LIFECYCLE = "lifecycle"
    """Hooks into startup/shutdown only."""


# ---------------------------------------------------------------------------
# Plugin metadata
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PluginMetadata:
    """Descriptive metadata about a plugin."""

    name: str
    version: str
    description: str = ""
    author: str = ""
    capabilities: tuple[PluginCapability, ...] = ()
    requires_config: tuple[str, ...] = ()
    """Config option keys the plugin requires in ``settings.options``."""


# ---------------------------------------------------------------------------
# Extended protocols for type checking
# ---------------------------------------------------------------------------

@runtime_checkable
class RequestFilterPlugin(Protocol):
    """Plugin that implements request filtering."""

    name: str
    version: str

    async def on_request(self, ctx: RequestContext) -> FilterResult | None: ...


@runtime_checkable
class ResponseFilterPlugin(Protocol):
    """Plugin that implements response filtering."""

    name: str
    version: str

    async def on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response | None: ...


@runtime_checkable
class EventForwarderPlugin(Protocol):
    """Plugin that forwards events."""

    name: str
    version: str

    async def on_event(self, event: RequestEvent) -> None: ...


@runtime_checkable
class LifecyclePlugin(Protocol):
    """Plugin that hooks into lifecycle events."""

    name: str
    version: str

    async def on_startup(self) -> None: ...
    async def on_shutdown(self) -> None: ...


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

ALL_HOOKS: tuple[HookName, ...] = (
    "on_request",
    "on_response",
    "on_event",
    "on_startup",
    "on_shutdown",
)


def validate_plugin(plugin: Any) -> list[str]:
    """Check that *plugin* satisfies the InfraGuardPlugin protocol.

    Returns a list of validation error strings.  An empty list means the
    plugin is valid.
    """
    errors: list[str] = []

    # Required attributes
    for attr in ("name", "version"):
        if not hasattr(plugin, attr):
            errors.append(f"Missing required attribute: {attr}")
        elif not isinstance(getattr(plugin, attr), str):
            errors.append(f"Attribute '{attr}' must be a str, got {type(getattr(plugin, attr)).__name__}")

    if hasattr(plugin, "name") and isinstance(getattr(plugin, "name", None), str):
        name = plugin.name
        if not name:
            errors.append("Plugin name must not be empty")

    # Required async methods
    import asyncio
    import inspect

    for hook in ALL_HOOKS:
        method = getattr(plugin, hook, None)
        if method is None:
            errors.append(f"Missing hook method: {hook}")
        elif not callable(method):
            errors.append(f"Hook '{hook}' is not callable")
        elif not (inspect.iscoroutinefunction(method) or inspect.isasyncgenfunction(method)):
            # Allow sync methods that return awaitables (edge case)
            if not inspect.ismethod(method) and not inspect.isfunction(method):
                errors.append(f"Hook '{hook}' should be an async method")

    return errors


def detect_capabilities(plugin: Any) -> list[PluginCapability]:
    """Detect which capabilities a plugin provides based on overridden hooks.

    Compares the plugin's methods against the BasePlugin no-op defaults to
    determine which hooks have been meaningfully overridden.
    """
    from infraguard.plugins.base import BasePlugin

    caps: list[PluginCapability] = []
    _noop_map = {
        "on_request": PluginCapability.REQUEST_FILTER,
        "on_response": PluginCapability.RESPONSE_FILTER,
        "on_event": PluginCapability.EVENT_FORWARDER,
    }

    for hook_name, cap in _noop_map.items():
        method = getattr(plugin, hook_name, None)
        if method is None:
            continue
        default = getattr(BasePlugin, hook_name, None)
        if default is not None and method.__func__ is not default:  # type: ignore[union-attr]
            caps.append(cap)

    # Lifecycle is always available but only flagged if non-trivially overridden
    for hook_name in ("on_startup", "on_shutdown"):
        method = getattr(plugin, hook_name, None)
        if method is None:
            continue
        default = getattr(BasePlugin, hook_name, None)
        if default is not None and method.__func__ is not default:  # type: ignore[union-attr]
            if PluginCapability.LIFECYCLE not in caps:
                caps.append(PluginCapability.LIFECYCLE)

    return caps
