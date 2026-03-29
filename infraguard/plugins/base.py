"""Plugin protocol and base class for InfraGuard extensions."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from starlette.requests import Request
from starlette.responses import Response

from infraguard.models.common import FilterResult
from infraguard.models.events import RequestEvent
from infraguard.pipeline.base import RequestContext


@runtime_checkable
class InfraGuardPlugin(Protocol):
    """Interface that all InfraGuard plugins must implement."""

    name: str
    version: str

    async def on_request(self, ctx: RequestContext) -> FilterResult | None: ...
    async def on_response(self, ctx: RequestContext, response: Response) -> Response | None: ...
    async def on_event(self, event: RequestEvent) -> None: ...
    async def on_startup(self) -> None: ...
    async def on_shutdown(self) -> None: ...


class BasePlugin:
    """Convenience base class with no-op defaults for all hooks.

    Plugins can inherit from this and only override the hooks they need.
    The ``configure`` method is called by the loader with plugin-specific
    settings from the config file.
    """

    name: str = "unnamed"
    version: str = "0.0.0"

    def configure(self, settings: Any) -> None:
        """Called by the loader with this plugin's PluginSettings."""
        self._settings = settings

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        return None

    async def on_response(self, ctx: RequestContext, response: Response) -> Response | None:
        return None

    async def on_event(self, event: RequestEvent) -> None:
        pass

    async def on_startup(self) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
