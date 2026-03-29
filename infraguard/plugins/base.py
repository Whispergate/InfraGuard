"""Plugin protocol for InfraGuard extensions."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from starlette.requests import Request
from starlette.responses import Response

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext


@runtime_checkable
class InfraGuardPlugin(Protocol):
    """Interface that all InfraGuard plugins must implement."""

    name: str
    version: str

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        """Called during the filter pipeline. Return None to pass through."""
        ...

    async def on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response | None:
        """Called after upstream response. Return None to pass through."""
        ...

    async def on_startup(self) -> None: ...
    async def on_shutdown(self) -> None: ...
