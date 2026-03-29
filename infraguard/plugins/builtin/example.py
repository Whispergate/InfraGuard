"""Example InfraGuard plugin demonstrating the plugin interface."""

from __future__ import annotations

from starlette.responses import Response

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext


class Plugin:
    name = "example"
    version = "0.1.0"

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        # Example: log a custom metric or add metadata
        ctx.metadata["example_plugin"] = True
        return None  # Pass through

    async def on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response | None:
        return None

    async def on_startup(self) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
