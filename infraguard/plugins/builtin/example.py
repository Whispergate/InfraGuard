"""Example InfraGuard plugin demonstrating the plugin interface."""

from __future__ import annotations

from starlette.responses import Response

from infraguard.models.common import FilterResult
from infraguard.models.events import RequestEvent
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin


class Plugin(BasePlugin):
    name = "example"
    version = "0.1.0"

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        ctx.metadata["example_plugin"] = True
        return None

    async def on_response(self, ctx: RequestContext, response: Response) -> Response | None:
        return None

    async def on_event(self, event: RequestEvent) -> None:
        pass
