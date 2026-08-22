"""InfraGuard Plugin SDK.

Provides protocols, type stubs, testing utilities, and packaging helpers
for building, testing, and distributing InfraGuard plugins.

Quick start::

    from infraguard.plugins.sdk import BasePlugin, FilterResult

    class Plugin(BasePlugin):
        name = "my_plugin"
        version = "1.0.0"

        async def on_request(self, ctx):
            if "bad" in ctx.request.headers.get("user-agent", ""):
                return FilterResult.block("Bad UA", filter_name=self.name)
            return None
"""

from infraguard.plugins.sdk.types import (
    EventHook,
    HookName,
    PluginCapability,
    PluginMetadata,
    RequestHook,
    ResponseHook,
    ShutdownHook,
    StartupHook,
    validate_plugin,
)
from infraguard.plugins.sdk.testing import PluginTestHarness
from infraguard.plugins.sdk.packaging import (
    PluginManifest,
    build_manifest,
    validate_manifest,
    package_plugin,
)

__all__ = [
    # Types
    "EventHook",
    "HookName",
    "PluginCapability",
    "PluginMetadata",
    "RequestHook",
    "ResponseHook",
    "ShutdownHook",
    "StartupHook",
    "validate_plugin",
    # Testing
    "PluginTestHarness",
    # Packaging
    "PluginManifest",
    "build_manifest",
    "validate_manifest",
    "package_plugin",
]
