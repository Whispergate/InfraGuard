# InfraGuard Plugin SDK

The Plugin SDK provides protocols, type stubs, testing utilities, and packaging helpers for building InfraGuard plugins.

## Installation

The SDK ships with InfraGuard. Import it directly:

```python
from infraguard.plugins.sdk import PluginTestHarness, PluginManifest, build_manifest
```

## Quick Start

### 1. Minimal Plugin

Every plugin must expose either a `plugin` instance or a `Plugin` class at module level:

```python
from infraguard.plugins.base import BasePlugin
from infraguard.models.common import FilterResult

class Plugin(BasePlugin):
    name = "my_plugin"
    version = "1.0.0"

    async def on_request(self, ctx):
        if "bad" in ctx.request.headers.get("user-agent", ""):
            return FilterResult.block("Bad UA", filter_name=self.name)
        return None

plugin = Plugin()
```

### 2. Plugin Protocol

All plugins implement `InfraGuardPlugin`:

| Hook | Signature | Purpose |
|------|-----------|---------|
| `on_request` | `(RequestContext) -> FilterResult \| None` | Filter incoming requests |
| `on_response` | `(RequestContext, Response) -> Response \| None` | Modify outgoing responses |
| `on_event` | `(RequestEvent) -> None` | Handle request events (for forwarding) |
| `on_startup` | `() -> None` | Initialize resources |
| `on_shutdown` | `() -> None` | Clean up resources |

Return `None` from `on_request`/`on_response` to let the pipeline continue unmodified.

### 3. Configuration

Plugins receive `PluginSettings` via `configure()`:

```python
def configure(self, settings):
    super().configure(settings)
    # Access options dict
    webhook_url = settings.options.get("webhook_url")
    # Access event filter
    only_blocked = settings.event_filter.only_blocked
```

Config in `infraguard.yaml`:

```yaml
plugins:
  my_plugin:
    enabled: true
    options:
      webhook_url: "https://hooks.example.com/..."
    event_filter:
      only_blocked: true
```

## SDK Modules

### `types.py` — Type Stubs & Protocols

```python
from infraguard.plugins.sdk.types import (
    RequestHook, ResponseHook, EventHook,       # Callable type aliases
    PluginCapability,                             # Capability enum
    PluginMetadata,                               # Metadata dataclass
    RequestFilterPlugin, ResponseFilterPlugin,    # Narrow protocols
    EventForwarderPlugin, LifecyclePlugin,
    validate_plugin,                              # Runtime validation
    detect_capabilities,                          # Auto-detect capabilities
)
```

**Runtime validation:**

```python
errors = validate_plugin(my_plugin)
if errors:
    print("Plugin has issues:", errors)
```

**Capability detection:**

```python
caps = detect_capabilities(my_plugin)
# [PluginCapability.REQUEST_FILTER, PluginCapability.LIFECYCLE]
```

### `testing.py` — Test Harness

```python
from infraguard.plugins.sdk.testing import (
    PluginTestHarness,
    make_request_context,
    make_request_event,
    make_plugin_settings,
    make_response,
    run_plugin_lifecycle,
)
```

**Basic usage:**

```python
harness = PluginTestHarness(MyPlugin())
harness.assert_valid()

# Build test fixtures
ctx = harness.make_request_context(
    path="/api/beacon",
    headers={"user-agent": "Mozilla/5.0"},
)
result = await harness.call_on_request(ctx)

harness.assert_hook_called("on_request")
assert result is None  # allowed
```

**Full lifecycle test:**

```python
settings = make_plugin_settings(options={"key": "value"})
harness = await run_plugin_lifecycle(MyPlugin(), settings=settings)
```

### `packaging.py` — Packaging & Distribution

```python
from infraguard.plugins.sdk.packaging import (
    PluginManifest,
    build_manifest,
    validate_manifest,
    package_plugin,
    unpack_plugin,
    scaffold_plugin,
    compute_checksum,
)
```

**Scaffold a new plugin:**

```python
scaffold_plugin("my_filter", "./plugins/", description="Custom filter")
# Creates: ./plugins/my_filter/plugin.py, manifest.json, requirements.txt
```

**Build and package:**

```python
manifest = build_manifest(
    name="my_filter",
    version="1.0.0",
    description="Custom request filter",
    author="Red Team",
)
manifest.save("./my_filter/manifest.json")

archive = package_plugin("./my_filter", "./dist/my_filter-1.0.0.zip")
checksum = compute_checksum(archive)
```

## Examples

The `examples/` directory contains working plugin examples:

| Example | Type | Description |
|---------|------|-------------|
| `ua_blocker.py` | Request Filter | Blocks by User-Agent regex |
| `file_logger.py` | Event Forwarder | Writes events to JSONL file |
| `header_injector.py` | Response Filter | Injects security headers |

### Using Examples in Tests

```python
from infraguard.plugins.sdk.examples.ua_blocker import plugin as ua_plugin
from infraguard.plugins.sdk.testing import PluginTestHarness, make_plugin_settings

settings = make_plugin_settings(options={"ua_pattern": r"curl"})
harness = PluginTestHarness(ua_plugin, settings=settings)

ctx = harness.make_request_context(headers={"user-agent": "curl/7.0"})
result = await harness.call_on_request(ctx)
assert result.action.value == "block"
```

## Built-in Plugin Base Classes

For forwarding events to external systems, extend `ForwardingPlugin`:

```python
from infraguard.plugins.builtin._base import ForwardingPlugin

class Plugin(ForwardingPlugin):
    name = "my_webhook"
    version = "1.0.0"

    async def on_event(self, event):
        if not self._should_forward(event):
            return
        data = self._event_to_dict(event)
        await self._client.post(url, json=data)
```

`ForwardingPlugin` provides:
- `self._client` — `httpx.AsyncClient` (auto-created on startup)
- `self._should_forward(event)` — applies `EventFilterConfig`
- `self._event_to_dict(event)` — serializes `RequestEvent`
- `self._opt(key, default)` — reads from `settings.options`
- `_needs_http_client = False` — skip client creation (e.g. for syslog)

## Loading Plugins

Plugins are loaded by the InfraGuard loader:

```python
from infraguard.plugins.loader import load_plugins

plugins = load_plugins(
    ["elasticsearch", "my_plugin"],  # short names or full paths
    plugin_settings=config.plugins,
)
```

Only short names from `BUILTIN_PLUGINS` or full paths under `infraguard.plugins.builtin.` are accepted for security.

## Best Practices

1. **Always call `super().configure(settings)`** in your `configure()` override.
2. **Return `None`** from hooks when no modification is needed — don't return empty results.
3. **Use `FilterResult.block()` / `.suspect()` / `.allow()`** factory methods.
4. **Set `_needs_http_client = False`** if your forwarding plugin doesn't need HTTP.
5. **Log with structlog** — use `log.info("plugin_event", key=value)` structured logging.
6. **Test with `PluginTestHarness`** — validate protocol compliance and hook behavior.
7. **Include a `manifest.json`** when distributing plugins as packages.
