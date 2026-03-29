"""Plugin discovery and loading."""

from __future__ import annotations

import importlib

import structlog

from infraguard.plugins.base import InfraGuardPlugin

log = structlog.get_logger()


def load_plugins(module_paths: list[str]) -> list[InfraGuardPlugin]:
    """Load plugins from Python module paths."""
    plugins: list[InfraGuardPlugin] = []

    for path in module_paths:
        try:
            module = importlib.import_module(path)
            # Look for a `plugin` attribute or a class named `Plugin`
            plugin_obj = getattr(module, "plugin", None)
            if plugin_obj is None:
                plugin_cls = getattr(module, "Plugin", None)
                if plugin_cls:
                    plugin_obj = plugin_cls()

            if plugin_obj and isinstance(plugin_obj, InfraGuardPlugin):
                plugins.append(plugin_obj)
                log.info(
                    "plugin_loaded",
                    name=plugin_obj.name,
                    version=plugin_obj.version,
                    module=path,
                )
            else:
                log.warning("plugin_invalid", module=path, reason="No valid plugin found")
        except ImportError:
            log.exception("plugin_import_error", module=path)
        except Exception:
            log.exception("plugin_load_error", module=path)

    return plugins
