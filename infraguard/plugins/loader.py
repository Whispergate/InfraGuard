"""Plugin discovery, loading, and configuration."""

from __future__ import annotations

import importlib
from typing import Any

import structlog

from infraguard.plugins.base import InfraGuardPlugin

log = structlog.get_logger()


def load_plugins(
    module_paths: list[str],
    plugin_settings: dict[str, Any] | None = None,
) -> list[InfraGuardPlugin]:
    """Load plugins from Python module paths.

    If *plugin_settings* is provided, each plugin's ``name`` is looked up
    in the dict. If found and ``enabled`` is False the plugin is skipped.
    Otherwise ``plugin.configure(settings)`` is called.
    """
    settings = plugin_settings or {}
    plugins: list[InfraGuardPlugin] = []

    for path in module_paths:
        try:
            module = importlib.import_module(path)
            plugin_obj = getattr(module, "plugin", None)
            if plugin_obj is None:
                plugin_cls = getattr(module, "Plugin", None)
                if plugin_cls:
                    plugin_obj = plugin_cls()

            if plugin_obj is None:
                log.warning("plugin_invalid", module=path, reason="No plugin or Plugin found")
                continue

            # Check settings — skip if disabled
            name = getattr(plugin_obj, "name", path.rsplit(".", 1)[-1])
            ps = settings.get(name)
            if ps and hasattr(ps, "enabled") and not ps.enabled:
                log.info("plugin_skipped", name=name, reason="disabled in config")
                continue

            # Configure if the plugin supports it
            if ps and hasattr(plugin_obj, "configure"):
                plugin_obj.configure(ps)

            plugins.append(plugin_obj)
            version = getattr(plugin_obj, "version", "?")
            log.info("plugin_loaded", name=name, version=version, module=path)

        except ImportError:
            log.exception("plugin_import_error", module=path)
        except Exception:
            log.exception("plugin_load_error", module=path)

    return plugins
