"""Plugin discovery, loading, and configuration."""

from __future__ import annotations

import importlib
import re
from typing import Any

import structlog

from infraguard.plugins.base import InfraGuardPlugin
from infraguard.plugins.builtin import BUILTIN_PLUGINS

log = structlog.get_logger()

# Allowlist of valid plugin name characters (alphanumeric + underscore only)
_VALID_PLUGIN_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")


def load_plugins(
    module_paths: list[str],
    plugin_settings: dict[str, Any] | None = None,
) -> list[InfraGuardPlugin]:
    """Load plugins from Python module paths or short builtin names.

    Short names (e.g. ``"discord"``) are automatically resolved to their
    full builtin module path (``infraguard.plugins.builtin.discord``).
    Full dotted paths continue to work as before.

    If *plugin_settings* is provided, each plugin's ``name`` is looked up
    in the dict. If found and ``enabled`` is False the plugin is skipped.
    Otherwise ``plugin.configure(settings)`` is called.
    """
    settings = plugin_settings or {}
    plugins: list[InfraGuardPlugin] = []

    for raw_path in module_paths:
        # Resolve short names (e.g. "elasticsearch") to full builtin paths
        path = BUILTIN_PLUGINS.get(raw_path, raw_path) if "." not in raw_path else raw_path

        # Security: validate plugin path to prevent arbitrary code execution
        if not _is_valid_plugin_path(path):
            log.warning(
                "plugin_rejected",
                module=path,
                reason="Invalid plugin path - must be alphanumeric/underscore or known builtin",
            )
            continue

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

            # Check settings - skip if disabled
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


def _is_valid_plugin_path(path: str) -> bool:
    """Validate that a plugin path is safe to import.

    Only allows:
    - Short builtin names (e.g. "discord", "slack") that exist in BUILTIN_PLUGINS
    - Full dotted paths under infraguard.plugins.builtin (e.g. "infraguard.plugins.builtin.discord")
    """
    # Check if it's a known builtin short name
    if path in BUILTIN_PLUGINS.values():
        return True

    # Check if it's a full path under the builtin namespace
    if path.startswith("infraguard.plugins.builtin."):
        # Validate the final component is a valid identifier
        final = path.rsplit(".", 1)[-1]
        return bool(_VALID_PLUGIN_NAME.match(final))

    # Reject everything else (no arbitrary module paths)
    return False
