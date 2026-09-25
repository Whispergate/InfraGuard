"""Plugin management API routes.

Lets the dashboard list every loaded plugin and flip individual plugins
on or off at runtime. Runtime toggles are also written back to the
YAML config so they survive a restart.

Endpoints:
  GET  /api/plugins                     - list loaded plugins + status
  POST /api/plugins/{name}/enable       - flip runtime on, persist
  POST /api/plugins/{name}/disable      - flip runtime off, persist

The dashboard container proxies mutations to the proxy's own API when
it isn't holding the live plugin list itself; see ``_forward_to_proxy``
in :mod:`infraguard.ui.api.routes.config` for the same pattern.
"""

from __future__ import annotations

import os
from pathlib import Path

import structlog
import yaml
from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.config.schema import InfraGuardConfig, PluginSettings
from infraguard.plugins.builtin import BUILTIN_PLUGINS

log = structlog.get_logger()


def _load_plugin_by_name(name: str):
    """Import a plugin module by short name or full dotted path and return
    an instantiated plugin object. Returns ``(plugin, error)``."""
    import importlib
    import re as _re

    dotted = BUILTIN_PLUGINS.get(name, name)
    if not _re.match(r"^[a-z_][a-z0-9_.]*$", dotted):
        return None, f"invalid plugin path: {dotted!r}"
    try:
        module = importlib.import_module(dotted)
    except ImportError as exc:
        return None, f"import failed: {exc}"
    plugin = getattr(module, "plugin", None)
    if plugin is None:
        cls = getattr(module, "Plugin", None)
        if cls is not None:
            try:
                plugin = cls()
            except Exception as exc:
                return None, f"instantiation failed: {exc}"
    if plugin is None:
        return None, f"module {dotted!r} exports no ``plugin`` or ``Plugin``"
    return plugin, None


def _forward_needed(request: Request) -> bool:
    """True when this process is a dashboard container without a plugin list."""
    return getattr(request.app.state, "plugins", None) is None


async def _forward_to_proxy(request: Request, path: str) -> JSONResponse | None:
    proxy_url = getattr(request.app.state, "proxy_api_url", None)
    if not proxy_url:
        return None
    import httpx
    url = proxy_url.rstrip("/") + path
    # The dashboard and proxy share the same api.auth_token, so forward
    # the caller's headers AND fall back to the local token so the proxy
    # doesn't reject the internal hop with 401.
    fwd_headers = {"Content-Type": "application/json"}
    if "authorization" in request.headers:
        fwd_headers["Authorization"] = request.headers["authorization"]
    else:
        tok = getattr(getattr(request.app.state, "config", None), "api", None)
        tok = getattr(tok, "auth_token", None) if tok is not None else None
        if tok:
            fwd_headers["Authorization"] = f"Bearer {tok}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            resp = await client.request(
                method=request.method,
                url=url,
                content=await request.body(),
                headers=fwd_headers,
                cookies=dict(request.cookies),
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
    except Exception as exc:
        log.warning("proxy_forward_failed", url=url, error=str(exc))
        return JSONResponse({"error": f"forward failed: {exc}"}, status_code=502)


def _find_plugin(plugins: list, name: str):
    for p in plugins:
        if getattr(p, "name", None) == name:
            return p
    return None


def _persist_plugin_toggle(
    config_path: Path, plugin_name: str, enabled: bool, actor: str
) -> tuple[bool, str | None]:
    """Write plugin_settings.<name>.enabled back to the YAML config.

    Uses the same .bak + git-history pattern as the CLI mutations so the
    dashboard change shows up in ``infraguard config log``. Returns
    ``(ok, error_message)``.
    """
    if not config_path.exists():
        return False, f"config file not found: {config_path}"
    try:
        with config_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        return False, f"config parse failed: {exc}"

    ps = data.setdefault("plugin_settings", {})
    entry = ps.setdefault(plugin_name, {})
    if not isinstance(entry, dict):
        entry = {}
        ps[plugin_name] = entry
    entry["enabled"] = enabled

    # If the plugin isn't in the top-level ``plugins:`` list yet, add
    # it so a re-enable actually loads it on next boot.
    if enabled and "plugins" in data and isinstance(data["plugins"], list):
        if plugin_name not in data["plugins"]:
            data["plugins"].append(plugin_name)

    try:
        import shutil
        bak = config_path.with_suffix(config_path.suffix + ".bak")
        shutil.copy2(config_path, bak)
        with config_path.open("w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    except Exception as exc:
        return False, f"config write failed: {exc}"

    try:
        from infraguard.config.git_history import ConfigHistory
        history_dir = os.environ.get(
            "INFRAGUARD_CONFIG_HISTORY",
            str(Path.home() / ".config" / "infraguard" / "history.git"),
        )
        summary = f"plugin {plugin_name} {'enabled' if enabled else 'disabled'}"
        ConfigHistory(history_dir).record(config_path, actor=actor, summary=summary)
    except Exception:
        pass

    return True, None


async def list_plugins(request: Request) -> JSONResponse:
    """GET /api/plugins - return loaded plugins, their status, and every
    known built-in name for the "add plugin" picker."""
    plugins = getattr(request.app.state, "plugins", None)
    if plugins is None:
        forwarded = await _forward_to_proxy(request, "/api/plugins")
        if forwarded is not None:
            return forwarded
        return JSONResponse({"error": "plugins not exposed on this instance"}, status_code=501)

    config: InfraGuardConfig = request.app.state.config
    settings_by_name = config.plugin_settings or {}

    loaded = []
    for p in plugins:
        name = getattr(p, "name", "unknown")
        s = settings_by_name.get(name)
        loaded.append({
            "name": name,
            "version": getattr(p, "version", "?"),
            "enabled": bool(getattr(p, "_runtime_enabled", True)),
            "class": p.__class__.__name__,
            "module": p.__class__.__module__,
            "options": (getattr(s, "options", {}) if s else {}),
        })

    loaded_names = {row["name"] for row in loaded}
    available = sorted(n for n in BUILTIN_PLUGINS if n not in loaded_names)

    return JSONResponse({
        "loaded": loaded,
        "available_builtin": available,
        "config_path": os.environ.get("INFRAGUARD_CONFIG", "config/config.yaml"),
    })


async def _toggle(request: Request, enabled: bool) -> JSONResponse:
    name = request.path_params["name"]
    plugins = getattr(request.app.state, "plugins", None)
    if plugins is None:
        verb = "enable" if enabled else "disable"
        forwarded = await _forward_to_proxy(request, f"/api/plugins/{name}/{verb}")
        if forwarded is not None:
            return forwarded
        return JSONResponse({"error": "plugins not exposed on this instance"}, status_code=501)

    plugin = _find_plugin(plugins, name)
    added_new = False
    if plugin is None:
        # Disable of an unknown plugin is a no-op we should surface, not
        # a silent success. Enable falls through to load-and-attach so the
        # marketplace's "Add & Enable" button works without a restart.
        if not enabled:
            return JSONResponse(
                {"error": f"plugin '{name}' is not loaded on this instance"},
                status_code=404,
            )

        plugin, err = _load_plugin_by_name(name)
        if plugin is None:
            return JSONResponse({"error": err}, status_code=400)

        # Apply any existing plugin_settings.<name>.options block that was
        # already declared in config but never loaded. If none exists we
        # give the plugin an empty settings object so ``configure`` still
        # runs uniformly.
        cfg: InfraGuardConfig = request.app.state.config
        ps = (cfg.plugin_settings or {}).get(name) or PluginSettings()
        if hasattr(plugin, "configure"):
            try:
                plugin.configure(ps)
            except Exception:
                log.exception("plugin_configure_error", plugin=name)

        plugin._runtime_enabled = True
        plugins.append(plugin)
        # Keep the recorder's own list in sync in the pathological case
        # where the loader started with an empty list (which yields a new
        # list object rather than a shared reference).
        router = getattr(request.app.state, "router", None)
        rec_plugins = getattr(getattr(router, "_recorder", None), "_plugins", None)
        if rec_plugins is not None and plugin not in rec_plugins:
            rec_plugins.append(plugin)

        added_new = True
        log.info("plugin_added_at_runtime", plugin=name, module=plugin.__class__.__module__)

    was = bool(getattr(plugin, "_runtime_enabled", True))
    plugin._runtime_enabled = enabled

    # Call startup/shutdown hooks so plugins that hold sockets or HTTP
    # clients actually free (or reopen) them on toggle. A freshly added
    # plugin also needs on_startup so its first request/response hook has
    # its client/sockets ready.
    if enabled and (not was or added_new):
        try:
            await plugin.on_startup()
        except Exception:
            log.exception("plugin_toggle_startup_error", plugin=name)
    elif not enabled and was:
        try:
            await plugin.on_shutdown()
        except Exception:
            log.exception("plugin_toggle_shutdown_error", plugin=name)

    # Persist to config so the toggle survives a restart.
    config_path = Path(os.environ.get("INFRAGUARD_CONFIG", "config/config.yaml"))
    actor = getattr(request.state, "user", None) or getattr(request.state, "actor", None) or "dashboard"
    ok, err = _persist_plugin_toggle(config_path, name, enabled, actor=str(actor))

    log.info(
        "plugin_runtime_toggled",
        plugin=name, enabled=enabled, persisted=ok, added=added_new,
    )
    return JSONResponse({
        "name": name,
        "enabled": enabled,
        "added": added_new,
        "persisted": ok,
        "persist_error": err,
    })


async def enable_plugin(request: Request) -> JSONResponse:
    """POST /api/plugins/{name}/enable - flip runtime on and persist."""
    return await _toggle(request, enabled=True)


async def disable_plugin(request: Request) -> JSONResponse:
    """POST /api/plugins/{name}/disable - flip runtime off and persist."""
    return await _toggle(request, enabled=False)
