"""``infraguard dashboard`` - standalone web dashboard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from infraguard.cli import cli


@cli.command("dashboard")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to config file.")
@click.option("--host", default=None, help="Override bind address.")
@click.option("--port", default=None, type=int, help="Override listen port.")
@click.option("--tls/--no-tls", default=None,
              help="Enable/disable TLS (default: auto from config).")
@click.option("--proxy-url", default=None, envvar="INFRAGUARD_PROXY_API",
              help="URL of the proxy's embedded API for forwarding mutations "
                   "(e.g. https://infraguard-proxy:8080). Also settable via "
                   "INFRAGUARD_PROXY_API env var.")
@click.option("--ollama-url", default=None, envvar="INFRAGUARD_OLLAMA_URL",
              help="URL of the Ollama API for AI-assisted profile generation "
                   "(e.g. http://ollama:11434). Also settable via "
                   "INFRAGUARD_OLLAMA_URL env var.")
def run_dashboard(
    config_path: Path,
    host: str | None,
    port: int | None,
    tls: bool | None,
    proxy_url: str | None,
    ollama_url: str | None,
) -> None:
    """Start the InfraGuard web dashboard (standalone mode).

    NOTE: In standalone mode the dashboard creates its own IntelManager,
    so whitelist/blocklist changes do NOT affect a running proxy.
    Use 'infraguard run' instead -- it embeds the dashboard and shares
    state so changes take effect immediately.

    Set --proxy-url (or INFRAGUARD_PROXY_API) to forward profile swaps
    and drop-action changes to the running proxy's embedded API.
    """
    import uvicorn

    from infraguard.config.loader import load_config
    from infraguard.core.tls import resolve_tls_paths
    from infraguard.intel.manager import IntelManager
    from infraguard.tracking.database import Database
    from infraguard.ui.api.app import create_api_app

    if proxy_url:
        click.echo(
            f"Standalone dashboard - mutations forwarded to proxy at {proxy_url}",
            err=True,
        )
    else:
        click.echo(
            "Warning: standalone dashboard does not share state with the proxy.\n"
            "Whitelist/blocklist changes won't affect a running proxy.\n"
            "Set INFRAGUARD_PROXY_API or use 'infraguard run' for integrated dashboard.",
            err=True,
        )

    cfg = load_config(config_path)
    db = Database(cfg.tracking.db_path)
    intel = IntelManager(cfg.intel)
    if ollama_url:
        cfg.ollama.enabled = True
        cfg.ollama.url = ollama_url

    app = create_api_app(cfg, db, intel)
    app.state.proxy_api_url = proxy_url

    bind = host or cfg.api.bind
    listen_port = port or cfg.api.port

    uvicorn_kwargs: dict[str, Any] = {
        "host": bind,
        "port": listen_port,
        "log_level": "info",
        "server_header": False,
        "date_header": False,
    }

    # TLS: auto-detect from listener config, or use --tls flag
    enable_tls = tls
    if enable_tls is None and cfg.listeners:
        # Auto-enable if any listener has TLS configured
        enable_tls = any(lis.tls for lis in cfg.listeners)

    if enable_tls and cfg.listeners:
        # Find TLS config from listeners
        for lis in cfg.listeners:
            if lis.tls:
                domains = lis.domains or list(cfg.domains.keys())
                cert_path, key_path = resolve_tls_paths(lis.tls, domains)
                uvicorn_kwargs["ssl_certfile"] = cert_path
                uvicorn_kwargs["ssl_keyfile"] = key_path
                break

    scheme = "https" if "ssl_certfile" in uvicorn_kwargs else "http"
    click.echo(f"InfraGuard Dashboard on {scheme}://{bind}:{listen_port}")
    uvicorn.run(app, **uvicorn_kwargs)
