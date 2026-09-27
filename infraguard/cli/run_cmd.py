"""``infraguard run`` - start the reverse-proxy server."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from infraguard import __version__
from infraguard.cli import cli


@cli.command("run")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to config file.")
@click.option("--host", default=None, help="Override bind address.")
@click.option("--port", default=None, type=int, help="Override listen port.")
@click.option("--ollama-url", default=None, envvar="INFRAGUARD_OLLAMA_URL",
              help="URL of the Ollama API for AI-assisted profile generation (e.g. http://ollama:11434). "
                   "Also settable via INFRAGUARD_OLLAMA_URL env var.")
def run_server(config_path: Path, host: str | None, port: int | None, ollama_url: str | None) -> None:
    """Start the InfraGuard reverse proxy server."""
    import uvicorn

    from infraguard.config.loader import load_config
    from infraguard.core.app import create_app

    cfg = load_config(config_path)
    if ollama_url:
        cfg.ollama.enabled = True
        cfg.ollama.url = ollama_url
    app = create_app(cfg)

    # Find the first HTTP/HTTPS listener for uvicorn binding.
    # Non-HTTP listeners (dns, mqtt, websocket, tcp_tunnel) are started
    # inside the ASGI lifespan and must not be used as the uvicorn config.
    _http_protocols = {"http", "https"}
    http_listener = None
    if cfg.listeners:
        for _lis in cfg.listeners:
            if _lis.protocol in _http_protocols:
                http_listener = _lis
                break
        if http_listener is None:
            click.echo(
                f"Warning: first listener protocol is '{cfg.listeners[0].protocol}', "
                f"not http/https. Non-HTTP listeners are started automatically "
                f"inside the ASGI lifespan. Using default bind 0.0.0.0:8443 for uvicorn.",
                err=True,
            )

    bind = host or (http_listener.bind if http_listener else "0.0.0.0")
    listen_port = port or (http_listener.port if http_listener else 8443)

    click.echo(f"InfraGuard v{__version__} starting on {bind}:{listen_port}")
    click.echo(f"Domains: {', '.join(cfg.domains.keys())}")

    # TLS setup
    uvicorn_kwargs: dict[str, Any] = {
        "host": bind,
        "port": listen_port,
        "log_level": "info",
        "server_header": False,
        "date_header": False,
    }
    if http_listener and http_listener.tls:
        from infraguard.core.tls import resolve_tls_paths

        domains = http_listener.domains or list(cfg.domains.keys())
        cert_path, key_path = resolve_tls_paths(http_listener.tls, domains)
        uvicorn_kwargs["ssl_certfile"] = cert_path
        uvicorn_kwargs["ssl_keyfile"] = key_path

        # HTTP/2 support
        if http_listener.http2:
            try:
                import h2  # noqa: F401
                uvicorn_kwargs["http"] = "h2"
            except ImportError:
                click.echo("Warning: http2 enabled but h2 package not installed", err=True)

    uvicorn.run(app, **uvicorn_kwargs)
