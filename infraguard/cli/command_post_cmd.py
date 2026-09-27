"""``infraguard command-post`` - multi-instance aggregator dashboard."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click

from infraguard.cli import cli


@cli.command("command-post")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), default=None,
              help="Path to command-post config YAML.")
@click.option("--instance", "instances", multiple=True,
              help="Instance in 'name|url|token' format (repeatable).")
@click.option("--host", default=None, help="Override bind address.")
@click.option("--port", default=None, type=int, help="Override listen port.")
@click.option("--ssl-cert", default=None, help="Path to SSL certificate.")
@click.option("--ssl-key", default=None, help="Path to SSL private key.")
def run_command_post(
    config_path: Path | None,
    instances: tuple[str, ...],
    host: str | None,
    port: int | None,
    ssl_cert: str | None,
    ssl_key: str | None,
) -> None:
    """Start the multi-instance Command Post dashboard."""
    import uvicorn

    from infraguard.ui.command_post.app import create_command_post_app
    from infraguard.ui.command_post.config import CommandPostConfig

    if config_path:
        cfg = CommandPostConfig.from_yaml(config_path)
    elif instances:
        cfg = CommandPostConfig.from_cli_instances(list(instances))
    else:
        click.echo(
            "Provide a config file (-c) or --instance args.\n\n"
            "Examples:\n"
            "  infraguard command-post -c config/command-post.yaml\n"
            '  infraguard command-post --instance "prod|https://ig1:8080|TOKEN"',
            err=True,
        )
        sys.exit(1)

    bind = host or cfg.bind
    listen_port = port or cfg.port

    if not cfg.instances:
        click.echo("No instances configured.", err=True)
        sys.exit(1)

    app = create_command_post_app(cfg)

    uvicorn_kwargs: dict[str, Any] = {
        "host": bind,
        "port": listen_port,
        "log_level": "info",
        "server_header": False,
        "date_header": False,
    }

    # TLS - use provided certs, or try to reuse from the infra config
    if ssl_cert and ssl_key:
        uvicorn_kwargs["ssl_certfile"] = ssl_cert
        uvicorn_kwargs["ssl_keyfile"] = ssl_key
    else:
        # Try auto-generating a self-signed cert
        from infraguard.core.tls import generate_self_signed_cert
        cert, key = generate_self_signed_cert("command-post")
        uvicorn_kwargs["ssl_certfile"] = str(cert)
        uvicorn_kwargs["ssl_keyfile"] = str(key)

    scheme = "https" if "ssl_certfile" in uvicorn_kwargs else "http"
    click.echo(f"InfraGuard Command Post on {scheme}://{bind}:{listen_port}")
    click.echo(f"Instances: {', '.join(i.name for i in cfg.instances)}")
    uvicorn.run(app, **uvicorn_kwargs)
