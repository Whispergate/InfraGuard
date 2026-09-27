"""``infraguard drop-preview``. render the drop response without traffic.

When an operator tunes ``drop_action`` (redirect / reset / decoy /
tarpit / proxy), they usually iterate by firing curls at the running
proxy. This command short-circuits that: build a mock blocked request
in-process, invoke ``handle_drop`` directly, and dump the response
(status, headers, first N bytes of body) to stdout.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from infraguard.cli import cli


@cli.command("drop-preview")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to config file.")
@click.option("--domain", required=True, help="Domain whose drop_action to preview.")
@click.option("--reason", default="preview",
              help="Reason string passed to handle_drop (shows up in decoy logs).")
@click.option("--body-preview", default=200, show_default=True, type=int,
              help="Bytes of response body to print (0 to skip).")
def drop_preview(
    config_path: Path, domain: str, reason: str, body_preview: int
) -> None:
    """Render the drop response for a domain without sending any traffic.

    \b
    Example:
      infraguard drop-preview -c config.yaml --domain cdn.example.com
    """
    from starlette.requests import Request

    from infraguard.config.loader import load_config
    from infraguard.core.drop import handle_drop

    cfg = load_config(config_path)
    if domain not in cfg.domains:
        click.echo(
            f"Domain {domain!r} not found. Available: {', '.join(cfg.domains.keys())}",
            err=True,
        )
        sys.exit(1)

    drop_action = cfg.domains[domain].drop_action
    pages_dir = cfg.decoy_pages_dir

    # A minimal fake request drop actions typically only read Host, UA,
    # and request.client.host.
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/preview",
        "query_string": b"",
        "headers": [
            (b"host", domain.encode()),
            (b"user-agent", b"drop-preview/1.0"),
        ],
        "server": ("127.0.0.1", 443),
        "root_path": "",
        "client": ("203.0.113.42", 55555),
    }
    request = Request(scope)

    async def _run():
        return await handle_drop(
            request, drop_action, reason=reason, pages_dir=pages_dir,
        )

    resp = asyncio.run(_run())

    click.echo(f"{'=' * 60}")
    # Use ASCII "->" instead of U+2192 so this works on Windows cp1252
    # consoles that have not set PYTHONIOENCODING=utf-8 or chcp 65001.
    click.secho(
        f"  DROP PREVIEW: {domain} -> action={drop_action.type.value!r} "
        f"target={drop_action.target or '(none)'}",
        bold=True,
    )
    click.echo(f"{'=' * 60}")
    click.echo(f"  status: {resp.status_code}")
    click.echo("  headers:")
    for k, v in resp.headers.items():
        click.echo(f"    {k}: {v}")

    if body_preview <= 0:
        return

    # StreamingResponse / FileResponse. try to render the body.
    body_bytes = getattr(resp, "body", None)
    if body_bytes is None:
        click.echo("  body: <streaming/file response. no in-memory body to preview>")
        return
    if not body_bytes:
        click.echo("  body: <empty>")
        return
    truncated = body_bytes[:body_preview]
    try:
        click.echo(f"  body (first {len(truncated)}b of {len(body_bytes)}b):")
        click.echo(f"    {truncated.decode('utf-8', errors='replace')}")
    except Exception:
        click.echo(f"  body (first {len(truncated)}b, binary): {truncated!r}")
