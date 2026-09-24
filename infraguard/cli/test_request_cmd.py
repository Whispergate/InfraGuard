"""``infraguard test-request`` - dry-run a request through the filter pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from infraguard.cli import cli


@cli.command("test-request")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to config file.")
@click.option("--domain", required=True, help="Target domain (must be in config).")
@click.option("--path", "uri_path", default="/", help="Request URI path.")
@click.option("--method", default="GET", help="HTTP method.")
@click.option("--ip", "client_ip", default="1.2.3.4", help="Simulated client IP.")
@click.option("--user-agent", "user_agent", default="Mozilla/5.0", help="User-Agent header.")
@click.option("--header", "extra_headers", multiple=True,
              help="Extra headers (Name:Value format, repeatable).")
def test_request(
    config_path: Path,
    domain: str,
    uri_path: str,
    method: str,
    client_ip: str,
    user_agent: str,
    extra_headers: tuple[str, ...],
) -> None:
    """Simulate a request through the filter pipeline (dry-run).

    Shows the per-filter scoring breakdown without sending any traffic.
    Useful for validating C2 profile configuration before going live.

    \b
    Examples:
      infraguard test-request -c config.yaml --domain cdn.example.com --path /jquery-3.3.1.min.js
      infraguard test-request -c config.yaml --domain cdn.example.com --ip 8.8.8.8 --user-agent "curl/7.68"
    """
    import asyncio
    from ipaddress import ip_address

    from infraguard.config.loader import load_config
    from infraguard.core.router import DomainRouter
    from infraguard.models.common import FilterAction
    from infraguard.pipeline.base import RequestContext

    cfg = load_config(config_path)

    if domain not in cfg.domains:
        click.echo(
            f"Domain '{domain}' not found in config. Available: {', '.join(cfg.domains.keys())}",
            err=True,
        )
        sys.exit(1)

    # Build the router (loads profiles and pipelines)
    router = DomainRouter(cfg)
    route = router.routes.get(domain)
    if not route:
        click.echo(f"Failed to load route for '{domain}'", err=True)
        sys.exit(1)

    # Build a mock request scope
    headers_list: list[tuple[bytes, bytes]] = [
        (b"host", domain.encode()),
        (b"user-agent", user_agent.encode()),
        (b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        (b"accept-language", b"en-US,en;q=0.9"),
        (b"accept-encoding", b"gzip, deflate, br"),
    ]
    for h in extra_headers:
        if ":" in h:
            name, value = h.split(":", 1)
            headers_list.append((name.strip().lower().encode(), value.strip().encode()))

    scope = {
        "type": "http",
        "method": method.upper(),
        "path": uri_path,
        "query_string": b"",
        "headers": headers_list,
        "server": ("127.0.0.1", 443),
        "root_path": "",
    }

    from starlette.requests import Request

    mock_request = Request(scope)

    ctx = RequestContext(
        request=mock_request,
        client_ip=ip_address(client_ip),
        domain_config=route.config,
        profile=route.profile,
        metadata={"body": b""},
    )

    async def _run():
        return await route.pipeline.evaluate(ctx)

    result = asyncio.run(_run())

    # Display results
    verdict = "ALLOW" if result.allowed else "BLOCK"
    color = "green" if result.allowed else "red"

    click.echo(f"\n{'=' * 60}")
    click.secho(f"  VERDICT: {verdict}", fg=color, bold=True)
    click.echo(f"  Total Score: {result.total_score:.2f} (threshold: {cfg.pipeline.block_score_threshold})")
    click.echo(f"  Duration: {result.duration_ms:.1f}ms")
    click.echo(f"  Mode: {cfg.pipeline.filter_mode}")
    click.echo(f"{'=' * 60}")

    click.echo(f"\n  Filter Breakdown:")
    click.echo(f"  {'Filter':<20} {'Action':<10} {'Score':<8} Reason")
    click.echo(f"  {'-' * 58}")
    for r in result.results:
        action_color = {
            FilterAction.ALLOW: "green",
            FilterAction.BLOCK: "red",
            FilterAction.SUSPECT: "yellow",
        }.get(r.action, "white")
        reason = r.reason or ""
        click.echo(
            f"  {r.filter_name:<20} "
            + click.style(f"{r.action.value:<10}", fg=action_color)
            + f" {r.score:<8.2f} {reason}"
        )

    click.echo()
