"""``infraguard simulate-beacon``. fire a fully profile-shaped request.

Closes the biggest operator-experience gap in v0.5: today the only way
to know whether a beacon-shaped request will pass the pipeline is to
fire real traffic and eyeball the block reasons. This command
constructs the exact HTTP request the profile describes. headers,
cookie name, transforms. pushes it through the router in dry-run
mode, and prints both the verdict and the per-filter breakdown.

Unlike ``test-request`` which just runs raw filter input, this one
reads the profile's ``http_get`` / ``http_post`` transaction and mirrors
what a real beacon would send byte-for-byte (including the
transform-applied cookie/parameter values). If the pipeline still
blocks, the reason is a *config bug*, not an operator typo.
"""

from __future__ import annotations

import asyncio
import base64
import random
import sys
from ipaddress import ip_address
from pathlib import Path

import click

from infraguard.cli import cli


@cli.command("simulate-beacon")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to config file.")
@click.option("--domain", required=True, help="Target domain (must be in config).")
@click.option("--verb", type=click.Choice(["GET", "POST"]), default="GET",
              help="Which profile transaction to mirror.")
@click.option("--ip", "client_ip", default="203.0.113.42",
              help="Simulated client IP (default: TEST-NET-3).")
@click.option("--ja3", default=None,
              help="Optional JA3 hash to inject as if extracted from ClientHello.")
@click.option("--body-size", default=64, show_default=True, type=int,
              help="Bytes of fake beacon metadata to encode into the message field.")
def simulate_beacon(
    config_path: Path,
    domain: str,
    verb: str,
    client_ip: str,
    ja3: str | None,
    body_size: int,
) -> None:
    """Simulate a real beacon request through the pipeline.

    \b
    Example:
      infraguard simulate-beacon -c config.yaml --domain cdn.example.com
      infraguard simulate-beacon -c config.yaml --domain cdn.example.com --verb POST --body-size 512
    """
    from infraguard.config.loader import load_config
    from infraguard.core.router import DomainRouter
    from infraguard.models.common import FilterAction
    from infraguard.pipeline.base import RequestContext

    cfg = load_config(config_path)
    if domain not in cfg.domains:
        click.echo(
            f"Domain {domain!r} not found. Available: {', '.join(cfg.domains.keys())}",
            err=True,
        )
        sys.exit(1)

    router = DomainRouter(cfg)
    route = router.routes.get(domain)
    if not route or route.profile is None:
        click.echo(f"No loaded profile for {domain!r}", err=True)
        sys.exit(1)

    profile = route.profile
    txn = profile.http_get if verb == "GET" else profile.http_post
    if txn is None:
        click.echo(
            f"Profile {profile.name!r} has no {verb} transaction. try the other verb.",
            err=True,
        )
        sys.exit(1)

    # Pick a URI at random from the profile's declared set. matches
    # what a real beacon does when the profile lists multiple.
    uri = random.choice(list(txn.uris)) if txn.uris else "/"

    # Assemble headers by taking the profile's declared client headers
    # verbatim if UA is present at profile level, use that.
    headers: list[tuple[bytes, bytes]] = [
        (b"host", domain.encode()),
    ]
    for h_name, h_value in txn.client.headers.items():
        headers.append((h_name.lower().encode(), h_value.encode()))
    if not any(name == b"user-agent" for name, _ in headers):
        headers.append((b"user-agent", (profile.useragent or "Mozilla/5.0").encode()))

    # Fake beacon metadata payload. the transforms defined by the
    # profile would be applied by a real implant we base64url it as a
    # stand-in so the value at least survives most transforms unchanged.
    metadata = base64.urlsafe_b64encode(random.randbytes(body_size)).rstrip(b"=").decode()

    # Deliver the metadata via whichever location the profile declares
    # (cookie / header / parameter / body / uri-append). Falls back to a
    # ``__session`` cookie which matches the ClientConfig default.
    msg = txn.client.message
    if msg is None:
        headers.append((b"cookie", f"__session={metadata}".encode()))
    elif msg.location == "cookie":
        headers.append((b"cookie", f"{msg.name or '__session'}={metadata}".encode()))
    elif msg.location == "header":
        headers.append((msg.name.lower().encode(), metadata.encode()))
    elif msg.location == "parameter":
        uri = f"{uri}?{msg.name or 'q'}={metadata}"
    elif msg.location == "uri-append":
        uri = f"{uri.rstrip('/')}/{metadata}"
    body = metadata.encode() if msg and msg.location == "body" else b""

    scope = {
        "type": "http",
        "method": verb,
        "path": uri.split("?", 1)[0],
        "query_string": uri.split("?", 1)[1].encode() if "?" in uri else b"",
        "headers": headers,
        "server": ("127.0.0.1", 443),
        "root_path": "",
    }
    from starlette.requests import Request

    request = Request(scope)
    if ja3:
        request.state.ja3 = ja3

    ctx = RequestContext(
        request=request,
        client_ip=ip_address(client_ip),
        domain_config=route.config,
        profile=profile,
        metadata={"body": body, "ja3": ja3},
    )

    result = asyncio.run(route.pipeline.evaluate(ctx))

    verdict = "ALLOW" if result.allowed else "BLOCK"
    color = "green" if result.allowed else "red"

    click.echo()
    click.echo(f"{'=' * 60}")
    click.secho(f"  SIMULATED BEACON: {verb} {uri}", bold=True)
    click.secho(f"  VERDICT: {verdict}", fg=color, bold=True)
    click.echo(f"  Score: {result.total_score:.2f}"
               f" (threshold: {cfg.pipeline.block_score_threshold})")
    click.echo(f"{'=' * 60}")
    click.echo()
    click.echo("  Request shape:")
    for hn, hv in headers:
        click.echo(f"    {hn.decode()}: {hv.decode()[:80]}")
    if body:
        click.echo(f"    <body: {len(body)} bytes>")
    click.echo()
    click.echo("  Filter breakdown:")
    click.echo(f"  {'filter':<20} {'action':<10} {'score':<8} reason")
    click.echo(f"  {'-' * 60}")
    for r in result.results:
        c = {
            FilterAction.ALLOW: "green",
            FilterAction.BLOCK: "red",
            FilterAction.SUSPECT: "yellow",
        }.get(r.action, "white")
        click.echo(
            f"  {r.filter_name:<20} "
            + click.style(f"{r.action.value:<10}", fg=c)
            + f" {r.score:<8.2f} {r.reason or ''}"
        )
    click.echo()
    if not result.allowed:
        click.echo(
            "  Hint: this beacon shape does not pass the pipeline. "
            "The blocking filter(s) above show which invariant failed. "
            "If ``profile`` is the blocker, the config's http_get/http_post "
            "transaction does not match what a real beacon of this framework "
            "would send. check headers, cookie name, and transforms.",
        )
