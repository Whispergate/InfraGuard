"""``infraguard generate`` - emit nginx/caddy/apache config for a redirector."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from infraguard.cli import cli
from infraguard.cli._helpers import load_profile_file


@cli.command("generate")
@click.argument("backend", type=click.Choice(["nginx", "caddy", "apache"]))
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to config file.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Output file (default: stdout).")
@click.option("--listen-port", type=int, default=None, help="Override listen port.")
@click.option("--ssl-cert", default=None, help="Path to SSL certificate.")
@click.option("--ssl-key", default=None, help="Path to SSL private key.")
@click.option("--redirect-url", default=None, help="Override redirect URL for blocked requests.")
@click.option("--default-action", type=click.Choice(["redirect", "404"]),
              default="redirect", help="Action for non-matching requests.")
@click.option("--no-ip-filter", is_flag=True, help="Omit IP allow/deny blocks.")
@click.option("--no-header-check", is_flag=True, help="Omit header validation rules.")
@click.option("--alias", multiple=True,
              help="Server name alias (domain:alias format, repeatable).")
@click.option("--header", "extra_headers", multiple=True,
              help="Custom response header (Name:Value format, repeatable).")
def generate_backend(
    backend: str,
    config_path: Path,
    output: Path | None,
    listen_port: int | None,
    ssl_cert: str | None,
    ssl_key: str | None,
    redirect_url: str | None,
    default_action: str,
    no_ip_filter: bool,
    no_header_check: bool,
    alias: tuple[str, ...],
    extra_headers: tuple[str, ...],
) -> None:
    """Generate web server config from InfraGuard config + C2 profiles."""
    from infraguard.backends.apache import generate_apache
    from infraguard.backends.base import GeneratorOptions
    from infraguard.backends.caddy import generate_caddy
    from infraguard.backends.nginx import generate_nginx
    from infraguard.config.loader import load_config
    from infraguard.models.common import PHISHING_PROFILE_TYPES, TUNNEL_PROFILE_TYPES
    from infraguard.profiles.models import C2Profile

    cfg = load_config(config_path)

    # Load profiles for each domain (skip phishing/tunnel types that have no C2 profile)
    profiles: dict[str, C2Profile] = {}
    for domain_name, domain_config in cfg.domains.items():
        if (
            domain_config.profile_type in PHISHING_PROFILE_TYPES
            or domain_config.profile_type in TUNNEL_PROFILE_TYPES
        ):
            continue
        p = Path(domain_config.profile_path)
        profiles[domain_name] = load_profile_file(p, domain_config.profile_type.value)

    # Resolve defaults from listener config
    port = listen_port
    if port is None and cfg.listeners:
        port = cfg.listeners[0].port
    if port is None:
        port = 443

    # Parse aliases (domain:alias format)
    server_aliases: dict[str, list[str]] = {}
    for a in alias:
        if ":" not in a:
            click.echo(f"Invalid alias format '{a}' (expected domain:alias)", err=True)
            sys.exit(1)
        domain_part, alias_part = a.split(":", 1)
        server_aliases.setdefault(domain_part, []).append(alias_part)

    # Parse custom headers (Name:Value format)
    custom_hdrs: dict[str, str] = {}
    for h in extra_headers:
        if ":" not in h:
            click.echo(f"Invalid header format '{h}' (expected Name:Value)", err=True)
            sys.exit(1)
        h_name, h_value = h.split(":", 1)
        custom_hdrs[h_name.strip()] = h_value.strip()

    options = GeneratorOptions(
        listen_port=port,
        ssl_cert=ssl_cert,
        ssl_key=ssl_key,
        redirect_url=redirect_url,
        default_action=default_action,
        include_ip_filtering=not no_ip_filter,
        include_header_checks=not no_header_check,
        server_name_aliases=server_aliases,
        custom_headers=custom_hdrs,
    )

    generators = {
        "nginx": generate_nginx,
        "caddy": generate_caddy,
        "apache": generate_apache,
    }
    result = generators[backend](cfg, profiles, options)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result, encoding="utf-8")
        click.echo(f"{backend.title()} config written to {output}")
    else:
        click.echo(result)
