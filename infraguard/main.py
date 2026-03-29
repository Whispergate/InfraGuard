"""InfraGuard CLI - Red team infrastructure tracker and C2 redirector."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
import structlog

from infraguard import __version__

log = structlog.get_logger()


@click.group()
@click.version_option(__version__, prog_name="infraguard")
def cli() -> None:
    """InfraGuard - Red team infrastructure tracker and C2 redirector."""


# ── Profile commands ──────────────────────────────────────────────────


@cli.group()
def profile() -> None:
    """C2 profile parsing and conversion utilities."""


@profile.command("parse")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--type",
    "profile_type",
    type=click.Choice(["auto", "cobalt_strike", "mythic"]),
    default="auto",
    help="Profile type (auto-detected by default).",
)
@click.option("--name", default=None, help="Override profile name.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "summary"]),
    default="summary",
    help="Output format.",
)
def profile_parse(
    file: Path, profile_type: str, name: str | None, output_format: str
) -> None:
    """Parse a C2 profile and display its contents."""
    from infraguard.profiles.cobalt_strike import parse_cobalt_strike_file
    from infraguard.profiles.mythic import parse_mythic_file

    # Auto-detect profile type
    if profile_type == "auto":
        if file.suffix == ".profile":
            profile_type = "cobalt_strike"
        elif file.suffix == ".json":
            profile_type = "mythic"
        else:
            click.echo(
                f"Cannot auto-detect profile type for '{file.suffix}'. "
                "Use --type to specify.",
                err=True,
            )
            sys.exit(1)

    if profile_type == "cobalt_strike":
        parsed = parse_cobalt_strike_file(file, name)
    else:
        parsed = parse_mythic_file(file, name)

    if output_format == "json":
        click.echo(parsed.to_json(indent=2))
    else:
        _print_profile_summary(parsed)


@profile.command("convert")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--type",
    "profile_type",
    type=click.Choice(["auto", "cobalt_strike", "mythic"]),
    default="auto",
    help="Source profile type.",
)
@click.option("--name", default=None, help="Override profile name.")
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file path (default: stdout).",
)
def profile_convert(
    file: Path, profile_type: str, name: str | None, output: Path | None
) -> None:
    """Convert a C2 profile to InfraGuard JSON format."""
    from infraguard.profiles.cobalt_strike import parse_cobalt_strike_file
    from infraguard.profiles.mythic import parse_mythic_file

    if profile_type == "auto":
        if file.suffix == ".profile":
            profile_type = "cobalt_strike"
        elif file.suffix == ".json":
            profile_type = "mythic"
        else:
            click.echo(
                f"Cannot auto-detect profile type for '{file.suffix}'. "
                "Use --type to specify.",
                err=True,
            )
            sys.exit(1)

    if profile_type == "cobalt_strike":
        parsed = parse_cobalt_strike_file(file, name)
    else:
        parsed = parse_mythic_file(file, name)

    json_output = parsed.to_json(indent=2)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json_output, encoding="utf-8")
        click.echo(f"Profile written to {output}")
    else:
        click.echo(json_output)


# ── Config commands ───────────────────────────────────────────────────


@cli.command("init")
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=Path("config.yaml"),
    help="Output config file path.",
)
def init_config(output: Path) -> None:
    """Generate a starter InfraGuard configuration file."""
    from infraguard.config.loader import generate_default_config

    if output.exists():
        click.confirm(f"{output} already exists. Overwrite?", abort=True)

    output.write_text(generate_default_config(), encoding="utf-8")
    click.echo(f"Config written to {output}")


@cli.command("validate")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to config file.",
)
def validate_config(config_path: Path) -> None:
    """Validate an InfraGuard configuration file."""
    from infraguard.config.loader import load_config

    try:
        cfg = load_config(config_path)
        click.echo(f"Config is valid.")
        click.echo(f"  Listeners: {len(cfg.listeners)}")
        click.echo(f"  Domains:   {len(cfg.domains)}")
        click.echo(f"  Plugins:   {len(cfg.plugins)}")
    except Exception as e:
        click.echo(f"Config validation failed: {e}", err=True)
        sys.exit(1)


# ── Run command ───────────────────────────────────────────────────────


@cli.command("run")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to config file.",
)
@click.option("--host", default=None, help="Override bind address.")
@click.option("--port", default=None, type=int, help="Override listen port.")
def run_server(config_path: Path, host: str | None, port: int | None) -> None:
    """Start the InfraGuard reverse proxy server."""
    import uvicorn

    from infraguard.config.loader import load_config
    from infraguard.core.app import create_app

    cfg = load_config(config_path)
    app = create_app(cfg)

    # Determine bind/port from first listener or overrides
    bind = host or (cfg.listeners[0].bind if cfg.listeners else "0.0.0.0")
    listen_port = port or (cfg.listeners[0].port if cfg.listeners else 8443)

    click.echo(f"InfraGuard v{__version__} starting on {bind}:{listen_port}")
    click.echo(f"Domains: {', '.join(cfg.domains.keys())}")

    # TLS setup
    uvicorn_kwargs: dict[str, Any] = {
        "host": bind,
        "port": listen_port,
        "log_level": "info",
    }
    if cfg.listeners and cfg.listeners[0].tls:
        from infraguard.core.tls import resolve_tls_paths

        listener = cfg.listeners[0]
        domains = listener.domains or list(cfg.domains.keys())
        cert_path, key_path = resolve_tls_paths(listener.tls, domains)
        uvicorn_kwargs["ssl_certfile"] = cert_path
        uvicorn_kwargs["ssl_keyfile"] = key_path

    uvicorn.run(app, **uvicorn_kwargs)


# ── Generate commands ─────────────────────────────────────────────────


@cli.command("generate")
@click.argument("backend", type=click.Choice(["nginx", "caddy", "apache"]))
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to config file.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file (default: stdout).",
)
@click.option("--listen-port", type=int, default=None, help="Override listen port.")
@click.option("--ssl-cert", default=None, help="Path to SSL certificate.")
@click.option("--ssl-key", default=None, help="Path to SSL private key.")
@click.option(
    "--redirect-url",
    default=None,
    help="Override redirect URL for blocked requests.",
)
@click.option(
    "--default-action",
    type=click.Choice(["redirect", "404"]),
    default="redirect",
    help="Action for non-matching requests.",
)
@click.option("--no-ip-filter", is_flag=True, help="Omit IP allow/deny blocks.")
@click.option("--no-header-check", is_flag=True, help="Omit header validation rules.")
@click.option(
    "--alias",
    multiple=True,
    help="Server name alias (domain:alias format, repeatable).",
)
@click.option(
    "--header",
    "extra_headers",
    multiple=True,
    help="Custom response header (Name:Value format, repeatable).",
)
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
    from infraguard.profiles.cobalt_strike import parse_cobalt_strike_file
    from infraguard.profiles.models import C2Profile
    from infraguard.profiles.mythic import parse_mythic_file

    cfg = load_config(config_path)

    # Load profiles for each domain
    profiles: dict[str, C2Profile] = {}
    for domain_name, domain_config in cfg.domains.items():
        p = Path(domain_config.profile_path)
        if domain_config.profile_type.value == "cobalt_strike":
            profiles[domain_name] = parse_cobalt_strike_file(p)
        else:
            profiles[domain_name] = parse_mythic_file(p)

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


# ── Dashboard command ─────────────────────────────────────────────────


@cli.command("dashboard")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to config file.",
)
@click.option("--host", default=None, help="Override bind address.")
@click.option("--port", default=None, type=int, help="Override listen port.")
def run_dashboard(config_path: Path, host: str | None, port: int | None) -> None:
    """Start the InfraGuard web dashboard."""
    import uvicorn

    from infraguard.config.loader import load_config
    from infraguard.intel.manager import IntelManager
    from infraguard.tracking.database import Database
    from infraguard.ui.api.app import create_api_app

    cfg = load_config(config_path)
    db = Database(cfg.tracking.db_path)
    intel = IntelManager(cfg.intel)
    app = create_api_app(cfg, db, intel)

    bind = host or cfg.api.bind
    listen_port = port or cfg.api.port

    click.echo(f"InfraGuard Dashboard on http://{bind}:{listen_port}")
    uvicorn.run(app, host=bind, port=listen_port, log_level="info")


# ── TUI command ──────────────────────────────────────────────────────


@cli.command("tui")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config file.",
)
def run_tui(config_path: Path | None) -> None:
    """Launch the InfraGuard terminal UI."""
    try:
        from infraguard.ui.tui.app import InfraGuardTUI

        app = InfraGuardTUI(config_path=str(config_path) if config_path else "")
        app.run()
    except ImportError:
        click.echo(
            "Textual is required for the TUI.\n\n"
            "Install with one of:\n"
            "  pipx inject infraguard textual\n"
            "  pip install infraguard[tui]\n"
            "  uv sync --extra tui",
            err=True,
        )
        sys.exit(1)


# ── Helpers ───────────────────────────────────────────────────────────


def _print_profile_summary(p: "C2Profile") -> None:  # noqa: F821
    """Print a human-readable summary of a parsed C2 profile."""
    from infraguard.profiles.models import C2Profile

    click.echo(f"Profile: {p.name}")
    click.echo(f"  User-Agent: {p.useragent or '(not set)'}")
    if p.sleeptime is not None:
        click.echo(f"  Sleep Time: {p.sleeptime}ms")
    if p.jitter is not None:
        click.echo(f"  Jitter:     {p.jitter}%")

    for label, txn in [
        ("HTTP GET", p.http_get),
        ("HTTP POST", p.http_post),
        ("HTTP Stager", p.http_stager),
    ]:
        if txn is None:
            continue
        click.echo(f"\n  {label}:")
        click.echo(f"    Verb: {txn.verb}")
        click.echo(f"    URIs: {', '.join(txn.uris)}")
        if txn.client.headers:
            click.echo(f"    Client Headers:")
            for k, v in txn.client.headers.items():
                click.echo(f"      {k}: {v}")
        if txn.client.message:
            click.echo(
                f"    Message: {txn.client.message.location}"
                + (f" ({txn.client.message.name})" if txn.client.message.name else "")
            )
        if txn.client.transforms:
            click.echo(f"    Client Transforms:")
            for t in txn.client.transforms:
                if t.value:
                    display = (
                        t.value[:60] + "..." if len(t.value) > 60 else t.value
                    )
                    click.echo(f"      {t.action}({display})")
                else:
                    click.echo(f"      {t.action}")
        if txn.server.headers:
            click.echo(f"    Server Headers:")
            for k, v in txn.server.headers.items():
                click.echo(f"      {k}: {v}")
        if txn.server.transforms:
            click.echo(f"    Server Transforms ({len(txn.server.transforms)} steps)")


if __name__ == "__main__":
    cli()
