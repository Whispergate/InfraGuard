"""``infraguard config …`` and ``infraguard validate`` - config commands.

Also stitches in the extended commands from :mod:`infraguard.config.cli_ext`
and the wizard from :mod:`infraguard.config.wizard`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from infraguard.cli import cli


@cli.group("config")
def config_group() -> None:
    """Configuration management commands."""


@config_group.command("init")
@click.option("-o", "--output", type=click.Path(path_type=Path),
              default=Path("config.yaml"), help="Output config file path.")
def init_config(output: Path) -> None:
    """Generate a starter InfraGuard configuration file."""
    from infraguard.config.loader import generate_default_config

    if output.exists():
        click.confirm(f"{output} already exists. Overwrite?", abort=True)

    output.write_text(generate_default_config(), encoding="utf-8")
    click.echo(f"Config written to {output}")


@config_group.command("generate")
@click.option("--domain", required=True, help="Primary domain for the redirector.")
@click.option("--c2-profile", required=True,
              type=click.Path(exists=True, path_type=Path),
              help="Path to C2 profile file.")
@click.option("--upstream", required=True,
              help="C2 teamserver URL (e.g. https://10.0.0.5:8443).")
@click.option("--profile-type",
              type=click.Choice(["auto", "cobalt_strike", "mythic", "brute_ratel", "sliver", "havoc"]),
              default="auto", help="Profile type (auto-detected by default).")
@click.option("--drop-target", default="https://www.google.com",
              help="Redirect URL for blocked traffic.")
@click.option("-o", "--output", type=click.Path(path_type=Path),
              default=Path("./infraguard-deploy"),
              help="Output directory for deployment bundle.")
def config_generate(domain: str, c2_profile: Path, upstream: str,
                    profile_type: str, drop_target: str, output: Path) -> None:
    """Generate a deployment-ready config bundle from minimal inputs."""
    from infraguard.deploy.config_gen import generate_config, write_bundle

    # Use container-relative path for the profile in the generated config
    # Emit a bundle-relative path (``profiles/<name>``) so the same
    # config works from BOTH the host (``infraguard run -c
    # bundle/config.yaml`` resolves it to ``bundle/profiles/<name>``)
    # AND the container (WORKDIR ends up at ``/config``, resolving to
    # ``/config/profiles/<name>`` - the exact path the compose file
    # bind-mounts). Historically this shipped as an absolute
    # ``/config/profiles/<name>`` which broke every host-side command
    # (``test-request``, ``validate`` on the bundle, ``run`` without
    # Docker) with FileNotFoundError. See the v0.5 QA report.
    bundle_relative_profile_path = f"profiles/{c2_profile.name}"

    cfg = generate_config(
        domain=domain,
        c2_profile_path=bundle_relative_profile_path,
        upstream=upstream,
        profile_type=profile_type,
        drop_target=drop_target,
    )
    # Pass the CLI inputs through to the bundle writer so the emitted
    # .env is populated (INFRAGUARD_DOMAIN, INFRAGUARD_*_UPSTREAM, and
    # the LE cert paths). Historically these were left blank, forcing
    # operators to hand-edit .env after ``config generate`` (v0.4 F4).
    # ``profile_type`` here selects which upstream env var name is
    # written (``INFRAGUARD_MYTHIC_UPSTREAM`` vs ``INFRAGUARD_CS_UPSTREAM``
    # etc.); if the user passed "auto", resolve it against the config we
    # just built so the .env agrees with the config.
    resolved_profile_type = profile_type
    if resolved_profile_type == "auto":
        resolved_profile_type = next(
            iter(cfg.domains.values())
        ).profile_type.value
    write_bundle(
        cfg,
        output,
        profile_source=c2_profile,
        domain=domain,
        upstream=upstream,
        profile_type=resolved_profile_type,
    )

    click.echo(f"Deployment bundle written to {output}/")
    click.echo("  config.yaml        - InfraGuard configuration")
    click.echo("  .env               - Environment variables (edit before deploy)")
    click.echo("  docker-compose.yml - Docker Compose deployment")
    click.echo("  profiles/          - C2 profile files")
    click.echo(f"\nNext: edit .env, then run 'docker-compose up -d' in {output}/")


@cli.command("validate")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to config file.")
def validate_config(config_path: Path) -> None:
    """Validate an InfraGuard configuration file."""
    from infraguard.config.loader import load_config

    try:
        cfg = load_config(config_path)
        click.echo("Config is valid.")
        click.echo(f"  Listeners: {len(cfg.listeners)}")
        click.echo(f"  Domains:   {len(cfg.domains)}")
        click.echo(f"  Plugins:   {len(cfg.plugins)}")
    except Exception as e:
        click.echo(f"Config validation failed: {e}", err=True)
        sys.exit(1)


# ── Extended config commands (from config.cli_ext) ────────────────────

from infraguard.config.cli_ext import (
    config_diff,
    config_test,
    config_validate,
    domain_group,
    intel_group,
    pipeline_group,
    set_value,
    show_config,
)

config_group.add_command(show_config, "show")
config_group.add_command(set_value, "set")
config_group.add_command(domain_group)
config_group.add_command(intel_group)
config_group.add_command(pipeline_group)
config_group.add_command(config_diff, "diff")
config_group.add_command(config_validate, "validate")
config_group.add_command(config_test, "test")


# ── Wizard commands ───────────────────────────────────────────────────

from infraguard.config.wizard import wizard_group

cli.add_command(wizard_group)
