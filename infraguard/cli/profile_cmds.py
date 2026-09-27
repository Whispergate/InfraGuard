"""``infraguard profile parse|convert`` - C2 profile utilities."""

from __future__ import annotations

from pathlib import Path

import click

from infraguard.cli import cli
from infraguard.cli._helpers import load_profile_file, print_profile_summary


@cli.group()
def profile() -> None:
    """C2 profile parsing and conversion utilities."""


_PROFILE_TYPES = click.Choice(
    [
        "auto",
        "cobalt_strike",
        "mythic",
        "mythic_http",
        "brute_ratel",
        "sliver",
        "havoc",
        "nighthawk",
        "poshc2",
    ]
)


@profile.command("parse")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--type", "profile_type", type=_PROFILE_TYPES, default="auto",
              help="Profile type (auto-detected by default).")
@click.option("--name", default=None, help="Override profile name.")
@click.option("--format", "output_format",
              type=click.Choice(["json", "summary"]), default="summary",
              help="Output format.")
def profile_parse(file: Path, profile_type: str, name: str | None, output_format: str) -> None:
    """Parse a C2 profile and display its contents."""
    parsed = load_profile_file(file, profile_type, name)

    if output_format == "json":
        click.echo(parsed.to_json(indent=2))
    else:
        print_profile_summary(parsed)


@profile.command("convert")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--type", "profile_type", type=_PROFILE_TYPES, default="auto",
              help="Source profile type.")
@click.option("--name", default=None, help="Override profile name.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Output file path (default: stdout).")
def profile_convert(file: Path, profile_type: str, name: str | None, output: Path | None) -> None:
    """Convert a C2 profile to InfraGuard JSON format."""
    parsed = load_profile_file(file, profile_type, name)

    json_output = parsed.to_json(indent=2)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json_output, encoding="utf-8")
        click.echo(f"Profile written to {output}")
    else:
        click.echo(json_output)
