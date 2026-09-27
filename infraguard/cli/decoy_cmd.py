"""``infraguard decoy generate`` - spin up a new industry decoy site."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from infraguard.cli import cli


@cli.group("decoy")
def decoy_group() -> None:
    """Decoy-site management."""


@decoy_group.command("industries")
def list_industries() -> None:
    """List the industry data files shipped under ``pages/_templates/``."""
    from infraguard.decoys import available_industries

    kinds = available_industries()
    if not kinds:
        click.echo("(no industry data files found)")
        return
    for k in kinds:
        click.echo(k)


@decoy_group.command("generate")
@click.option("--industry", required=True,
              help="Industry slug (see 'infraguard decoy industries').")
@click.option("-o", "--out", "out_dir", required=True,
              type=click.Path(path_type=Path),
              help="Destination directory (will be created if missing).")
@click.option("--force", is_flag=True,
              help="Overwrite index.html if it already exists.")
def generate_decoy(industry: str, out_dir: Path, force: bool) -> None:
    """Render a data-driven decoy blog for the given industry.

    \b
    Examples:
      infraguard decoy generate --industry banking     -o pages/MyBankBlog
      infraguard decoy generate --industry healthcare  -o pages/ClinicBlog
    """
    from infraguard.decoys import available_industries, generate_blog

    if industry not in available_industries():
        click.echo(
            f"unknown industry {industry!r}. "
            f"Try: {', '.join(available_industries()) or '(none)'}",
            err=True,
        )
        sys.exit(1)

    target = out_dir / "index.html"
    if target.exists() and not force:
        click.echo(f"{target} exists (use --force to overwrite)", err=True)
        sys.exit(1)

    written = generate_blog(industry, out_dir)
    click.echo(f"Decoy blog written to {written}")
    click.echo(
        "Assets (icon.svg, style.css) are not copied automatically - "
        "reuse the tree from an existing pages/*Blog/assets directory, "
        "or the site will render unstyled."
    )
