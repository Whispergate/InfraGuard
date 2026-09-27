"""``infraguard tui`` - launch the terminal UI."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from infraguard.cli import cli


@cli.command("tui")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), default=None,
              help="Path to config file (reads API URL and token from it).")
@click.option("--url", "api_url", default=None,
              help="Dashboard API URL (e.g. http://127.0.0.1:8080).")
@click.option("--token", "api_token", default=None,
              help="Dashboard API bearer token.")
def run_tui(
    config_path: Path | None, api_url: str | None, api_token: str | None
) -> None:
    """Launch the InfraGuard terminal UI."""
    try:
        from infraguard.ui.tui.app import InfraGuardTUI

        app = InfraGuardTUI(
            config_path=str(config_path) if config_path else "",
            api_url=api_url or "",
            api_token=api_token or "",
        )
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
