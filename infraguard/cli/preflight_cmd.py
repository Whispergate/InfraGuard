"""``infraguard preflight`` - adversary-emulation self-test.

Runs the local scanner suite against a target and cross-references the
tracking DB to show which filter caught which probe. Writes a Markdown
report.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from infraguard.cli import cli


@cli.command("preflight")
@click.option("--scan", type=click.Choice(["self", "target"]), default="self",
              help="What to scan. 'self' targets the local infraguard host.")
@click.option("--target", default=None,
              help="Explicit URL (overrides --scan).")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), default=None,
              help="Config file (used to resolve tracking DB path).")
@click.option("--db", "db_path", type=click.Path(path_type=Path), default=None,
              help="SQLite tracking DB path (overrides config).")
@click.option("-o", "--out", "out_path", type=click.Path(path_type=Path),
              default=Path("infraguard-preflight.md"),
              help="Markdown report output path.")
def preflight(scan: str, target: str | None, config_path: Path | None,
              db_path: Path | None, out_path: Path) -> None:
    """Run the adversary-emulation self-test and write a report.

    \b
    Examples:
      infraguard preflight --scan self -c config.yaml
      infraguard preflight --target https://phish.example.com --db infraguard.db
    """
    if target is None:
        target = "https://127.0.0.1:443" if scan == "self" else None
    if not target:
        click.echo("must give either --scan or --target", err=True)
        sys.exit(1)

    from infraguard.deploy.adversary_emulation import (
        correlate_with_tracking,
        run_self_test,
        write_report,
    )

    click.echo(f"[preflight] scanning {target} ...")
    report = run_self_test(target)
    ran = [r.name for r in report.runs if r.ran]
    skipped = [r.name for r in report.runs if not r.ran]
    click.echo(f"[preflight] ran: {', '.join(ran) or '(none)'}")
    if skipped:
        click.echo(f"[preflight] skipped (not installed): {', '.join(skipped)}")

    # Correlate against tracking DB if we can resolve one.
    resolved_db = _resolve_db(config_path, db_path)
    if resolved_db:
        async def _run() -> None:
            from infraguard.tracking.database import Database
            db = Database(resolved_db)
            await db.connect()
            try:
                await correlate_with_tracking(report, db)
            finally:
                await db.close()
        try:
            asyncio.run(_run())
            click.echo(
                f"[preflight] correlated {len(report.correlated_events)} "
                "pipeline events"
            )
        except Exception as exc:
            click.echo(f"[preflight] correlation failed: {exc}", err=True)
    else:
        click.echo("[preflight] no tracking DB found; skipping correlation")

    written = write_report(report, out_path)
    click.echo(f"[preflight] report: {written}")


def _resolve_db(config_path: Path | None, db_path: Path | None) -> str | None:
    if db_path:
        return str(db_path)
    if config_path:
        try:
            from infraguard.config.loader import load_config
            return load_config(config_path).tracking.db_path
        except Exception:
            return None
    return None
