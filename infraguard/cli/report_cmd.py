"""``infraguard report`` - generate an HTML engagement report."""

from __future__ import annotations

from pathlib import Path

import click

from infraguard.cli import cli


@cli.command("report")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), default=None,
              help="Path to config file (reads db_path from tracking.db_path).")
@click.option("--db", "db_path", type=click.Path(path_type=Path), default=None,
              help="Path to SQLite database (overrides config).")
@click.option("-o", "--output", type=click.Path(path_type=Path),
              default=Path("infraguard-report.html"),
              help="Output HTML report path.")
@click.option("--title", default="InfraGuard Engagement Report", help="Report title.")
def generate_report_cmd(
    config_path: Path | None, db_path: Path | None, output: Path, title: str
) -> None:
    """Generate an HTML engagement report from the tracking database.

    \b
    Examples:
      infraguard report --db infraguard.db
      infraguard report -c config.yaml -o report.html --title "Op Phantom 2026"
    """
    import asyncio

    from infraguard.tracking.database import Database
    from infraguard.tracking.report import generate_report

    # Resolve DB path: explicit --db flag, or extract from config, or default
    resolved_db = "infraguard.db"
    if db_path:
        resolved_db = str(db_path)
    elif config_path:
        try:
            from infraguard.config.loader import load_config
            cfg = load_config(config_path)
            resolved_db = cfg.tracking.db_path
        except Exception as e:
            # Config may not fully validate (e.g. unset env vars in a
            # non-Docker environment).  Fall back to extracting db_path
            # directly from the raw YAML.
            import os
            import re

            import yaml
            with open(config_path) as f:
                raw = yaml.safe_load(f) or {}
            tracking = raw.get("tracking", {})
            if isinstance(tracking, dict) and tracking.get("db_path"):
                val = tracking["db_path"]
                val = re.sub(r"\$\{([^}]+)\}", lambda m: os.environ.get(m.group(1), ""), val)
                if val:
                    resolved_db = val
            click.echo(
                f"Warning: Config did not fully validate ({e}), using db_path={resolved_db}",
                err=True,
            )

    async def _run():
        db = Database(resolved_db)
        await db.connect()
        try:
            result_path = await generate_report(db, output, title)
            click.echo(f"Report generated: {result_path}")
        finally:
            await db.close()

    asyncio.run(_run())
