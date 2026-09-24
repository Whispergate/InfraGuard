"""``infraguard events tail``. stream the audit / request log as JSONL.

For pipe-friendly ops: ``infraguard events tail -c cfg.yaml | jq
'select(.filter_result == "block")'``. Works against the tracking DB
either by polling (default) or one-shot (``--no-follow``).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from infraguard.cli import cli


@cli.command("events")
def events_group_placeholder() -> None:
    """Placeholder. see 'infraguard events --help'."""


# Rebind as a group with subcommands. Click doesn't let us do
# ``@cli.group`` after ``@cli.command`` on the same name in one file,
# so we register imperatively below.
_events_group = click.Group("events", help="Query the tracking event log.")
cli.commands.pop("events", None)
cli.add_command(_events_group)


@_events_group.command("tail")
@click.option("-c", "--config", "config_path",
              type=click.Path(exists=True, path_type=Path), default=None,
              help="Path to config file (reads tracking.db_path).")
@click.option("--db", "db_path", type=click.Path(path_type=Path), default=None,
              help="Path to SQLite DB (overrides config).")
@click.option("-n", "--limit", default=20, show_default=True, type=int,
              help="How many trailing rows to emit before starting to poll.")
@click.option("--follow/--no-follow", default=True, show_default=True,
              help="Poll for new rows every --interval seconds.")
@click.option("--interval", default=1.0, show_default=True, type=float,
              help="Poll interval in seconds.")
@click.option("--filter-result", "filter_result",
              type=click.Choice(["allow", "block", "suspect"]), default=None,
              help="Emit only rows with this filter_result.")
@click.option("--domain", default=None, help="Emit only rows for this domain.")
def events_tail(
    config_path: Path | None,
    db_path: Path | None,
    limit: int,
    follow: bool,
    interval: float,
    filter_result: str | None,
    domain: str | None,
) -> None:
    """Stream tracking DB events as JSON lines to stdout.

    \b
    Examples:
      infraguard events tail -c config.yaml
      infraguard events tail --db infraguard.db --filter-result block
      infraguard events tail -c config.yaml | jq -c '{ts:.timestamp, d:.domain, r:.filter_reason}'
    """
    resolved_db = _resolve_db(config_path, db_path)

    async def _run() -> None:
        from infraguard.tracking.database import Database

        db = Database(resolved_db)
        await db.connect()
        try:
            where, params = _build_where(filter_result, domain)
            # Seed with the last N rows so operators see recent context.
            rows = await db.fetchall(
                f"SELECT * FROM requests {where} ORDER BY id DESC LIMIT ?",
                (*params, limit),
            )
            last_id = 0
            for r in reversed(rows):
                _emit(r)
                last_id = max(last_id, int(r["id"]))
            if not follow:
                return
            # Poll. exit cleanly on Ctrl-C.
            while True:
                await asyncio.sleep(interval)
                rows = await db.fetchall(
                    f"SELECT * FROM requests WHERE id > ? {'AND ' + where[6:] if where else ''} "
                    f"ORDER BY id ASC LIMIT 500",
                    (last_id, *params),
                )
                for r in rows:
                    _emit(r)
                    last_id = max(last_id, int(r["id"]))
        finally:
            await db.close()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        # Clean exit. do NOT print a traceback for a natural Ctrl-C.
        sys.exit(0)


def _resolve_db(config_path: Path | None, db_path: Path | None) -> str:
    if db_path:
        return str(db_path)
    if config_path:
        try:
            from infraguard.config.loader import load_config

            return load_config(config_path).tracking.db_path
        except Exception:
            # Fall through to default.
            pass
    return "infraguard.db"


def _build_where(filter_result: str | None, domain: str | None) -> tuple[str, tuple]:
    clauses: list[str] = []
    params: list = []
    if filter_result:
        clauses.append("filter_result = ?")
        params.append(filter_result)
    if domain:
        clauses.append("domain = ?")
        params.append(domain)
    if not clauses:
        return "", ()
    return "WHERE " + " AND ".join(clauses), tuple(params)


def _emit(row: dict) -> None:
    # ``row`` is already dict-shaped from Database.fetchall's Row factory.
    # Use compact JSON stdout may be piped to jq / a file / a SIEM.
    try:
        sys.stdout.write(json.dumps(dict(row), separators=(",", ":"), default=str) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        # Consumer closed the pipe (``| head -20``). quit silently.
        sys.exit(0)
