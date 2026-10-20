"""Data management commands: burn (secure wipe) and purge (retention)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from infraguard.cli import cli


@cli.group("data")
def data_group() -> None:
    """Manage the tracking database and operational data."""


@data_group.command("burn")
@click.option(
    "--db",
    "db_path",
    default=None,
    type=click.Path(),
    help="Path to the SQLite database (default: from config or ./data/infraguard.db).",
)
@click.option(
    "--data-dir",
    default=None,
    type=click.Path(),
    help="Data directory to wipe (default: parent of --db).",
)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def burn_cmd(db_path: str | None, data_dir: str | None, yes: bool) -> None:
    """Securely wipe the tracking database and WAL/SHM files.

    Overwrites the DB, WAL, and SHM files with zeros before unlinking
    so the data is not recoverable from the filesystem. Use before
    decommissioning a redirector host.
    """
    if db_path is None:
        db_path = os.environ.get("INFRAGUARD_DB_PATH", "data/infraguard.db")

    db = Path(db_path)
    targets: list[Path] = []

    for suffix in ("", "-wal", "-shm"):
        candidate = db.parent / (db.name + suffix) if suffix else db
        if candidate.exists():
            targets.append(candidate)

    if data_dir:
        dd = Path(data_dir)
        if dd.is_dir():
            for f in dd.rglob("*"):
                if f.is_file() and f not in targets:
                    targets.append(f)

    if not targets:
        click.echo("Nothing to burn - no database or data files found.")
        return

    click.echo("The following files will be overwritten with zeros and deleted:")
    total_bytes = 0
    for t in targets:
        size = t.stat().st_size
        total_bytes += size
        click.echo(f"  {t}  ({size:,} bytes)")

    if not yes:
        click.confirm(
            f"\nDestroy {len(targets)} file(s) ({total_bytes:,} bytes)? This cannot be undone",
            abort=True,
        )

    for t in targets:
        _secure_delete(t)
        click.echo(f"  burned: {t}")

    click.echo(f"\n{len(targets)} file(s) destroyed.")


@data_group.command("purge")
@click.option(
    "--db",
    "db_path",
    default=None,
    type=click.Path(exists=True),
    help="Path to the SQLite database.",
)
@click.option(
    "--older-than",
    "days",
    default=None,
    type=int,
    help="Delete request rows older than N days (default: from config retention_days).",
)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def purge_cmd(db_path: str | None, days: int | None, yes: bool) -> None:
    """Purge old request rows from the tracking database.

    Uses the configured retention_days unless --older-than is specified.
    """
    import asyncio

    if db_path is None:
        db_path = os.environ.get("INFRAGUARD_DB_PATH", "data/infraguard.db")

    if days is None:
        days = 30

    db_file = Path(db_path)
    if not db_file.exists():
        click.echo(f"Database not found: {db_file}")
        sys.exit(1)

    if not yes:
        click.confirm(
            f"Delete request rows older than {days} days from {db_file}?",
            abort=True,
        )

    from infraguard.tracking.database import Database

    async def _run() -> int:
        database = Database(str(db_file))
        await database.initialize()
        deleted = await database.purge_old_requests(days)
        await database.close()
        return deleted

    deleted = asyncio.run(_run())
    click.echo(f"Purged {deleted:,} request row(s) older than {days} days.")


def _secure_delete(path: Path) -> None:
    """Overwrite file contents with zeros, then unlink."""
    try:
        size = path.stat().st_size
        if size > 0:
            with open(path, "r+b") as f:
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass
