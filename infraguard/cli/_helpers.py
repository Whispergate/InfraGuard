"""Shared helpers used by more than one CLI module.

Kept minimal on purpose - anything larger than a formatter or dispatcher
belongs in a real module under ``infraguard.<subsystem>``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click


def load_profile_file(file: Path, profile_type: str, name: str | None = None):
    """Load a C2 profile file, auto-detecting type if needed.

    Dispatches through :mod:`infraguard.profiles.registry` so adding a
    new C2 needs one ``register_parser`` call and nothing here.
    """
    from infraguard.profiles.registry import parse_profile_file

    if profile_type == "auto":
        from infraguard.deploy.profile_detect import detect_profile_type

        try:
            profile_type = detect_profile_type(file).value
        except ValueError as exc:
            click.echo(str(exc), err=True)
            sys.exit(1)

    try:
        return parse_profile_file(profile_type, file, name)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc


def print_profile_summary(p) -> None:
    """Print a human-readable summary of a parsed C2 profile."""

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


__all__ = ["load_profile_file", "print_profile_summary"]
