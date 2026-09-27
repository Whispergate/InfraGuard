"""``infraguard profile transpile`` subcommand.

Wires :mod:`infraguard.profiles.transpile` into the ``profile``
group so operators can:

    infraguard profile transpile --from-kind cobalt_strike \\
        --to-kind mythic_http --in cs.profile --out mythic.json
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from infraguard.cli.profile_cmds import profile as profile_group


@profile_group.command("transpile")
@click.option("--from-kind", "source_kind", required=True,
              help="Source profile kind (e.g. cobalt_strike, mythic).")
@click.option("--to-kind", "target_kind", required=True,
              help="Target profile kind. Native emitters: cobalt_strike, "
                   "sliver, mythic_http. Others fall back to InfraGuard JSON.")
@click.option("--in", "in_path", required=True,
              type=click.Path(exists=True, path_type=Path),
              help="Source profile file.")
@click.option("--out", "out_path", type=click.Path(path_type=Path),
              default=None, help="Write output here (default: stdout).")
@click.option("--name", default=None,
              help="Override the profile name in the output.")
def transpile(
    source_kind: str,
    target_kind: str,
    in_path: Path,
    out_path: Path | None,
    name: str | None,
) -> None:
    """Convert a C2 profile between frameworks via the shared IR."""
    from infraguard.profiles.transpile import supported_targets, transpile_file

    try:
        rendered = transpile_file(in_path, source_kind, target_kind, name)
    except ValueError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)

    if out_path is None:
        click.echo(rendered)
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    click.echo(f"Transpiled to {out_path}")
    if target_kind not in supported_targets():
        click.echo(
            f"  Note: no native emitter for {target_kind!r}; wrote "
            f"InfraGuard JSON. Native targets: "
            f"{', '.join(supported_targets()) or '(none yet)'}",
            err=True,
        )
