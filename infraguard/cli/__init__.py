"""InfraGuard's Click CLI.

Historically every subcommand lived in :mod:`infraguard.main` (1323 LOC).
That made each command hard to test in isolation, hard to review, and
hard to grep - a bug in one command's flag handling meant reading the
whole file. As of v0.5 each command lives in its own module under this
package; :func:`cli` here is a thin group that imports each module so
its decorators register onto the same top-level group.

To add a new command:
    1. Create ``infraguard/cli/<name>_cmd.py`` (or extend a topical module).
    2. Decorate with ``@cli.command(...)`` where ``cli`` is imported from
       :mod:`infraguard.cli`.
    3. Add the module to :data:`_COMMAND_MODULES` so it loads at import.
"""

from __future__ import annotations

import importlib

import click

from infraguard import __version__


@click.group()
@click.version_option(__version__, prog_name="infraguard")
def cli() -> None:
    """InfraGuard - Red team infrastructure tracker and C2 redirector."""


# Order matters only where a submodule adds subcommands to a group
# defined by another submodule (config_cmds registers the config group;
# its extensions from config.cli_ext / wizard are then attached inside
# that module). Keep this list explicit so the import surface is
# discoverable without reflection.
_COMMAND_MODULES: tuple[str, ...] = (
    "infraguard.cli.ingest_cmd",
    "infraguard.cli.profile_cmds",
    "infraguard.cli.config_cmds",
    "infraguard.cli.run_cmd",
    "infraguard.cli.generate_cmd",
    "infraguard.cli.dashboard_cmd",
    "infraguard.cli.command_post_cmd",
    "infraguard.cli.tui_cmd",
    "infraguard.cli.report_cmd",
    "infraguard.cli.test_request_cmd",
    "infraguard.cli.rotate_cmd",
    "infraguard.cli.completions_cmd",
    "infraguard.cli.decoy_cmd",
    "infraguard.cli.simulate_beacon_cmd",
    "infraguard.cli.drop_preview_cmd",
    "infraguard.cli.events_cmd",
    "infraguard.cli.transpile_cmd",
    "infraguard.cli.preflight_cmd",
    "infraguard.cli.deploy_shim",
)

for _mod in _COMMAND_MODULES:
    importlib.import_module(_mod)


__all__ = ["cli"]
