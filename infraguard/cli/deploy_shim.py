"""Attach external command groups exposed by other subpackages.

Kept as its own module so :mod:`infraguard.cli.__init__` can import it
last, guaranteeing the ``cli`` group already exists before we mutate it.
"""

from __future__ import annotations

from infraguard.cli import cli
from infraguard.deploy.cli import deploy_group
from infraguard.deploy.schedule_cli import schedule_group

cli.add_command(deploy_group)
cli.add_command(schedule_group)
