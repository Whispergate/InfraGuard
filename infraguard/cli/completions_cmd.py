"""``infraguard completions`` - emit shell completion scripts."""

from __future__ import annotations

import click

from infraguard.cli import cli


@cli.command("completions")
@click.argument(
    "shell",
    type=click.Choice(["bash", "zsh", "fish"]),
    required=False,
    default=None,
)
def completions(shell: str | None) -> None:
    """Generate shell completion script.

    \n
    Activate in current session:
        eval "$(infraguard completions bash)"
    \n
    Persist across sessions:
        infraguard completions bash >> ~/.bashrc
        infraguard completions zsh  >> ~/.zshrc
        infraguard completions fish >  ~/.config/fish/completions/infraguard.fish
    """
    import os

    from click.shell_completion import BashComplete, FishComplete, ZshComplete

    shells = {
        "bash": BashComplete,
        "zsh": ZshComplete,
        "fish": FishComplete,
    }

    if shell is None:
        shell_env = os.environ.get("SHELL", "")
        if "zsh" in shell_env:
            shell = "zsh"
        elif "fish" in shell_env:
            shell = "fish"
        else:
            shell = "bash"

    comp = shells[shell](
        cli=cli,
        ctx_args={},
        prog_name="infraguard",
        complete_var="_INFRAGUARD_COMPLETE",
    )
    click.echo(comp.source())
