"""InfraGuard CLI entrypoint."""

from __future__ import annotations

from infraguard.cli import cli

__all__ = ["cli"]


if __name__ == "__main__":
    cli()
