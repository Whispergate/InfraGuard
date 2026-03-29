"""Base protocol for C2 profile parsers."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from infraguard.profiles.models import C2Profile


@runtime_checkable
class ProfileParser(Protocol):
    """Interface that all profile parsers must implement."""

    def parse(self, content: str) -> C2Profile: ...

    def parse_file(self, path: str | Path) -> C2Profile:
        with open(path, encoding="utf-8") as f:
            return self.parse(f.read())
