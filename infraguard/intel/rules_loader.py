"""File-backed loader for the ``rules/`` intel lists.

The historical InfraGuard shipped every scanner CIDR, bot User-Agent, JA3
hash and rDNS/header keyword hard-coded in Python. That meant a signature
update needed a code release. This loader makes those lists data-driven:

  * one entry per line
  * blank lines and ``# comment`` lines are ignored
  * an inline ``foo # note`` trims the note off ``foo``
  * a ``[group]`` header switches subsequent lines into a named bucket
    (used by :func:`load_grouped` for the cloud CIDR file)

If a rules file is missing or unreadable, the loader logs a warning and
returns the caller-supplied ``fallback`` list - keeping legacy behavior
so operators who deleted the ``rules/`` tree do not get an empty pipeline.

The default resolution for ``rules/`` is:
    1. ``$INFRAGUARD_RULES_DIR`` if set
    2. ``<repo root>/rules`` relative to this file
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

import structlog

log = structlog.get_logger()


def _default_rules_dir() -> Path:
    env = os.environ.get("INFRAGUARD_RULES_DIR")
    if env:
        return Path(env)
    # infraguard/intel/rules_loader.py -> repo root -> rules/
    return Path(__file__).resolve().parents[2] / "rules"


def rules_path(name: str) -> Path:
    """Resolve a ``rules/<name>`` file path (may or may not exist)."""
    return _default_rules_dir() / name


def _strip_inline_comment(line: str) -> str:
    # Preserve the leading token, drop everything after the first ' #'
    # so ``foo  # note`` becomes ``foo``. A bare ``#…`` was already
    # filtered by the caller.
    idx = line.find(" #")
    return (line[:idx] if idx >= 0 else line).strip()


def load_list(name: str, *, fallback: Iterable[str] = ()) -> list[str]:
    """Load a flat list from ``rules/<name>``.

    Missing file or read error → the ``fallback`` iterable (as a fresh
    list). Duplicates are preserved so callers can decide.
    """
    path = rules_path(name)
    if not path.is_file():
        log.debug("rules_file_missing", path=str(path))
        return list(fallback)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("rules_file_read_failed", path=str(path), error=str(exc))
        return list(fallback)

    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            # Group header in a flat file - skip; use load_grouped for those.
            continue
        entry = _strip_inline_comment(line)
        if entry:
            out.append(entry)
    return out


def load_grouped(
    name: str, *, fallback: dict[str, list[str]] | None = None
) -> dict[str, list[str]]:
    """Load a grouped list from ``rules/<name>``.

    Sections are introduced with ``[group_name]`` lines. Entries before
    any header land in the ``default`` bucket.
    """
    path = rules_path(name)
    if not path.is_file():
        log.debug("rules_file_missing", path=str(path))
        return {k: list(v) for k, v in (fallback or {}).items()}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("rules_file_read_failed", path=str(path), error=str(exc))
        return {k: list(v) for k, v in (fallback or {}).items()}

    groups: dict[str, list[str]] = {}
    current = "default"
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip() or "default"
            groups.setdefault(current, [])
            continue
        entry = _strip_inline_comment(line)
        if entry:
            groups.setdefault(current, []).append(entry)
    return groups


__all__ = ["load_grouped", "load_list", "rules_path"]
