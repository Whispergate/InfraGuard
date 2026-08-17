"""Configuration diffing for InfraGuard.

Compares two YAML config files (or one file against the in-repo defaults)
and reports added, removed, and changed values in a human-friendly,
colour-coded format.  Useful for code-reviewing config changes, spotting
drift between environments, or auditing what an operator actually changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import click
import yaml

from infraguard.config.loader import generate_default_config


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ConfigChange:
    """A single difference between two configs."""

    kind: str            # "added" | "removed" | "changed"
    path: str            # dot-path, e.g. "domains.evil.com.upstream"
    old: Any = None      # present for removed/changed
    new: Any = None      # present for added/changed


@dataclass
class DiffResult:
    """The full diff between two configs."""

    changes: list[ConfigChange] = field(default_factory=list)

    @property
    def added(self) -> list[ConfigChange]:
        return [c for c in self.changes if c.kind == "added"]

    @property
    def removed(self) -> list[ConfigChange]:
        return [c for c in self.changes if c.kind == "removed"]

    @property
    def changed(self) -> list[ConfigChange]:
        return [c for c in self.changes if c.kind == "changed"]

    def __bool__(self) -> bool:
        return bool(self.changes)


# ---------------------------------------------------------------------------
# Differ
# ---------------------------------------------------------------------------


class ConfigDiffer:
    """Compute the difference between two InfraGuard configs.

    Operates on plain ``dict`` trees (the result of ``yaml.safe_load``) so
    diffing works even when one side fails schema validation - exactly the
    situation an operator is usually in when they reach for a diff.
    """

    #: Scalar values that compare equal to None (treated as unset).
    _NULLISH = (None, "")

    def __init__(self, ignore_paths: Iterable[str] | None = None) -> None:
        # Dot-paths to skip (e.g. volatile secrets or per-env overrides).
        self._ignore = set(ignore_paths or ())

    # -- public API ---------------------------------------------------------

    def diff(self, old: dict, new: dict) -> DiffResult:
        """Return the diff that turns ``old`` into ``new``."""
        result = DiffResult()
        self._walk(old, new, path="", result=result)
        # Stable, readable ordering
        result.changes.sort(key=lambda c: (c.path, c.kind))
        return result

    def diff_files(self, old_path: Path, new_path: Path) -> DiffResult:
        """Load two YAML files and diff them."""
        return self.diff(self._load(old_path), self._load(new_path))

    def diff_against_defaults(self, new_path: Path) -> DiffResult:
        """Diff *new_path* against the generated default config."""
        defaults = yaml.safe_load(generate_default_config()) or {}
        return self.diff(defaults, self._load(new_path))

    # -- rendering ----------------------------------------------------------

    def render(self, result: DiffResult, color: bool = True) -> str:
        """Render a diff as a human-readable string."""
        if not result:
            return click.style("No differences.", fg="green") if color else "No differences."

        lines: list[str] = []
        if result.added:
            lines.append(self._style(f"+ Added ({len(result.added)})", "green", color, bold=True))
            for c in result.added:
                lines.append(f"  + {c.path} = {self._fmt(c.new)}")
        if result.removed:
            lines.append(self._style(f"- Removed ({len(result.removed)})", "red", color, bold=True))
            for c in result.removed:
                lines.append(f"  - {c.path}  (was {self._fmt(c.old)})")
        if result.changed:
            lines.append(self._style(f"~ Changed ({len(result.changed)})", "yellow", color, bold=True))
            for c in result.changed:
                lines.append(f"  ~ {c.path}: {self._fmt(c.old)}  ->  {self._fmt(c.new)}")
        return "\n".join(lines)

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            raise FileNotFoundError(f"Config not found: {path}")
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _walk(self, old: Any, new: Any, path: str, result: DiffResult) -> None:
        if path in self._ignore:
            return

        # Dict-vs-dict: recurse key-by-key
        if isinstance(old, dict) and isinstance(new, dict):
            for key in sorted(set(old) | set(new)):
                child_path = f"{path}.{key}" if path else str(key)
                if child_path in self._ignore:
                    continue
                in_old = key in old
                in_new = key in new
                if in_old and not in_new:
                    result.changes.append(ConfigChange("removed", child_path, old=old[key]))
                elif in_new and not in_old:
                    result.changes.append(ConfigChange("added", child_path, new=new[key]))
                else:
                    self._walk(old[key], new[key], child_path, result)
            return

        # List-vs-list: compare as ordered sequences; fall back to set-style
        # diff for scalar-only lists so CIDR/UA/ASN lists don't show as a
        # full replacement when one entry changes.
        if isinstance(old, list) and isinstance(new, list):
            if self._is_scalar_list(old) and self._is_scalar_list(new):
                old_set, new_set = set(old), set(new)
                for item in sorted(new_set - old_set, key=repr):
                    result.changes.append(ConfigChange("added", f"{path}[]", new=item))
                for item in sorted(old_set - new_set, key=repr):
                    result.changes.append(ConfigChange("removed", f"{path}[]", old=item))
                return
            # Ordered comparison for structured lists (listeners, routes)
            common = min(len(old), len(new))
            for i in range(common):
                self._walk(old[i], new[i], f"{path}[{i}]", result)
            for i in range(common, len(new)):
                result.changes.append(ConfigChange("added", f"{path}[{i}]", new=new[i]))
            for i in range(common, len(old)):
                result.changes.append(ConfigChange("removed", f"{path}[{i}]", old=old[i]))
            return

        # Scalars (or type change)
        if self._nullish(old) and self._nullish(new):
            return
        if old != new:
            result.changes.append(ConfigChange("changed", path, old=old, new=new))

    @staticmethod
    def _nullish(v: Any) -> bool:
        return v is None or v == ""

    @staticmethod
    def _is_scalar_list(lst: list) -> bool:
        return all(not isinstance(x, (dict, list)) for x in lst)

    @staticmethod
    def _fmt(value: Any) -> str:
        if value is None:
            return "(null)"
        if isinstance(value, str):
            if value == "":
                return "(empty)"
            # Mask anything that looks like a secret
            if len(value) > 12 and any(
                tok in value.lower() for tok in ("token", "secret", "key", "pass")
            ):
                return value[:4] + "..." + value[-2:]
            return repr(value)
        if isinstance(value, (dict, list)):
            rendered = yaml.dump(value, default_flow_style=True, allow_unicode=True).strip()
            if len(rendered) > 80:
                rendered = rendered[:77] + "..."
            return rendered
        return repr(value)

    @staticmethod
    def _style(text: str, fg: str, color: bool, bold: bool = False) -> str:
        return click.style(text, fg=fg, bold=bold) if color else text
