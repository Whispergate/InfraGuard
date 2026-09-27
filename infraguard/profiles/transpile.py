"""Cross-C2 profile transpiler.

Uses the shared :class:`~infraguard.profiles.models.C2Profile` IR as a
pivot. Every registered parser already returns a ``C2Profile``; every
existing serializer (see :mod:`infraguard.profiles.generators`)
consumes one. A transpile is therefore just:

    source_file --(parser)--> C2Profile --(generator)--> target_file

The generator side does not yet cover every framework. Where a
target-specific emitter is missing we fall back to InfraGuard's own
JSON representation (``profile.to_json()``) plus an explicit note in
the output so the operator knows to hand-massage.

CLI: ``infraguard profile transpile --from cs.profile --to sliver
--out out.json``
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from infraguard.profiles.models import C2Profile
from infraguard.profiles.registry import parse_profile_file, supported_kinds

# Optional emitter functions from the existing generators module.
try:
    from infraguard.profiles import generators as _gen
except ImportError:
    _gen = None  # type: ignore

_GeneratorFn = Callable[[C2Profile], str]

# Map target-kind to a stringifier of C2Profile. Anything not in the
# table falls back to profile.to_json().
_GENERATORS: dict[str, _GeneratorFn] = {}
if _gen is not None:
    if hasattr(_gen, "generate_cobalt_strike_malleable"):
        _GENERATORS["cobalt_strike"] = _gen.generate_cobalt_strike_malleable
    if hasattr(_gen, "generate_sliver_yaml"):
        _GENERATORS["sliver"] = _gen.generate_sliver_yaml
    if hasattr(_gen, "generate_mythic_httpx_json"):
        _GENERATORS["mythic_http"] = _gen.generate_mythic_httpx_json


def supported_targets() -> list[str]:
    """Return kinds we can emit natively (rest fall back to JSON)."""
    return sorted(_GENERATORS)


def transpile_file(
    source_path: str | Path,
    source_kind: str,
    target_kind: str,
    target_name: str | None = None,
) -> str:
    """Parse a source profile, emit as ``target_kind``.

    Raises ``ValueError`` on unknown source kind. Never raises on an
    unknown target kind: falls back to InfraGuard JSON with a header
    comment naming the intended target so a downstream tool (or a
    human) can pick up the tail.
    """
    if source_kind not in supported_kinds():
        raise ValueError(
            f"unknown source profile kind {source_kind!r}. "
            f"Supported: {', '.join(supported_kinds())}"
        )

    profile = parse_profile_file(source_kind, source_path, target_name)

    emitter = _GENERATORS.get(target_kind)
    if emitter is None:
        # Fall back to the IR JSON so the operator gets a portable
        # representation plus an explicit note.
        note = (
            f"// transpiled to {target_kind}: no native generator "
            f"registered, emitting InfraGuard JSON representation.\n"
            f"// Registered generators: {', '.join(supported_targets()) or '(none)'}\n"
        )
        return note + profile.to_json(indent=2)

    return emitter(profile)


__all__ = ["supported_targets", "transpile_file"]
