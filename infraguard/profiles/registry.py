"""Central registry for C2 profile parsers.

Historically each new C2 (Cobalt Strike, Sliver, Mythic, Havoc, …) meant:

    1. Write ``profiles/<name>.py`` with a ``parse_<name>_file`` function.
    2. Add a branch to the 8-way ``if kind == "cobalt_strike": …`` chain
       in :mod:`infraguard.cli._helpers`, :mod:`infraguard.cli.generate_cmd`,
       and :mod:`infraguard.core.routing.profile_loader`.
    3. Hope you did not forget one of the three.

That third step failed silently every time. This registry makes step 2
automatic: a parser module calls :func:`register_parser` at import time
and the dispatchers here (``parse_profile_file``, ``supported_kinds``)
pick it up. New C2 support is now O(one parser + one register call).

The IR the parsers produce is :class:`infraguard.profiles.models.C2Profile`
- every parser already returns one, so no downstream code changes.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from infraguard.profiles.models import C2Profile

# Signature: (path, name_override) -> C2Profile. Parsers whose current
# implementation does not accept a name override must still take the
# argument (they may ignore it).
ProfileParserFn = Callable[[Path, "str | None"], C2Profile]

_registry: dict[str, ProfileParserFn] = {}


def register_parser(kind: str, parser: ProfileParserFn) -> None:
    """Register ``parser`` as the handler for the given profile ``kind``.

    Re-registration overwrites the previous entry, so a plugin can shadow
    a built-in parser by importing after core startup.
    """
    _registry[kind] = parser


def unregister_parser(kind: str) -> None:
    _registry.pop(kind, None)


def supported_kinds() -> list[str]:
    """Return the registered profile kinds, sorted."""
    _ensure_builtins_loaded()
    return sorted(_registry)


def parse_profile_file(
    kind: str, path: str | Path, name: str | None = None
) -> C2Profile:
    """Dispatch to the registered parser for ``kind``.

    Raises:
        ValueError: if ``kind`` is not registered.
    """
    _ensure_builtins_loaded()
    parser = _registry.get(kind)
    if parser is None:
        raise ValueError(
            f"Unknown profile type {kind!r}. "
            f"Registered: {', '.join(sorted(_registry)) or '(none)'}"
        )
    return parser(Path(path), name)


_builtins_loaded = False


def _ensure_builtins_loaded() -> None:
    """Wire every built-in parser into the registry on first use.

    Deferred until first use so importing this module in isolation is
    cheap. Two parsers (nighthawk, poshc2) do not accept a name override
    yet - wrapped with a lambda that discards it so the registry
    presents a uniform (path, name) signature.
    """
    global _builtins_loaded
    if _builtins_loaded:
        return
    _builtins_loaded = True

    from infraguard.profiles.brute_ratel import parse_brute_ratel_file
    from infraguard.profiles.cobalt_strike import parse_cobalt_strike_file
    from infraguard.profiles.havoc import parse_havoc_file
    from infraguard.profiles.mythic import parse_mythic_file
    from infraguard.profiles.mythic_http import parse_mythic_http_file
    from infraguard.profiles.nighthawk import parse_nighthawk_file
    from infraguard.profiles.poshc2 import parse_poshc2_file
    from infraguard.profiles.sliver import parse_sliver_file

    register_parser("cobalt_strike", parse_cobalt_strike_file)
    register_parser("brute_ratel", parse_brute_ratel_file)
    register_parser("sliver", parse_sliver_file)
    register_parser("havoc", parse_havoc_file)
    register_parser("mythic", parse_mythic_file)
    register_parser("mythic_http", parse_mythic_http_file)
    # Adapters for parsers that ignore the name override - the registry's
    # uniform signature demands a two-argument callable.
    register_parser("nighthawk", lambda p, _name=None: parse_nighthawk_file(p))
    register_parser("poshc2", lambda p, _name=None: parse_poshc2_file(p))


__all__ = [
    "ProfileParserFn",
    "parse_profile_file",
    "register_parser",
    "supported_kinds",
    "unregister_parser",
]
