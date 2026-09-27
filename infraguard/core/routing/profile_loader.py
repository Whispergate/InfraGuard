"""Dispatch a :class:`DomainConfig` to its parser.

Free function so tests can hand it a config and get a profile back
without instantiating a router. Was ``DomainRouter._load_profile``.

Delegates to :mod:`infraguard.profiles.registry` - new C2 support drops
in by calling ``register_parser`` once, no edit needed here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from infraguard.profiles.registry import parse_profile_file

if TYPE_CHECKING:
    from infraguard.config.schema import DomainConfig
    from infraguard.profiles.models import C2Profile


def load_c2_profile_from_config(config: DomainConfig) -> C2Profile:
    try:
        return parse_profile_file(config.profile_type.value, config.profile_path)
    except ValueError as exc:
        # Preserve the historical message shape so operators debugging
        # a bad config file get the same error text they used to.
        raise ValueError(
            f"{exc} - for domain {config.domain!r}"
        ) from exc
