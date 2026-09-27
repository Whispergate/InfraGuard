"""Submodules that :mod:`infraguard.core.router` composes.

Extracted from the historical 1097-LOC ``core/router.py`` so each piece
can be tested in isolation without spinning up an entire
:class:`~infraguard.core.router.DomainRouter`. Anything with heavy
per-request-hot-path branching (``handle``, ``resolve``, ``reload``)
still lives on ``DomainRouter``; the pieces here are stateless helpers
or plain dataclasses.
"""

from infraguard.core.routing.content_guards import (
    check_content_guard,
    record_content_event,
)
from infraguard.core.routing.profile_loader import load_c2_profile_from_config
from infraguard.core.routing.route import DomainRoute

__all__ = [
    "DomainRoute",
    "check_content_guard",
    "load_c2_profile_from_config",
    "record_content_event",
]
