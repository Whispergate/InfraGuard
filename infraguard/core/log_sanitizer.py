"""structlog redaction processor - strips sensitive fields from log events."""

from __future__ import annotations

from typing import Any

_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "authorization",
        "x-api-key",
        "auth_token",
        "password",
        "token",
        "secret",
    }
)

_SENSITIVE_SUFFIXES: tuple[str, ...] = (
    "-token",
    "-secret",
    "-key",
    "-credential",
)


def redact_sensitive_fields(
    logger: Any,
    method: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """structlog processor that replaces sensitive field values with ``[REDACTED]``.

    Matches keys against a fixed sensitive-name set and a set of suffixes,
    both compared case-insensitively.  The structlog processor contract
    requires this function to return *event_dict*.

    Args:
        logger: The wrapped logger (unused; required by structlog signature).
        method: The logging method name (unused; required by structlog signature).
        event_dict: The mutable structlog event dictionary.

    Returns:
        The same *event_dict* instance with sensitive values replaced.
    """
    for key in list(event_dict.keys()):
        lower = key.lower()
        if lower in _SENSITIVE_KEYS or lower.endswith(_SENSITIVE_SUFFIXES):
            event_dict[key] = "[REDACTED]"
    return event_dict
