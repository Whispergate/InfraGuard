"""Header sanitizer - strips non-whitelisted headers from upstream responses."""

from __future__ import annotations

DEFAULT_SAFE_HEADERS: frozenset[str] = frozenset(
    {
        "content-type",
        "content-length",
        "content-encoding",
        "cache-control",
        "etag",
        "last-modified",
        "location",
        "set-cookie",
        "transfer-encoding",
    }
)


def sanitize_response_headers(
    headers: dict[str, str],
    extra_allowed: frozenset[str] | None = None,
) -> dict[str, str]:
    """Return a copy of *headers* containing only whitelisted keys.

    Keys are compared case-insensitively.  Any header not in
    ``DEFAULT_SAFE_HEADERS`` (or *extra_allowed*) is stripped.

    Args:
        headers: Raw response headers from the upstream.
        extra_allowed: Additional header names (lowercase) to permit beyond
            the default whitelist.  Useful for domain-specific pass-through
            headers configured via ``DomainConfig.extra_allowed_headers``.

    Returns:
        Filtered header dict.  The original key casing is preserved.
    """
    allowed: frozenset[str] = DEFAULT_SAFE_HEADERS
    if extra_allowed:
        allowed = allowed | extra_allowed

    return {k: v for k, v in headers.items() if k.lower() in allowed}
