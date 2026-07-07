"""Header sanitizer - strips non-whitelisted headers from upstream responses.

OPSEC: Upstream teamservers (Cobalt Strike, Mythic, etc.) may inject
identifying headers into responses.  This module ensures only safe,
generic headers are forwarded to the client.  The blocklist prevents
operator misconfiguration (via extra_allowed_headers) from accidentally
leaking server identity.
"""

from __future__ import annotations

DEFAULT_SAFE_HEADERS: frozenset[str] = frozenset(
    {
        "content-type",
        "content-length",
        "cache-control",
        "etag",
        "last-modified",
        "location",
        "set-cookie",
        "date",
        "expires",
        "pragma",
        "vary",
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-max-age",
        "x-content-type-options",
    }
)

# Headers that MUST NEVER be forwarded regardless of extra_allowed_headers.
# These leak server identity or internal infrastructure details.
BLOCKED_HEADERS: frozenset[str] = frozenset(
    {
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-runtime",
        "x-generator",
        "x-drupal-cache",
        "x-varnish",
        "via",
        "x-amz-request-id",
        "x-amz-id-2",
        "x-azure-ref",
        "x-ms-request-id",
        "x-debug",
        "x-debug-token",
        "x-debug-token-link",
    }
)


def sanitize_response_headers(
    headers: dict[str, str],
    extra_allowed: frozenset[str] | None = None,
    server_header: str | None = None,
) -> dict[str, str]:
    """Return a copy of *headers* containing only whitelisted keys.

    Keys are compared case-insensitively.  Any header not in
    ``DEFAULT_SAFE_HEADERS`` (or *extra_allowed*) is stripped.
    Headers in ``BLOCKED_HEADERS`` are **always** stripped, even if
    they appear in *extra_allowed* - this prevents operator
    misconfiguration from leaking server identity.

    Args:
        headers: Raw response headers from the upstream.
        extra_allowed: Additional header names (lowercase) to permit beyond
            the default whitelist.  Useful for domain-specific pass-through
            headers configured via ``DomainConfig.extra_allowed_headers``.
        server_header: If set, inject a ``Server`` header with this value
            (e.g. "nginx") to maintain the redirector's persona.

    Returns:
        Filtered header dict.  The original key casing is preserved.
    """
    allowed: frozenset[str] = DEFAULT_SAFE_HEADERS
    if extra_allowed:
        # Remove any blocked headers the operator accidentally allowed
        allowed = (allowed | extra_allowed) - BLOCKED_HEADERS

    result = {k: v for k, v in headers.items() if k.lower() in allowed}

    # Inject persona Server header to match the redirector's cover identity
    if server_header:
        result["Server"] = server_header

    return result

def preserve_multi_value_headers(
    response,
    upstream_headers,
    multi_value_names: frozenset[str] = frozenset(
        {"set-cookie", "www-authenticate", "proxy-authenticate"}
    ),
) -> None:
    """
    Rebuild response.raw_headers to PRESERVE multi-value upstream headers.

    Starlette's ``Response(headers=Mapping[str, str])`` and any dict cast
    of ``httpx.Headers`` collapse duplicate keys. For headers that
    legitimately repeat (``Set-Cookie`` most importantly), we need to re-emit each
    occurrence from the untouched upstream headers.
    """
    keep = [
        (k, v) for k, v in response.raw_headers
        if k.decode("latin-1").lower() not in multi_value_names
    ]
    for name, value in upstream_headers.multi_items():
        if name.lower() in multi_value_names:
            keep.append(
                (name.lower().encode("latin-1"), value.encode("latin-1"))
            )
    response.raw_headers = keep
