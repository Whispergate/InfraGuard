"""SSL context factory - builds per-backend SSL verification configuration."""

from __future__ import annotations

import ssl


def build_ssl_context(
    ssl_verify: bool,
    ca_bundle: str | None = None,
) -> ssl.SSLContext | bool:
    """Build an SSL verification object for httpx from domain config fields.

    Args:
        ssl_verify: When ``False`` the upstream certificate is not verified
            (appropriate for C2 teamservers using self-signed certs).
            When ``True`` the system CA store or a custom bundle is used.
        ca_bundle: Path to a PEM-encoded CA certificate bundle.  Only
            consulted when *ssl_verify* is ``True``.

    Returns:
        ``False``          - disable TLS verification entirely.
        ``True``           - use the default system CA store.
        ``ssl.SSLContext`` - use the supplied *ca_bundle* for verification.

    Raises:
        FileNotFoundError: If *ca_bundle* is provided but the file does not
            exist (raised by ``ssl.create_default_context``).
        ssl.SSLError: If *ca_bundle* exists but is not a valid PEM file.
    """
    if not ssl_verify:
        return False

    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle)

    return True
