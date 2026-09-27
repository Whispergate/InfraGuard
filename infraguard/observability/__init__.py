"""Optional OpenTelemetry integration.

Adds distributed tracing spans that link a single beacon hit across
the redirector: listener accept, filter pipeline, upstream forward,
response write. If the ``opentelemetry-api`` package is not installed,
the module exposes no-op shims so nothing has to guard imports at
call sites.

Usage:

    from infraguard.observability import setup_otel, span
    setup_otel(service_name="infraguard-proxy", endpoint="http://otel:4318")
    with span("router.handle", domain=route.domain, client=str(client_ip)):
        ...

Nothing is enabled by default. Wire in ``core/app.py`` lifespan if
``config.observability.otel.enabled``.
"""

from infraguard.observability.otel import (
    otel_available,
    setup_otel,
    shutdown_otel,
    span,
    tracer,
)

__all__ = ["otel_available", "setup_otel", "shutdown_otel", "span", "tracer"]
