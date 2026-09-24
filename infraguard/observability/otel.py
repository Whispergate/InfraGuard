"""Thin wrapper over ``opentelemetry`` with no-op fallbacks.

Callers can use ``span(name, **attrs)`` and ``tracer()`` unconditionally;
if OTEL is not installed the calls become cheap no-ops.
"""

from __future__ import annotations

import contextlib
from typing import Any

import structlog

log = structlog.get_logger()

_TRACER: Any = None
_PROVIDER: Any = None


def otel_available() -> bool:
    try:
        import opentelemetry  # noqa: F401
    except ImportError:
        return False
    return True


def setup_otel(
    *,
    service_name: str = "infraguard",
    endpoint: str | None = None,
    resource_attrs: dict[str, str] | None = None,
) -> bool:
    """Initialize a global tracer. Returns True on success.

    ``endpoint`` is an OTLP HTTP endpoint (e.g. ``http://otel:4318``).
    When None, spans are still created and can be sampled by a
    console exporter for local dev.
    """
    global _TRACER, _PROVIDER

    if not otel_available():
        log.info("otel_not_installed_using_noop_shims")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create({SERVICE_NAME: service_name, **(resource_attrs or {})})
        provider = TracerProvider(resource=resource)

        if endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter,
                )

                provider.add_span_processor(
                    BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces"))
                )
            except ImportError:
                log.warning(
                    "otel_otlp_exporter_missing",
                    install="pip install opentelemetry-exporter-otlp-proto-http",
                )
        else:
            try:
                from opentelemetry.sdk.trace.export import ConsoleSpanExporter

                provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
            except ImportError:
                pass

        trace.set_tracer_provider(provider)
        _PROVIDER = provider
        _TRACER = trace.get_tracer("infraguard", "1.0.0")
        log.info("otel_initialized", service=service_name, endpoint=endpoint or "console")
        return True
    except Exception as exc:
        log.warning("otel_setup_failed", error=str(exc))
        return False


def shutdown_otel() -> None:
    if _PROVIDER is not None:
        try:
            _PROVIDER.shutdown()
        except Exception:
            pass


def tracer() -> Any:
    return _TRACER


@contextlib.contextmanager
def span(name: str, **attrs: Any):
    """Context manager that creates a span if OTEL is up, else no-op."""
    if _TRACER is None:
        yield None
        return
    with _TRACER.start_as_current_span(name) as s:
        for k, v in attrs.items():
            try:
                s.set_attribute(k, v)
            except Exception:
                pass
        yield s
