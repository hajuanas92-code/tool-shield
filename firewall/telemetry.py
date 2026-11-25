"""
OpenTelemetry tracing, optional. Turned on only when OTEL_EXPORTER_OTLP_ENDPOINT is set
(docker-compose sets it for you). Without it, span() does nothing, so nothing else changes.
"""
import logging
import os
from contextlib import contextmanager

log = logging.getLogger("agentguard")
_tracer = None
_provider = None


class _Noop:
    def set_attribute(self, *a, **k):
        pass


def setup() -> None:
    global _tracer, _provider
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        log.warning("OTEL_EXPORTER_OTLP_ENDPOINT is set but opentelemetry packages are missing; tracing off")
        return
    _provider = TracerProvider(resource=Resource.create({"service.name": "agentguard"}))
    _provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))  # endpoint comes from the env var
    trace.set_tracer_provider(_provider)
    _tracer = trace.get_tracer("agentguard")
    log.info("OpenTelemetry tracing enabled")


def shutdown() -> None:
    if _provider is not None:
        _provider.shutdown()  # flushes spans still in the buffer


@contextmanager
def span(name: str, **attrs):
    if _tracer is None:
        yield _Noop()
        return
    with _tracer.start_as_current_span(name) as s:
        for k, v in attrs.items():
            if v is not None:
                s.set_attribute(k, v)
        yield s