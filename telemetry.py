from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)


# ============================================================
# OPEN TELEMETRY SETUP
# ============================================================

provider = TracerProvider()

provider.add_span_processor(
    SimpleSpanProcessor(
        ConsoleSpanExporter()
    )
)

trace.set_tracer_provider(provider)

tracer = trace.get_tracer("agent-jail")


# ============================================================
# HELPERS
# ============================================================

def start_span(name: str):
    """
    Create a new OpenTelemetry span for Agent Jail.
    """

    return tracer.start_as_current_span(name)