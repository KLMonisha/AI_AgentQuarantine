from telemetry import start_span


with start_span("agent_jail.test") as span:
    span.set_attribute("test.component", "Agent Jail")
    span.set_attribute("test.status", "working")

print("Telemetry test complete.")