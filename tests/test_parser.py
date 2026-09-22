from dataclasses import dataclass

from threat_parser import parse_threat_document, parse_moss_results


@dataclass
class FakeMossDocument:
    id: str
    score: float
    text: str


def test_parse_threat_document():
    doc = FakeMossDocument(
        id="PI-001",
        score=0.94,
        text=(
            "Attack category: instruction override. "
            "Threat pattern: Ignore previous instructions. "
            "Attack description: Attempts to replace the agent's instructions. "
            "Attack intent: Hijack agent behavior. "
            "Target: AI agent. "
            "Actions: Override system instructions. "
            "Indicators: Phrases such as ignore previous instructions."
        ),
    )

    threat = parse_threat_document(doc)

    assert threat["id"] == "PI-001"
    assert threat["score"] == 0.94
    assert threat["category"] == "instruction override"
    assert threat["pattern"] == "Ignore previous instructions"
    assert threat["description"] == "Attempts to replace the agent's instructions"
    assert threat["attack_intent"] == "Hijack agent behavior"
    assert threat["target"] == "AI agent"
    assert threat["actions"] == "Override system instructions"
    assert threat["indicators"] == "Phrases such as ignore previous instructions"


def test_parse_moss_results():
    results = type(
        "FakeResults",
        (),
        {
            "docs": [
                FakeMossDocument(
                    id="PI-001",
                    score=0.94,
                    text="Attack category: instruction override.",
                ),
                FakeMossDocument(
                    id="PI-028",
                    score=0.99,
                    text="Attack category: destructive email action.",
                ),
            ]
        },
    )()

    threats = parse_moss_results(results)

    assert len(threats) == 2
    assert threats[0]["id"] == "PI-001"
    assert threats[0]["score"] == 0.94
    assert threats[1]["id"] == "PI-028"
    assert threats[1]["score"] == 0.99