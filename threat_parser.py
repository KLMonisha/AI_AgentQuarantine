import re


def parse_threat_document(doc):
    """
    Convert a Moss Document result into structured threat evidence.

    Expected Moss text format:

    Attack category: ...
    Threat pattern: ...
    Attack description: ...
    Attack intent: ...
    Target: ...
    Actions: ...
    Indicators: ...
    """

    text = doc.text

    def extract(field_name):
        pattern = rf"{field_name}:\s*(.*?)(?=\.\s+[A-Z][A-Za-z ]*:|$)"
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)

        if not match:
            return ""

        return match.group(1).strip()

    return {
        "id": doc.id,
        "score": doc.score,
        "category": extract("Attack category").rstrip("."),
        "pattern": extract("Threat pattern").rstrip("."),
        "description": extract("Attack description").rstrip("."),
        "attack_intent": extract("Attack intent").rstrip("."),
        "target": extract("Target").rstrip("."),
        "actions": extract("Actions").rstrip("."),
        "indicators": extract("Indicators").rstrip("."),
    }


def parse_moss_results(results):
    """
    Convert all Moss documents into structured threat evidence.
    """

    return [
        parse_threat_document(doc)
        for doc in results.docs
    ]


def display_threat_evidence(threats):
    """
    Display structured threat evidence.
    """

    print("\n" + "=" * 70)
    print("AGENT JAIL — STRUCTURED THREAT EVIDENCE")
    print("=" * 70)

    for i, threat in enumerate(threats, start=1):

        print(f"\nThreat #{i}")
        print(f"ID:       {threat['id']}")
        print(f"Score:    {threat['score']:.4f}")
        print(f"Category: {threat['category']}")
        print(f"Intent:   {threat['attack_intent']}")
        print(f"Target:   {threat['target']}")
        print(f"Actions:  {threat['actions']}")

    print("\n" + "=" * 70)