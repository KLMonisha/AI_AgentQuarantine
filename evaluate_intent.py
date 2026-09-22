import json
from pathlib import Path

from intent_analysis import analyze_intent


BASE_DIR = Path(__file__).resolve().parent

DATASETS = [
    ("threat", BASE_DIR / "threat_patterns.json"),
    ("benign", BASE_DIR / "agent_jail_benign_evaluation_50.json"),
    ("ambiguous", BASE_DIR / "agent_jail_ambiguous_evaluation_50.json"),
]


def load_records(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Evaluation datasets use {"records": [...]}
    if isinstance(data, dict) and "records" in data:
        return data["records"]

    # Threat corpus uses {"threat_patterns": [...]}
    if isinstance(data, dict) and "threat_patterns" in data:
        return data["threat_patterns"]

    if isinstance(data, list):
        return data

    raise ValueError(f"Unknown dataset structure: {path}")


def extract_content(case):
    """
    Build the text that would actually be analyzed.

    For email evaluation cases, include subject + body.
    For threat patterns, combine the semantic threat description
    fields used by the corpus.
    """

    if "body" in case:
        subject = case.get("subject", "")
        body = case.get("body", "")
        return f"{subject}\n{body}".strip()

    parts = [
        case.get("threat_pattern", ""),
        case.get("attack_description", ""),
        case.get("attack_intent", ""),
        case.get("indicators", ""),
        case.get("actions", ""),
    ]

    return "\n".join(
        part for part in parts
        if isinstance(part, str) and part.strip()
    )


def evaluate_dataset(label, path):
    records = load_records(path)

    agent_directed = 0
    human_directed = 0
    overrides = 0
    privileged = 0
    sensitive = 0

    for case in records:
        content = extract_content(case)

        if not content:
            continue

        result = analyze_intent(content)

        if result.agent_directed:
            agent_directed += 1

        if result.human_directed:
            human_directed += 1

        if result.instruction_override:
            overrides += 1

        if result.requests_privileged_action:
            privileged += 1

        if result.sensitive_data_request:
            sensitive += 1

    return {
        "total": len(records),
        "agent_directed": agent_directed,
        "human_directed": human_directed,
        "instruction_override": overrides,
        "privileged_action": privileged,
        "sensitive_data": sensitive,
    }


def main():
    print("=" * 70)
    print("AGENT JAIL — INTENT ANALYSIS EVALUATION")
    print("=" * 70)

    totals = {}

    for label, path in DATASETS:
        stats = evaluate_dataset(label, path)
        totals[label] = stats

        print(f"\n{label.upper()}")
        print("-" * 40)
        print(f"Cases:                 {stats['total']}")
        print(f"Agent-directed:        {stats['agent_directed']}")
        print(f"Human-directed:        {stats['human_directed']}")
        print(f"Instruction override:  {stats['instruction_override']}")
        print(f"Privileged action:     {stats['privileged_action']}")
        print(f"Sensitive data:        {stats['sensitive_data']}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    for label, stats in totals.items():
        print(
            f"{label:10} | "
            f"agent-directed={stats['agent_directed']:2} | "
            f"override={stats['instruction_override']:2} | "
            f"privileged={stats['privileged_action']:2}"
        )


if __name__ == "__main__":
    main()