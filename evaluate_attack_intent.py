import json
from pathlib import Path

from intent_analysis import analyze_intent


BASE_DIR = Path(__file__).resolve().parent
DATASET = BASE_DIR / "agent_jail_attack_intent_20.json"


def main():
    with open(DATASET, "r", encoding="utf-8") as f:
        data = json.load(f)

    records = data["records"]

    correct = 0

    print("=" * 70)
    print("AGENT JAIL — ATTACK INTENT EVALUATION")
    print("=" * 70)

    for case in records:
        result = analyze_intent(case["body"])

        predicted = result.agent_directed
        expected = case["expected_agent_directed"]

        is_correct = predicted == expected

        if is_correct:
            correct += 1

        status = "PASS" if is_correct else "FAIL"

        print(
            f"{status} | "
            f"{case['id']} | "
            f"{case['category']:28} | "
            f"predicted={predicted}"
        )

    accuracy = correct / len(records) * 100

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)
    print(f"Correct:  {correct}/{len(records)}")
    print(f"Accuracy: {accuracy:.1f}%")


if __name__ == "__main__":
    main()