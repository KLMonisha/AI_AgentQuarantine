import asyncio
import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from moss import MossClient, QueryOptions


load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

PROJECT_ID = os.getenv("MOSS_PROJECT_ID")
PROJECT_KEY = os.getenv("MOSS_PROJECT_KEY")

INDEX_NAME = "agent-jail-threats-v2"
TOP_K = 5


if not PROJECT_ID or not PROJECT_KEY:
    raise RuntimeError(
        "Missing MOSS_PROJECT_ID or MOSS_PROJECT_KEY in .env"
    )


def load_evaluation_cases():
    """
    Load:
    - 50 existing threat patterns
    - 50 benign evaluation cases
    - 50 ambiguous evaluation cases

    Total = 150 cases.
    """

    cases = []

    # ---------------------------------------------------------
    # 1. Existing threat corpus
    # ---------------------------------------------------------

    threat_file = BASE_DIR / "threat_patterns.json"

    if not threat_file.exists():
        raise FileNotFoundError(
            f"Missing file: {threat_file}"
        )

    threat_data = json.loads(
        threat_file.read_text(encoding="utf-8")
    )

    # threat_patterns.json uses "threat_patterns"
    threat_patterns = threat_data.get("threat_patterns", [])

    for threat in threat_patterns:

        # Combine the important semantic fields into the query.
        text_parts = [
            threat.get("category", ""),
            threat.get("threat_pattern", ""),
            threat.get("pattern", ""),
            threat.get("description", ""),
            threat.get("attack_intent", ""),
            threat.get("target", ""),
            threat.get("action", ""),
            threat.get("actions", ""),
            threat.get("indicators", ""),
        ]

        text = " ".join(
            str(part)
            for part in text_parts
            if part
        )

        cases.append(
            {
                "id": threat.get("id", "UNKNOWN"),
                "class": "threat",
                "category": threat.get("category", ""),
                "subject": "",
                "body": text,
                "text": text,
                "agent_directed": True,
            }
        )

    # ---------------------------------------------------------
    # 2. Benign cases
    # ---------------------------------------------------------

    benign_file = (
        BASE_DIR /
        "agent_jail_benign_evaluation_50.json"
    )

    if not benign_file.exists():
        raise FileNotFoundError(
            f"Missing file: {benign_file}"
        )

    benign_data = json.loads(
        benign_file.read_text(encoding="utf-8")
    )

    for item in benign_data["records"]:

        subject = item.get("subject", "")
        body = item.get("body", "")

        text = (
            f"Subject: {subject}\n"
            f"Body: {body}"
        )

        cases.append(
            {
                "id": item["id"],
                "class": "benign",
                "category": item.get("category", ""),
                "subject": subject,
                "body": body,
                "text": text,
                "agent_directed": item.get(
                    "agent_directed",
                    False,
                ),
            }
        )

    # ---------------------------------------------------------
    # 3. Ambiguous cases
    # ---------------------------------------------------------

    ambiguous_file = (
        BASE_DIR /
        "agent_jail_ambiguous_evaluation_50.json"
    )

    if not ambiguous_file.exists():
        raise FileNotFoundError(
            f"Missing file: {ambiguous_file}"
        )

    ambiguous_data = json.loads(
        ambiguous_file.read_text(encoding="utf-8")
    )

    for item in ambiguous_data["records"]:

        subject = item.get("subject", "")
        body = item.get("body", "")

        text = (
            f"Subject: {subject}\n"
            f"Body: {body}"
        )

        cases.append(
            {
                "id": item["id"],
                "class": "ambiguous",
                "category": item.get("category", ""),
                "subject": subject,
                "body": body,
                "text": text,
                "agent_directed": item.get(
                    "agent_directed",
                    False,
                ),
            }
        )

    # ---------------------------------------------------------
    # Verify dataset
    # ---------------------------------------------------------

    if len(cases) != 150:
        raise ValueError(
            f"Expected 150 cases, "
            f"but found {len(cases)}."
        )

    counts = {
        "threat": 0,
        "benign": 0,
        "ambiguous": 0,
    }

    for case in cases:
        counts[case["class"]] += 1

    if counts != {
        "threat": 50,
        "benign": 50,
        "ambiguous": 50,
    }:
        raise ValueError(
            f"Unexpected class distribution: {counts}"
        )

    return cases


def parse_moss_result(doc):
    """
    Convert a Moss result document into JSON-safe data.
    """

    return {
        "id": getattr(doc, "id", None),
        "score": float(
            getattr(doc, "score", 0.0)
        ),
        "text": getattr(doc, "text", ""),
    }


async def evaluate_moss():

    cases = load_evaluation_cases()

    print()
    print("=" * 60)
    print("AGENT JAIL - MOSS EVALUATION")
    print("=" * 60)
    print()
    print(f"Index: {INDEX_NAME}")
    print(f"Cases: {len(cases)}")
    print("Threat: 50")
    print("Benign: 50")
    print("Ambiguous: 50")
    print()

    # ---------------------------------------------------------
    # Connect to EXISTING Moss index
    # ---------------------------------------------------------

    client = MossClient(
        PROJECT_ID,
        PROJECT_KEY,
    )

    print(
        f"Loading existing Moss index: "
        f"{INDEX_NAME}"
    )

    await client.load_index(INDEX_NAME)

    print("Index loaded.")
    print()

    # ---------------------------------------------------------
    # Run evaluation
    # ---------------------------------------------------------

    results = []

    total_start = time.perf_counter()

    for number, case in enumerate(
        cases,
        start=1,
    ):

        start = time.perf_counter()

        moss_results = await client.query(
            INDEX_NAME,
            case["text"],
            QueryOptions(
                top_k=TOP_K
            ),
        )

        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        matches = [
            parse_moss_result(doc)
            for doc in moss_results.docs
        ]

        top_match = (
            matches[0]
            if matches
            else None
        )

        result = {
            "id": case["id"],
            "class": case["class"],
            "category": case["category"],
            "agent_directed": case[
                "agent_directed"
            ],
            "subject": case["subject"],
            "body": case["body"],
            "latency_ms": round(
                latency_ms,
                2,
            ),
            "top_score": (
                top_match["score"]
                if top_match
                else 0.0
            ),
            "top_match_id": (
                top_match["id"]
                if top_match
                else None
            ),
            "matches": matches,
        }

        results.append(result)

        # -----------------------------------------------------
        # Console output
        # -----------------------------------------------------

        if top_match:

            print(
                f"[{number:03d}/150] "
                f"{case['class']:<9} "
                f"{case['id']:<15} "
                f"score="
                f"{top_match['score']:.4f} "
                f"match="
                f"{top_match['id']} "
                f"latency="
                f"{latency_ms:.2f}ms"
            )

        else:

            print(
                f"[{number:03d}/150] "
                f"{case['class']:<9} "
                f"{case['id']:<15} "
                f"NO MATCH"
            )

    total_latency_ms = (
        time.perf_counter()
        - total_start
    ) * 1000

    # ---------------------------------------------------------
    # Save results
    # ---------------------------------------------------------

    output_file = (
        BASE_DIR /
        "evaluation_results.json"
    )

    output = {
        "evaluation": {
            "index": INDEX_NAME,
            "top_k": TOP_K,
            "case_count": len(results),
            "total_latency_ms": round(
                total_latency_ms,
                2,
            ),
            "classes": {
                "threat": 50,
                "benign": 50,
                "ambiguous": 50,
            },
        },
        "results": results,
    }

    output_file.write_text(
        json.dumps(
            output,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 60)
    print("EVALUATION COMPLETE")
    print("=" * 60)
    print()
    print(
        f"Results saved to:"
    )
    print(output_file)
    print()
    print(
        f"Total cases: {len(results)}"
    )
    print(
        f"Total query time: "
        f"{total_latency_ms:.2f} ms"
    )


if __name__ == "__main__":
    asyncio.run(
        evaluate_moss()
    )