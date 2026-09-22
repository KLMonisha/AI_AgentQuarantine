from policy import evaluate_policy, SecurityDecision, RiskLevel


def test_trusted_content():
    decision = evaluate_policy(
        tainted=False,
        threat_matches=[],
    )

    assert decision.decision == SecurityDecision.ALLOW
    assert decision.risk == RiskLevel.LOW


def test_tainted_but_benign():
    decision = evaluate_policy(
        tainted=True,
        threat_matches=[],
    )

    assert decision.decision == SecurityDecision.ALLOW
    assert decision.risk == RiskLevel.LOW


def test_threat_detected():
    decision = evaluate_policy(
        tainted=True,
        threat_matches=[
            {
                "category": "instruction_override",
                "score": 0.91,
            }
        ],
    )

    assert decision.decision == SecurityDecision.QUARANTINE
    assert decision.risk == RiskLevel.HIGH


def test_threat_with_privileged_action():
    decision = evaluate_policy(
        tainted=True,
        threat_matches=[
            {
                "category": "email_exfiltration",
                "score": 0.97,
            },
            {
                "category": "instruction_override",
                "score": 0.88,
            },
        ],
        requested_action="forward_email",
    )

    assert decision.decision == SecurityDecision.BLOCK
    assert decision.risk == RiskLevel.CRITICAL