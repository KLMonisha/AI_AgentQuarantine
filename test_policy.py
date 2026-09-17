from policy import evaluate_policy


# --------------------------------------------------
# Test 1 — Trusted content
# --------------------------------------------------

decision = evaluate_policy(
    tainted=False,
    threat_matches=[],
)

print("TEST 1 — Trusted content")
print(decision)
print()


# --------------------------------------------------
# Test 2 — Tainted but benign
# --------------------------------------------------

decision = evaluate_policy(
    tainted=True,
    threat_matches=[],
)

print("TEST 2 — Tainted but no threat")
print(decision)
print()


# --------------------------------------------------
# Test 3 — Threat detected, no dangerous action
# --------------------------------------------------

decision = evaluate_policy(
    tainted=True,
    threat_matches=[
        {
            "category": "instruction_override",
            "score": 0.91,
        }
    ],
)

print("TEST 3 — Threat detected")
print(decision)
print()


# --------------------------------------------------
# Test 4 — Threat + privileged action
# --------------------------------------------------

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

print("TEST 4 — Threat + privileged action")
print(decision)
print()


print("✅ POLICY TESTS COMPLETED")