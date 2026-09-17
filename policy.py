from dataclasses import dataclass
from enum import Enum


class SecurityDecision(Enum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PolicyDecision:
    decision: SecurityDecision
    risk: RiskLevel
    reason: str
    matched_threats: list[str]


# Threat categories that indicate malicious influence.
HIGH_RISK_CATEGORIES = {
    "instruction_override",
    "email_exfiltration",
    "agent_action_hijacking",
    "destructive_email_action",
    "data_exfiltration",
    "prompt_extraction",
    "authority_impersonation",
    "injection_propagation",
}


# Actions that can have external side effects.
PRIVILEGED_ACTIONS = {
    "send_email",
    "forward_email",
    "delete_email",
    "send_message",
    "modify_file",
    "delete_file",
    "execute_api",
}


def evaluate_policy(
    tainted: bool,
    threat_matches: list[dict],
    requested_action: str | None = None,
) -> PolicyDecision:

    # --------------------------------------------------
    # Rule 1 — Trusted content
    # --------------------------------------------------

    if not tainted:
        return PolicyDecision(
            decision=SecurityDecision.ALLOW,
            risk=RiskLevel.LOW,
            reason="Content originates from a trusted source.",
            matched_threats=[],
        )

    # --------------------------------------------------
    # Extract meaningful threat matches
    # --------------------------------------------------

    matched_threats = []

    for match in threat_matches:

        category = match["category"]
        score = match["score"]

        if (
            category in HIGH_RISK_CATEGORIES
            and score >= 0.85
        ):
            matched_threats.append(category)

    # --------------------------------------------------
    # Rule 2 — Tainted but no strong threat evidence
    # --------------------------------------------------

    if not matched_threats:
        return PolicyDecision(
            decision=SecurityDecision.ALLOW,
            risk=RiskLevel.LOW,
            reason=(
                "Content is untrusted but no strong "
                "prompt-injection threat was identified."
            ),
            matched_threats=[],
        )

    # --------------------------------------------------
    # Rule 3 — Tainted content attempting a
    # privileged external action
    # --------------------------------------------------

    if requested_action in PRIVILEGED_ACTIONS:

        return PolicyDecision(
            decision=SecurityDecision.BLOCK,
            risk=RiskLevel.CRITICAL,
            reason=(
                "Tainted content is associated with a high-risk "
                "threat and attempts a privileged action."
            ),
            matched_threats=matched_threats,
        )

    # --------------------------------------------------
    # Rule 4 — Threat detected but no privileged
    # action requested yet
    # --------------------------------------------------

    return PolicyDecision(
        decision=SecurityDecision.QUARANTINE,
        risk=RiskLevel.HIGH,
        reason=(
            "Tainted content contains strong threat indicators "
            "and has been isolated from trusted agent reasoning."
        ),
        matched_threats=matched_threats,
    )