from dataclasses import dataclass
from enum import Enum
from telemetry import start_span

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
    intent_analysis=None,
    ) -> PolicyDecision:

    with start_span("policy.evaluate") as span:
        def record_policy_span(decision):
            span.set_attribute(
                "policy.decision",
                decision.decision.value,
            )
            span.set_attribute(
                "policy.risk",
                decision.risk.value,
            )
            span.set_attribute(
                "policy.high_risk_threat_count",
                len(decision.matched_threats),
            )
            return decision

        # --------------------------------------------------
        # Rule 1 — Trusted content
        # --------------------------------------------------

        if not tainted:
            return record_policy_span(PolicyDecision(
                decision=SecurityDecision.ALLOW,
                risk=RiskLevel.LOW,
                reason="Content originates from a trusted source.",
                matched_threats=[],
            ))

        # --------------------------------------------------
        # Extract meaningful Moss threat matches
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
        # Rule 2 — Tainted but no strong Moss evidence
        # --------------------------------------------------

        if not matched_threats:
            return record_policy_span(PolicyDecision(
                decision=SecurityDecision.ALLOW,
                risk=RiskLevel.LOW,
                reason=(
                    "Content is untrusted but no strong "
                    "prompt-injection threat was identified."
                ),
                matched_threats=[],
            ))

        # --------------------------------------------------
        # Rule 3 — Strong Moss evidence but content is
        # human-directed rather than agent-directed
        # --------------------------------------------------

        if (
            intent_analysis is not None
            and not intent_analysis.agent_directed
        ):
            return record_policy_span(PolicyDecision(
                decision=SecurityDecision.ALLOW,
                risk=RiskLevel.LOW,
                reason=(
                    "Content resembles known threat patterns "
                    "semantically, but intent analysis indicates "
                    "that the content is human-directed and is not "
                    "attempting to manipulate the agent."
                ),
                matched_threats=matched_threats,
            ))

        # --------------------------------------------------
        # Rule 4 — Strong threat + agent-directed content +
        # privileged action
        # --------------------------------------------------

        if (
            intent_analysis is not None
            and intent_analysis.agent_directed
            and (
                requested_action in PRIVILEGED_ACTIONS
                or intent_analysis.requests_privileged_action
            )
        ):
            return record_policy_span(PolicyDecision(
                decision=SecurityDecision.BLOCK,
                risk=RiskLevel.CRITICAL,
                reason=(
                    "Tainted content matches a high-risk threat and "
                    "intent analysis indicates an agent-directed "
                    "attempt to perform a privileged action."
                ),
                matched_threats=matched_threats,
            )
            )
        # --------------------------------------------------
        # Rule 5 — Strong threat + agent-directed content
        # --------------------------------------------------

        if (
            intent_analysis is not None
            and intent_analysis.agent_directed
        ):
            return record_policy_span(PolicyDecision(
                decision=SecurityDecision.QUARANTINE,
                risk=RiskLevel.HIGH,
                reason=(
                    "Tainted content matches high-risk threat patterns "
                    "and intent analysis indicates an attempt to "
                    "influence or manipulate the agent."
                ),
                matched_threats=matched_threats,
            ))

        # --------------------------------------------------
        # Rule 6 — Backward-compatible fallback
        #
        # Used when no Gemini intent analysis is supplied.
        # --------------------------------------------------

        if requested_action in PRIVILEGED_ACTIONS:
            return record_policy_span(PolicyDecision(
                decision=SecurityDecision.BLOCK,
                risk=RiskLevel.CRITICAL,
                reason=(
                    "Tainted content is associated with a high-risk "
                    "threat and attempts a privileged action."
                ),
                matched_threats=matched_threats,
            ))

        def record_policy_span(decision):
            span.set_attribute("policy.decision", decision.decision.value)
            span.set_attribute("policy.risk", decision.risk.value)
            span.set_attribute(
                "policy.threat_count",
                len(decision.matched_threats),
            )
            return decision

        return record_policy_span(PolicyDecision(
            decision=SecurityDecision.QUARANTINE,
            risk=RiskLevel.HIGH,
            reason=(
                "Tainted content contains strong threat indicators "
                "and has been isolated from trusted agent reasoning."
            ),
            matched_threats=matched_threats,
        ))