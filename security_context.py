from dataclasses import dataclass, field

from taint import TaintedContent
from quarantine import QuarantineVault

@dataclass
class ContentSecurityResult:
    content: TaintedContent
    threat_matches: list[dict] = field(default_factory=list)
    decision: object | None = None
@dataclass
class SecurityContext:
    """
    Security state associated with the current agent execution.

    The context tracks both untrusted content that can currently
    influence the agent and security evidence observed during the
    execution.
    """

    tainted: bool = False

    tainted_content: list[TaintedContent] = field(
        default_factory=list
    )

    quarantined_content: list[TaintedContent] = field(
        default_factory=list
    )

    threat_matches: list[dict] = field(
        default_factory=list
    )

    quarantine_vault: QuarantineVault = field(
        default_factory=QuarantineVault
    )

    content_results: list[ContentSecurityResult] = field(
        default_factory=list
    )

    def add_content_result(
        self,
        content: TaintedContent,
        threat_matches: list[dict],
        decision,
    ):
        self.content_results.append(
            ContentSecurityResult(
                content=content,
                threat_matches=threat_matches,
                decision=decision,
            )
        )

    def active_threats(self) -> list[dict]:
        threats = []

        for item in self.content_results:
            if item.content in self.quarantined_content:
                continue

            if item.decision and item.decision.decision.value != "allow":
                threats.extend(item.threat_matches)

        return threats

    def add_tainted_content(
        self,
        content: TaintedContent,
    ):
        """
        Add untrusted content that is currently available
        to the agent.
        """

        if not content.is_tainted:
            return

        self.tainted = True
        self.tainted_content.append(content)

    def quarantine_content(
        self,
        content: TaintedContent,
    ):
        """
        Move tainted content out of the active agent context.
        """

        if content in self.tainted_content:
            self.tainted_content.remove(content)

        self.quarantined_content.append(content)

        # Recalculate whether active tainted content remains.
        self.tainted = len(self.tainted_content) > 0


    def clear(self):
        """
        Reset the security context.
        """

        self.tainted = False
        self.tainted_content.clear()
        self.quarantined_content.clear()
        self.threat_matches.clear()

    def has_active_threat(self) -> bool:
        return len(self.active_threats()) > 0

    def active_risk_level(self):
        risks = [
            item.decision.risk
            for item in self.content_results
            if item.content not in self.quarantined_content
            and item.decision
            and item.decision.decision.value != "allow"
        ]

        if not risks:
            return None

        priority = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        return max(risks, key=lambda r: priority[r.value])

    def summary(self):
        """
        Return a simple representation useful for logging/debugging.
        """

        return {
            "tainted": self.tainted,
            "tainted_sources": [
                content.source
                for content in self.tainted_content
            ],
            "quarantined_count": len(
                self.quarantined_content
            ),
            "active_threat_count": len(
                self.active_threats()
            ),
        }