from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from taint import TaintedContent
from policy import PolicyDecision
from telemetry import start_span

class QuarantineStatus:
    QUARANTINED = "quarantined"
    RELEASED = "released"


@dataclass
class QuarantineItem:
    id: str
    content: TaintedContent
    decision: PolicyDecision
    requested_action: str | None
    status: str = QuarantineStatus.QUARANTINED
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def release(self):
        self.status = QuarantineStatus.RELEASED


class QuarantineVault:

    def __init__(self):
        self.items: dict[str, QuarantineItem] = {}
        self._counter = 0

    def quarantine(
    self,
    content: TaintedContent,
    decision: PolicyDecision,
    requested_action: str | None = None,
) -> QuarantineItem:

        with start_span("quarantine.store") as span:
            span.set_attribute(
                "quarantine.source",
                content.source,
            )
            span.set_attribute(
                "quarantine.source_type",
                content.source_type,
            )
            span.set_attribute(
                "quarantine.decision",
                decision.decision.value,
            )
            span.set_attribute(
                "quarantine.risk",
                decision.risk.value,
            )

            self._counter += 1

            item_id = f"AJ-Q-{self._counter:04d}"

            item = QuarantineItem(
                id=item_id,
                content=content,
                decision=decision,
                requested_action=requested_action,
            )

            self.items[item_id] = item

            span.set_attribute(
                "quarantine.item_id",
                item_id,
            )
            span.set_attribute(
                "quarantine.vault_size",
                len(self.items),
            )

            return item

    def get(self, item_id: str) -> QuarantineItem | None:
        return self.items.get(item_id)

    def list_items(self) -> list[QuarantineItem]:
        return list(self.items.values())

    def display(self):

        print("\n" + "=" * 70)
        print("AGENT JAIL — QUARANTINE VAULT")
        print("=" * 70)

        if not self.items:
            print("Vault is empty.")
            return

        for item in self.items.values():

            print(f"\nID:               {item.id}")
            print(f"Status:           {item.status.upper()}")
            print(f"Source:           {item.content.source}")
            print(f"Source Type:      {item.content.source_type}")
            print(f"Risk:             {item.decision.risk.value.upper()}")
            print(f"Decision:         {item.decision.decision.value.upper()}")
            print(f"Requested Action: {item.requested_action}")
            print(f"Created:          {item.created_at}")

            print("\nMatched Threats:")

            for threat in item.decision.matched_threats:
                print(f"  - {threat}")

            print("\nOriginal Content:")
            print(f"  {item.content.content}")

            print("-" * 70)