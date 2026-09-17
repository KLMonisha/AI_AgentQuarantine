from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TrustLevel(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass
class Provenance:
    source: str
    source_type: str
    trust_level: TrustLevel
    description: str = ""


@dataclass
class TaintedContent:
    content: str
    trust_level: TrustLevel
    source: str
    source_type: str
    provenance: list[Provenance] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_tainted(self) -> bool:
        return self.trust_level == TrustLevel.UNTRUSTED

    def add_provenance(
        self,
        source: str,
        source_type: str,
        trust_level: TrustLevel,
        description: str = "",
    ):
        self.provenance.append(
            Provenance(
                source=source,
                source_type=source_type,
                trust_level=trust_level,
                description=description,
            )
        )


def trusted_content(
    content: str,
    source: str,
    source_type: str = "user",
) -> TaintedContent:
    """
    Create content originating from a trusted source.
    """

    item = TaintedContent(
        content=content,
        trust_level=TrustLevel.TRUSTED,
        source=source,
        source_type=source_type,
    )

    item.add_provenance(
        source=source,
        source_type=source_type,
        trust_level=TrustLevel.TRUSTED,
        description="Trusted origin",
    )

    return item


def untrusted_content(
    content: str,
    source: str,
    source_type: str,
    metadata: dict[str, Any] | None = None,
) -> TaintedContent:
    """
    Create content originating from an untrusted external source.
    """

    item = TaintedContent(
        content=content,
        trust_level=TrustLevel.UNTRUSTED,
        source=source,
        source_type=source_type,
        metadata=metadata or {},
    )

    item.add_provenance(
        source=source,
        source_type=source_type,
        trust_level=TrustLevel.UNTRUSTED,
        description="Untrusted external origin",
    )

    return item


def propagate_taint(
    content: TaintedContent,
    new_content: str,
    transformation: str,
) -> TaintedContent:
    """
    Propagate taint when content is transformed, summarized,
    extracted, or passed through another agent step.

    Taint is preserved unless the transformation is explicitly
    trusted and verified elsewhere.
    """

    derived = TaintedContent(
        content=new_content,
        trust_level=content.trust_level,
        source=content.source,
        source_type=content.source_type,
        provenance=list(content.provenance),
        metadata=dict(content.metadata),
    )

    derived.add_provenance(
        source=content.source,
        source_type=content.source_type,
        trust_level=content.trust_level,
        description=transformation,
    )

    return derived


def display_taint(content: TaintedContent):
    """
    Print a human-readable representation of the trust state.
    """

    print("\n" + "=" * 60)
    print("AGENT JAIL — TAINT INSPECTOR")
    print("=" * 60)

    print(f"Content:       {content.content}")
    print(f"Trust Level:   {content.trust_level.value.upper()}")
    print(f"Tainted:       {'YES' if content.is_tainted else 'NO'}")
    print(f"Source:        {content.source}")
    print(f"Source Type:   {content.source_type}")

    print("\nProvenance:")
    for i, entry in enumerate(content.provenance, start=1):
        print(
            f"  {i}. {entry.source} "
            f"[{entry.trust_level.value}] "
            f"→ {entry.description}"
        )

    if content.metadata:
        print("\nMetadata:")
        for key, value in content.metadata.items():
            print(f"  {key}: {value}")

    print("=" * 60)