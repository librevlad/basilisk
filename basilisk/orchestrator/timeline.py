"""Structured execution log for the autonomous loop."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class TimelineEntry:
    """A single step in the execution timeline."""

    step: int
    timestamp: float
    capability: str
    target_entity: str
    knowledge_gained: list[str] = field(default_factory=list)
    confidence_delta: float = 0.0
    reason: str = ""
    duration: float = 0.0


class Timeline:
    """Records the full execution history of the autonomous loop."""

    def __init__(self) -> None:
        self.entries: list[TimelineEntry] = []

    def record_step(
        self,
        step: int,
        chosen: list,
        *,
        gaps_found: int = 0,
    ) -> None:
        """Record a batch of capabilities executed in one step."""
        now = time.monotonic()
        for sc in chosen:
            self.entries.append(TimelineEntry(
                step=step,
                timestamp=now,
                capability=sc.capability.name,
                target_entity=sc.target_entity.data.get("host", sc.target_entity.id[:8]),
                reason=sc.reason,
            ))

    def record_result(
        self,
        capability_name: str,
        target_host: str,
        new_entity_ids: list[str],
        confidence_delta: float,
        duration: float,
    ) -> None:
        """Update the most recent entry for this capability with results."""
        for entry in reversed(self.entries):
            if entry.capability == capability_name and entry.target_entity == target_host:
                entry.knowledge_gained = new_entity_ids
                entry.confidence_delta = confidence_delta
                entry.duration = duration
                break

    def summary(self) -> str:
        """Human-readable execution log."""
        lines = []
        for entry in self.entries:
            gained = f"+{len(entry.knowledge_gained)} entities" if entry.knowledge_gained else ""
            lines.append(
                f"  Step {entry.step}: {entry.capability} → {entry.target_entity} "
                f"({entry.duration:.1f}s) {gained}"
            )
        return "\n".join(lines) if lines else "  (no steps executed)"

    @property
    def total_steps(self) -> int:
        if not self.entries:
            return 0
        return self.entries[-1].step

    @property
    def total_entities_gained(self) -> int:
        return sum(len(e.knowledge_gained) for e in self.entries)
