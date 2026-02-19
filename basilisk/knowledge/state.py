"""Knowledge state — delta-tracking wrapper around KnowledgeGraph."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from basilisk.decisions.decision import ContextSnapshot
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.observations.observation import Observation

if TYPE_CHECKING:
    from basilisk.orchestrator.planner import KnowledgeGap, Planner


@dataclass
class ObservationOutcome:
    """Result of applying a single observation — captures before/after confidence."""

    entity_id: str
    was_new: bool
    confidence_before: float
    confidence_after: float

    @property
    def confidence_delta(self) -> float:
        return self.confidence_after - self.confidence_before


class KnowledgeState:
    """Delta-tracking wrapper around KnowledgeGraph.

    Reuses the graph's merge logic but captures confidence before/after
    for every observation applied. Does NOT replace the graph — wraps it.
    """

    def __init__(
        self, graph: KnowledgeGraph, planner: Planner | None = None,
    ) -> None:
        self.graph = graph
        self._planner = planner

    def apply_observation(self, obs: Observation) -> ObservationOutcome:
        """Apply observation to graph and return delta information."""
        entity_id = Entity.make_id(obs.entity_type, **obs.key_fields)
        now = datetime.now(UTC)

        existing = self.graph.get(entity_id)
        confidence_before = existing.confidence if existing else 0.0
        was_new = existing is None

        entity = Entity(
            id=entity_id,
            type=obs.entity_type,
            data=obs.entity_data,
            confidence=obs.confidence,
            evidence=[obs.evidence] if obs.evidence else [],
            first_seen=now,
            last_seen=now,
        )

        merged = self.graph.add_entity(entity)
        confidence_after = merged.confidence

        if obs.relation:
            self.graph.add_relation(obs.relation)

        return ObservationOutcome(
            entity_id=entity_id,
            was_new=was_new,
            confidence_before=confidence_before,
            confidence_after=confidence_after,
        )

    def snapshot(self, step: int, elapsed: float, gap_count: int) -> ContextSnapshot:
        """Create a deterministic snapshot of current graph state."""
        return ContextSnapshot(
            entity_count=self.graph.entity_count,
            relation_count=self.graph.relation_count,
            host_count=len(self.graph.hosts()),
            service_count=len(self.graph.services()),
            finding_count=len(self.graph.findings()),
            gap_count=gap_count,
            elapsed_seconds=elapsed,
            step=step,
        )

    def find_gaps(self) -> list[KnowledgeGap]:
        """Delegate gap detection to planner or graph."""
        if self._planner:
            return self._planner.find_gaps(self.graph)
        return self.graph.find_missing_knowledge()
