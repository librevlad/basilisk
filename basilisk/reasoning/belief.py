"""Evidence aggregator — multi-source belief revision within a step."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from basilisk.observations.source_families import get_source_family

if TYPE_CHECKING:
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.reasoning.hypothesis import HypothesisEngine

logger = logging.getLogger(__name__)


class EvidenceAggregator:
    """Track evidence across a step and apply belief revision.

    After a step, entities observed by 2+ independent source families
    get a confidence bonus. Contradictions get a penalty.
    """

    def __init__(
        self,
        graph: KnowledgeGraph,
        hypothesis_engine: HypothesisEngine | None = None,
    ) -> None:
        self._graph = graph
        self._hypothesis_engine = hypothesis_engine
        # Per-step evidence: entity_id → [(plugin, family, delta)]
        self._step_evidence: dict[str, list[tuple[str, str, float]]] = defaultdict(list)

    def record_evidence(
        self,
        entity_id: str,
        source_plugin: str,
        confidence_delta: float,
    ) -> None:
        """Record an evidence observation for this step."""
        family = get_source_family(source_plugin)
        self._step_evidence[entity_id].append((source_plugin, family, confidence_delta))

    def revise_beliefs(self) -> list[tuple[str, float, float]]:
        """Apply belief revision based on accumulated step evidence.

        For entities with evidence from 2+ source families:
        - Independence bonus: +0.05 per additional family (max +0.15)
        - Contradiction: if families disagree on direction, -0.1

        Returns list of (entity_id, old_confidence, new_confidence).
        """
        revisions: list[tuple[str, float, float]] = []

        for entity_id, evidence_list in self._step_evidence.items():
            entity = self._graph.get(entity_id)
            if entity is None:
                continue

            # Group by source family
            families: dict[str, list[float]] = defaultdict(list)
            for _plugin, family, delta in evidence_list:
                families[family].append(delta)

            family_count = len(families)
            if family_count < 2:
                continue

            old_conf = entity.confidence

            # Independence bonus: +0.05 per extra family, max +0.15
            independence_bonus = min((family_count - 1) * 0.05, 0.15)

            # Check for contradictions (some families positive, some negative)
            positive_families = sum(
                1 for deltas in families.values() if sum(deltas) > 0
            )
            negative_families = sum(
                1 for deltas in families.values() if sum(deltas) < 0
            )
            contradiction_penalty = -0.1 if positive_families > 0 and negative_families > 0 else 0.0

            adjustment = independence_bonus + contradiction_penalty
            entity.confidence = max(0.1, min(1.0, entity.confidence + adjustment))

            if entity.confidence != old_conf:
                revisions.append((entity_id, old_conf, entity.confidence))

        return revisions

    def reset_step(self) -> None:
        """Clear step evidence for the next iteration."""
        self._step_evidence.clear()
