"""Confidence model — maps verification verdicts to confidence updates."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    from basilisk.knowledge.entities import Entity
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.knowledge.vulns.registry import VulnRegistry

logger = logging.getLogger(__name__)

# Verdict → base confidence delta
_VERDICT_DELTAS: dict[str, float] = {
    "confirmed": 0.3,
    "likely": 0.1,
    "false_positive": -0.3,
    "inconclusive": 0.0,
}


class ConfidenceUpdate(BaseModel):
    """A confidence adjustment to apply to an entity."""

    entity_id: str
    old_confidence: float
    new_confidence: float
    reason: str
    source_count: int = 1


class ConfidenceModel:
    """Maps verification verdicts to confidence deltas.

    Uses VulnRegistry thresholds when available, else hardcoded defaults.
    """

    def __init__(self, vuln_registry: VulnRegistry | None = None) -> None:
        self._registry = vuln_registry

    def update_from_verification(
        self,
        entity: Entity,
        verdict: str,
        category: str = "",
        source_count: int = 1,
    ) -> ConfidenceUpdate:
        """Compute confidence update for a verification verdict.

        Args:
            entity: The entity being verified.
            verdict: One of confirmed|likely|false_positive|inconclusive.
            category: Vuln category for registry threshold lookup.
            source_count: Number of independent sources confirming.

        Returns:
            ConfidenceUpdate with old and new confidence values.
        """
        old_conf = entity.confidence

        # Get thresholds from registry or use defaults
        thresholds = None
        if self._registry and category:
            thresholds = self._registry.confidence_thresholds_for(category)

        base_delta = _VERDICT_DELTAS.get(verdict, 0.0)

        if thresholds and verdict == "confirmed":
            base_delta = thresholds.verification_bonus
        elif thresholds and verdict == "false_positive":
            base_delta = -thresholds.false_positive_cap

        # Multi-source bonus
        multi_bonus = 0.0
        if source_count >= 2:
            bonus_rate = thresholds.multi_source_bonus if thresholds else 0.15
            multi_bonus = min((source_count - 1) * 0.05, bonus_rate)

        new_conf = max(0.0, min(1.0, old_conf + base_delta + multi_bonus))

        reason = f"Verdict '{verdict}' (category={category}, sources={source_count})"
        return ConfidenceUpdate(
            entity_id=entity.id,
            old_confidence=old_conf,
            new_confidence=new_conf,
            reason=reason,
            source_count=source_count,
        )

    @staticmethod
    def aggregate_multi_source(confidences: list[float]) -> float:
        """Probabilistic OR: 1 - product(1 - ci)."""
        if not confidences:
            return 0.0
        product = 1.0
        for c in confidences:
            product *= 1.0 - c
        return 1.0 - product

    @staticmethod
    def apply(update: ConfidenceUpdate, graph: KnowledgeGraph) -> None:
        """Apply a confidence update to an entity in the graph."""
        entity = graph.get(update.entity_id)
        if entity is not None:
            entity.confidence = update.new_confidence
