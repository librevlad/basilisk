"""Priority scoring engine for capability selection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph

if TYPE_CHECKING:
    from basilisk.memory.history import History


class ScoredCapability(BaseModel):
    """A capability scored for a specific target entity."""

    capability: Capability
    target_entity: Entity
    score: float
    reason: str
    score_breakdown: dict[str, float] = Field(default_factory=dict)


class Scorer:
    """Score and rank (capability, entity) candidates.

    priority = (novelty * knowledge_gain) / (cost + noise + repetition_penalty)
    """

    def __init__(
        self, graph: KnowledgeGraph, history: History | None = None,
    ) -> None:
        self.graph = graph
        self._history = history

    def rank(
        self, candidates: list[tuple[Capability, Entity]],
    ) -> list[ScoredCapability]:
        """Score all candidates and return sorted by score descending."""
        scored = []
        for cap, entity in candidates:
            score, breakdown = self._score_one(cap, entity)
            reason = self._explain(cap, entity, score)
            scored.append(ScoredCapability(
                capability=cap,
                target_entity=entity,
                score=score,
                reason=reason,
                score_breakdown=breakdown,
            ))
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored

    def _score_one(self, cap: Capability, entity: Entity) -> tuple[float, dict[str, float]]:
        """Compute priority score for a single (capability, entity) pair.

        Returns (score, breakdown_dict).

        novelty: 1.0 if entity never explored by this cap, decays with observation_count
        knowledge_gain: len(produces) * (1 - confidence)
        cost: cost_score (1-10)
        noise: noise_score (1-10)
        repetition_penalty: from History if available, else binary 5.0 from graph
        """
        # Novelty — higher when entity has fewer observations
        novelty = 1.0 / (1.0 + (entity.observation_count - 1) * 0.3)

        # Knowledge gain — how much new info this capability could produce
        knowledge_gain = len(cap.produces_knowledge) * (1.0 - entity.confidence)
        knowledge_gain = max(knowledge_gain, 0.1)  # minimum gain

        # Repetition penalty — prefer History when available
        # Use host-level fingerprint for Endpoint entities (pentesting plugins
        # scan all endpoints on a host in one run)
        if entity.type == EntityType.ENDPOINT:
            host = entity.data.get("host", entity.id)
            fingerprint = f"{cap.plugin_name}:{host}"
        else:
            fingerprint = f"{cap.plugin_name}:{entity.id}"
        if self._history:
            repetition_penalty = self._history.repetition_penalty(
                cap.plugin_name, entity.id,
            )
        else:
            repetition_penalty = 5.0 if self.graph.was_executed(fingerprint) else 0.0

        # Cost + noise baseline
        cost = cap.cost_score
        noise = cap.noise_score
        denominator = cost + noise + repetition_penalty
        denominator = max(denominator, 0.1)  # avoid division by zero

        raw_score = (novelty * knowledge_gain) / denominator

        breakdown = {
            "novelty": novelty,
            "knowledge_gain": knowledge_gain,
            "cost": cost,
            "noise": noise,
            "repetition_penalty": repetition_penalty,
            "raw_score": raw_score,
        }

        return raw_score, breakdown

    @staticmethod
    def _explain(cap: Capability, entity: Entity, score: float) -> str:
        """Human-readable explanation of why this was scored."""
        host = entity.data.get("host", entity.id[:8])
        return (
            f"{cap.name} on {host}: score={score:.3f} "
            f"(cost={cap.cost_score}, noise={cap.noise_score}, "
            f"produces={cap.produces_knowledge})"
        )
