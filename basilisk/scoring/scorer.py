"""Priority scoring engine for capability selection."""

from __future__ import annotations

from pydantic import BaseModel

from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph


class ScoredCapability(BaseModel):
    """A capability scored for a specific target entity."""

    capability: Capability
    target_entity: Entity
    score: float
    reason: str


class Scorer:
    """Score and rank (capability, entity) candidates.

    priority = (novelty * knowledge_gain) / (cost + noise + repetition_penalty)
    """

    def __init__(self, graph: KnowledgeGraph) -> None:
        self.graph = graph

    def rank(
        self, candidates: list[tuple[Capability, Entity]],
    ) -> list[ScoredCapability]:
        """Score all candidates and return sorted by score descending."""
        scored = []
        for cap, entity in candidates:
            score = self._score_one(cap, entity)
            reason = self._explain(cap, entity, score)
            scored.append(ScoredCapability(
                capability=cap,
                target_entity=entity,
                score=score,
                reason=reason,
            ))
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored

    def _score_one(self, cap: Capability, entity: Entity) -> float:
        """Compute priority score for a single (capability, entity) pair.

        novelty: 1.0 if entity never explored by this cap, decays with observation_count
        knowledge_gain: len(produces) * (1 - confidence)
        cost: cost_score (1-10)
        noise: noise_score (1-10)
        repetition_penalty: 5.0 if same cap+entity was run before, else 0
        """
        # Novelty — higher when entity has fewer observations
        novelty = 1.0 / (1.0 + (entity.observation_count - 1) * 0.3)

        # Knowledge gain — how much new info this capability could produce
        knowledge_gain = len(cap.produces_knowledge) * (1.0 - entity.confidence)
        knowledge_gain = max(knowledge_gain, 0.1)  # minimum gain

        # Repetition penalty
        fingerprint = f"{cap.plugin_name}:{entity.id}"
        repetition_penalty = 5.0 if self.graph.was_executed(fingerprint) else 0.0

        # Cost + noise baseline
        denominator = cap.cost_score + cap.noise_score + repetition_penalty
        denominator = max(denominator, 0.1)  # avoid division by zero

        return (novelty * knowledge_gain) / denominator

    @staticmethod
    def _explain(cap: Capability, entity: Entity, score: float) -> str:
        """Human-readable explanation of why this was scored."""
        host = entity.data.get("host", entity.id[:8])
        return (
            f"{cap.name} on {host}: score={score:.3f} "
            f"(cost={cap.cost_score}, noise={cap.noise_score}, "
            f"produces={cap.produces_knowledge})"
        )
