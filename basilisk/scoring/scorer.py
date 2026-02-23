"""Priority scoring engine for capability selection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph

if TYPE_CHECKING:
    from basilisk.campaign.memory import CampaignMemory
    from basilisk.memory.history import History
    from basilisk.orchestrator.cost_tracker import CostTracker
    from basilisk.reasoning.hypothesis import HypothesisEngine


class ScoredCapability(BaseModel):
    """A capability scored for a specific target entity."""

    capability: Capability
    target_entity: Entity
    score: float
    reason: str
    score_breakdown: dict[str, float] = Field(default_factory=dict)


class Scorer:
    """Score and rank (capability, entity) candidates.

    priority = (novelty * knowledge_gain * success_probability + unlock_value + prior_bonus)
             / (cost + noise + repetition_penalty)
    """

    def __init__(
        self,
        graph: KnowledgeGraph,
        history: History | None = None,
        cost_tracker: CostTracker | None = None,
        campaign_memory: CampaignMemory | None = None,
        hypothesis_engine: HypothesisEngine | None = None,
    ) -> None:
        self.graph = graph
        self._history = history
        self._cost_tracker = cost_tracker
        self._campaign = campaign_memory
        self._hypothesis_engine = hypothesis_engine

    def rank(
        self,
        candidates: list[tuple[Capability, Entity, float]]
        | list[tuple[Capability, Entity]],
    ) -> list[ScoredCapability]:
        """Score all candidates and return sorted by score descending."""
        scored = []
        for item in candidates:
            if len(item) == 3:
                cap, entity, gap_priority = item
            else:
                cap, entity = item
                gap_priority = 5.0  # default mid-priority
            score, breakdown = self._score_one(cap, entity, gap_priority)
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

    def _score_one(
        self, cap: Capability, entity: Entity, gap_priority: float = 5.0,
    ) -> tuple[float, dict[str, float]]:
        """Compute priority score for a single (capability, entity) pair.

        Returns (score, breakdown_dict).

        gap_priority: from planner (1-10), boosts candidates from high-priority gaps
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

        # Cost + noise baseline (use learned cost if available)
        if self._cost_tracker:
            cost = self._cost_tracker.adjusted_cost(cap.plugin_name, cap.cost_score)
        elif self._campaign:
            cost = self._campaign.adjusted_cost(cap.plugin_name, cap.cost_score)
        else:
            cost = cap.cost_score
        noise = cap.noise_score
        denominator = cost + noise + repetition_penalty
        denominator = max(denominator, 0.1)  # avoid division by zero

        # Multi-step scoring: future unlock value from attack paths
        unlock_value = self._compute_unlock_value(cap, entity)

        # Campaign prior bonus — reward when we know the infrastructure
        prior_bonus = 0.0
        if self._campaign:
            host = entity.data.get("host", "")
            if entity.type == EntityType.SERVICE:
                port = entity.data.get("port", 0)
                if self._campaign.is_known_infrastructure(host, port):
                    prior_bonus = 0.15
            elif entity.type == EntityType.HOST and host:
                known_techs = self._campaign.known_technologies(host)
                if known_techs:
                    tech_rate = self._campaign.plugin_tech_rate(
                        cap.plugin_name, known_techs,
                    )
                    if tech_rate is not None and tech_rate > 0.5:
                        prior_bonus = tech_rate * 0.2

        # Success probability — learned from past runs
        success_probability = self._compute_success_probability(cap)

        # Hypothesis resolution gain — how much this helps resolve active hypotheses
        hypothesis_gain = 0.0
        if self._hypothesis_engine is not None:
            hypothesis_gain = self._hypothesis_engine.resolution_gain(
                cap.plugin_name, entity.id,
            )

        # Action type bonus — prefer experiments when uncertain, exploits when justified
        action_type_bonus = self._compute_action_type_bonus(cap, entity)

        # Gap priority boost — normalized to [0.5, 2.0] range so high-priority gaps
        # (like host_without_services=10) strongly outrank low-priority gaps (like
        # low_confidence_entity=3).  Formula: 0.5 + gap_priority / 10 * 1.5
        gap_boost = 0.5 + gap_priority / 10.0 * 1.5

        raw_score = (
            novelty * knowledge_gain * success_probability + unlock_value + prior_bonus
            + hypothesis_gain + action_type_bonus
        ) * gap_boost / denominator

        breakdown = {
            "novelty": novelty,
            "knowledge_gain": knowledge_gain,
            "success_probability": success_probability,
            "unlock_value": unlock_value,
            "prior_bonus": prior_bonus,
            "hypothesis_gain": hypothesis_gain,
            "action_type_bonus": action_type_bonus,
            "gap_priority": gap_priority,
            "gap_boost": gap_boost,
            "cost": cost,
            "noise": noise,
            "repetition_penalty": repetition_penalty,
            "raw_score": raw_score,
        }

        return raw_score, breakdown

    def _compute_success_probability(self, cap: Capability) -> float:
        """Estimate probability that the plugin will produce useful results.

        Priority: CostTracker (runtime stats) > CampaignMemory (cross-audit) > default 0.5.
        Floor at 0.05 to prevent zeroing out the score entirely.
        """
        if self._cost_tracker:
            stats = self._cost_tracker.get_stats(cap.plugin_name)
            if stats is not None and stats.runs >= 2:
                return max(stats.success_rate, 0.05)

        if self._campaign:
            rate = self._campaign.plugin_success_rate(cap.plugin_name)
            if rate > 0:
                return max(rate, 0.05)

        return 0.5  # uninformative prior

    def _compute_unlock_value(self, cap: Capability, entity: Entity) -> float:
        """Compute future value: how many attack paths this capability would unlock.

        A capability that produces Endpoint knowledge is valuable even without
        immediate findings because it opens vulnerability_testing paths.
        """
        from basilisk.orchestrator.attack_paths import count_unlockable_paths

        n_unlocked = count_unlockable_paths(cap.produces_knowledge, self.graph)
        # Each unlocked path contributes 0.3 to the score
        return n_unlocked * 0.3

    @staticmethod
    def _compute_action_type_bonus(cap: Capability, entity: Entity) -> float:
        """Bonus based on action type vs current entity confidence.

        - EXPERIMENT + low confidence → prefer testing when uncertain
        - EXPLOIT + high confidence → prefer exploitation when justified
        - VERIFICATION + high/critical finding → always valuable
        """
        from basilisk.capabilities.capability import ActionType

        if cap.action_type == ActionType.EXPERIMENT and entity.confidence < 0.7:
            return 0.1
        if cap.action_type == ActionType.EXPLOIT and entity.confidence >= 0.8:
            return 0.15
        if cap.action_type == ActionType.VERIFICATION:
            severity = entity.data.get("severity", "")
            if severity in ("high", "critical"):
                return 0.2
        return 0.0

    @staticmethod
    def _explain(cap: Capability, entity: Entity, score: float) -> str:
        """Human-readable explanation of why this was scored."""
        host = entity.data.get("host", entity.id[:8])
        return (
            f"{cap.name} on {host}: score={score:.3f} "
            f"(cost={cap.cost_score}, noise={cap.noise_score}, "
            f"produces={cap.produces_knowledge})"
        )
