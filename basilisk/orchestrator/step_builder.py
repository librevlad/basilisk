"""Pre-execution step planning: gaps → capabilities → scoring → batch selection."""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from basilisk.events.bus import Event, EventType
from basilisk.knowledge.fingerprint import make_execution_fingerprint

if TYPE_CHECKING:
    from basilisk.events.bus import EventBus
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.knowledge.state import KnowledgeState
    from basilisk.orchestrator.coverage_tracker import CoverageTracker
    from basilisk.orchestrator.goals import GoalEngine
    from basilisk.orchestrator.planner import KnowledgeGap
    from basilisk.orchestrator.safety import SafetyLimits
    from basilisk.orchestrator.selector import Selector
    from basilisk.scoring.scorer import ScoredCapability, Scorer

logger = logging.getLogger(__name__)


@dataclass
class StepPlan:
    """Result of the step planning phase."""

    chosen: list[ScoredCapability]
    all_scored: list[ScoredCapability]
    gaps: list[KnowledgeGap]


class StepBuilder:
    """Find gaps → match capabilities → score → filter → select batch.

    Encapsulates the pre-execution phase of the autonomous loop.
    """

    def __init__(
        self,
        state: KnowledgeState,
        selector: Selector,
        scorer: Scorer,
        safety: SafetyLimits,
        graph: KnowledgeGraph,
        bus: EventBus,
        *,
        goal_engine: GoalEngine | None = None,
        coverage_tracker: CoverageTracker | None = None,
        exploration_rate: float = 0.15,
    ) -> None:
        self._state = state
        self._selector = selector
        self._scorer = scorer
        self._safety = safety
        self._graph = graph
        self._bus = bus
        self._goal_engine = goal_engine
        self._coverage_tracker = coverage_tracker
        self._exploration_rate = exploration_rate
        self.termination_reason: str = ""

    def build(self, step: int) -> StepPlan | None:
        """Plan a single step. Returns None on termination."""
        # 1. Safety check
        if not self._safety.can_continue(step):
            self.termination_reason = (
                f"limit_reached (step={step}, elapsed={self._safety.elapsed:.0f}s)"
            )
            logger.info("Autonomous loop: %s", self.termination_reason)
            return None

        # 2. Find gaps
        gaps = self._state.find_gaps()
        if not gaps:
            self.termination_reason = "no_gaps"
            logger.info("Autonomous loop: no knowledge gaps remain")
            return None

        # 2b. Goal-driven gap prioritization
        if self._goal_engine is not None:
            if self._goal_engine.should_advance(gaps, self._coverage_tracker):
                self._goal_engine.advance()
            gaps = self._goal_engine.prioritize_gaps(gaps)

        self._bus.emit(Event(EventType.GAP_DETECTED, {"count": len(gaps), "step": step}))

        # 3. Match capabilities to gaps
        candidates = self._selector.match(gaps, self._graph)
        if not candidates:
            self.termination_reason = "no_capabilities"
            logger.info("Autonomous loop: no capabilities can fill remaining gaps")
            return None

        # 4. Score and rank
        scored = self._scorer.rank(candidates)

        # 4b. Filter out already-executed pairs and cooldown
        scored = [
            sc for sc in scored
            if not self._graph.was_executed(
                make_execution_fingerprint(sc.capability.plugin_name, sc.target_entity),
            )
            and self._safety.is_cooled_down(
                make_execution_fingerprint(sc.capability.plugin_name, sc.target_entity),
            )
        ]

        # 5. Select batch (exploration vs exploitation)
        if scored and random.random() < self._exploration_rate:
            k = min(len(scored), self._safety.batch_size)
            chosen: list[ScoredCapability] = random.sample(scored, k)
        else:
            chosen = self._selector.pick(scored, budget=self._safety.batch_size)

        if not chosen:
            self.termination_reason = "no_candidates"
            return None

        return StepPlan(chosen=chosen, all_scored=scored, gaps=gaps)
