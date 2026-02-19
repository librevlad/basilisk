"""Main autonomous loop — inspect → plan → score → execute → repeat."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from basilisk.decisions.decision import Decision, EvaluatedOption
from basilisk.events.bus import Event, EventBus, EventType
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.state import KnowledgeState
from basilisk.observations.observation import Observation
from basilisk.orchestrator.planner import Planner
from basilisk.orchestrator.safety import SafetyLimits
from basilisk.orchestrator.selector import Selector
from basilisk.orchestrator.timeline import Timeline
from basilisk.scoring.scorer import ScoredCapability, Scorer

logger = logging.getLogger(__name__)


@dataclass
class LoopResult:
    """Result of the autonomous loop execution."""

    graph: KnowledgeGraph
    timeline: Timeline
    steps: int = 0
    total_observations: int = 0
    termination_reason: str = ""
    results: dict[str, Any] = field(default_factory=dict)
    plugin_results: dict[str, Any] = field(default_factory=dict)
    decisions: list[Decision] = field(default_factory=list)
    history: Any = None  # History | None


class AutonomousLoop:
    """State-driven autonomous engine.

    The loop:
    1. Find knowledge gaps
    2. Match capabilities to gaps
    3. Score and rank candidates
    4. Select a batch
    5. Execute concurrently (with decision tracing)
    6. Apply observations to the graph via KnowledgeState
    7. Repeat until no gaps remain or limits are reached
    """

    def __init__(
        self,
        graph: KnowledgeGraph,
        planner: Planner,
        selector: Selector,
        scorer: Scorer,
        executor: Any,  # OrchestratorExecutor
        bus: EventBus,
        safety: SafetyLimits,
        on_progress: Callable | None = None,
        history: Any = None,  # History | None
    ) -> None:
        self.graph = graph
        self.planner = planner
        self.selector = selector
        self.scorer = scorer
        self.executor = executor
        self.bus = bus
        self.safety = safety
        self.on_progress = on_progress
        self.timeline = Timeline()
        self._history = history
        self._state = KnowledgeState(graph, planner)

    async def run(self, initial_targets: list) -> LoopResult:
        """Main autonomous loop."""
        self.safety.start()

        # Seed graph with initial Host entities
        self._seed_targets(initial_targets)

        step = 0
        total_obs = 0
        termination_reason = "completed"
        all_decisions: list[Decision] = []

        while True:
            step += 1

            # 1. Safety check
            if not self.safety.can_continue(step):
                termination_reason = (
                    f"limit_reached (step={step}, elapsed={self.safety.elapsed:.0f}s)"
                )
                logger.info("Autonomous loop: %s", termination_reason)
                break

            # 2. Find gaps
            gaps = self._state.find_gaps()
            if not gaps:
                termination_reason = "no_gaps"
                logger.info("Autonomous loop: no knowledge gaps remain")
                break

            self.bus.emit(Event(EventType.GAP_DETECTED, {"count": len(gaps), "step": step}))

            # 3. Match capabilities to gaps
            candidates = self.selector.match(gaps, self.graph)
            if not candidates:
                termination_reason = "no_capabilities"
                logger.info("Autonomous loop: no capabilities can fill remaining gaps")
                break

            # 4. Score and rank
            scored = self.scorer.rank(candidates)

            # 5. Select batch
            chosen = self.selector.pick(scored, budget=self.safety.batch_size)
            if not chosen:
                termination_reason = "no_candidates"
                break

            # 6. Execute batch concurrently with decision tracing
            tasks = []
            step_decisions: list[Decision] = []
            for sc in chosen:
                fingerprint = self._fingerprint(sc)

                # Check cooldown
                if not self.safety.is_cooled_down(fingerprint):
                    continue

                if self.graph.was_executed(fingerprint):
                    continue

                # Build decision BEFORE execution
                decision = self._build_decision(step, sc, scored, gaps)
                step_decisions.append(decision)
                all_decisions.append(decision)

                if self._history is not None:
                    self._history.record(decision)

                self.bus.emit(Event(EventType.DECISION_MADE, {
                    "decision_id": decision.id,
                    "plugin": sc.capability.name,
                    "target": sc.target_entity.data.get("host", ""),
                    "step": step,
                    "score": sc.score,
                    "reasoning": decision.reasoning_trace,
                }))

                self.graph.record_execution(fingerprint)
                self.safety.record_run(fingerprint)

                self.bus.emit(Event(EventType.PLUGIN_STARTED, {
                    "plugin": sc.capability.name,
                    "target": sc.target_entity.data.get("host", ""),
                    "step": step,
                }))
                tasks.append(self._execute_one(sc, step, decision))

            if not tasks:
                termination_reason = "all_executed"
                break

            # Record timeline before execution
            self.timeline.record_step(step, chosen, gaps_found=len(gaps))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # 7. Apply observations via KnowledgeState (captures deltas)
            step_obs_count = 0
            for idx, obs_list in enumerate(results):
                if isinstance(obs_list, BaseException):
                    logger.warning("Execution error in step %d: %s", step, obs_list)
                    continue

                decision = step_decisions[idx] if idx < len(step_decisions) else None
                obs_count = 0
                new_entities = 0
                total_confidence_delta = 0.0

                for obs in obs_list:
                    outcome = self._state.apply_observation(obs)
                    self.bus.emit(Event(
                        EventType.ENTITY_UPDATED if not outcome.was_new
                        else EventType.ENTITY_CREATED,
                        {"entity_id": outcome.entity_id},
                    ))
                    obs_count += 1
                    if outcome.was_new:
                        new_entities += 1
                    total_confidence_delta += outcome.confidence_delta

                step_obs_count += obs_count

                # Update decision outcome
                if decision:
                    decision.outcome_observations = obs_count
                    decision.outcome_new_entities = new_entities
                    decision.outcome_confidence_delta = total_confidence_delta
                    decision.outcome_duration = decision.outcome_duration  # set by _execute_one
                    decision.was_productive = (
                        new_entities > 0 or total_confidence_delta > 0.01
                    )
                    if self._history is not None:
                        self._history.update_outcome(
                            decision.id,
                            observations=obs_count,
                            new_entities=new_entities,
                            confidence_delta=total_confidence_delta,
                            duration=decision.outcome_duration,
                        )

            total_obs += step_obs_count

            # 8. Emit step event
            self.bus.emit(Event(EventType.STEP_COMPLETED, {
                "step": step,
                "observations": step_obs_count,
                "entities": self.graph.entity_count,
                "relations": self.graph.relation_count,
            }))

            logger.info(
                "Step %d: %d tasks, +%d observations, %d entities total",
                step, len(tasks), step_obs_count, self.graph.entity_count,
            )

            if self.on_progress:
                self.on_progress({
                    "step": step,
                    "entities": self.graph.entity_count,
                    "observations": total_obs,
                })

        return LoopResult(
            graph=self.graph,
            timeline=self.timeline,
            steps=step,
            total_observations=total_obs,
            termination_reason=termination_reason,
            results=self._collect_results(),
            plugin_results=dict(self.executor.ctx.pipeline),
            decisions=all_decisions,
            history=self._history,
        )

    def _seed_targets(self, targets: list) -> None:
        """Seed the graph with initial Host entities from Target objects."""
        now = datetime.now(UTC)
        for target in targets:
            entity = Entity(
                id=Entity.make_id(EntityType.HOST, host=target.host),
                type=EntityType.HOST,
                data={"host": target.host, "type": target.type.value},
                first_seen=now,
                last_seen=now,
            )
            self.graph.add_entity(entity)
            self.bus.emit(Event(EventType.ENTITY_CREATED, {"entity_id": entity.id}))

    async def _execute_one(
        self, sc: ScoredCapability, step: int, decision: Decision,
    ) -> list[Observation]:
        """Execute a single scored capability."""
        start = time.monotonic()
        try:
            observations = await self.executor.execute(
                sc.capability, sc.target_entity, self.graph,
            )
        except Exception:
            logger.exception("Plugin %s failed", sc.capability.name)
            return []
        finally:
            duration = time.monotonic() - start
            decision.outcome_duration = duration
            self.bus.emit(Event(EventType.PLUGIN_FINISHED, {
                "plugin": sc.capability.name,
                "target": sc.target_entity.data.get("host", ""),
                "duration": duration,
                "step": step,
            }))

        # Record result in timeline with real confidence delta (computed later)
        new_ids = [obs.key_fields.get("host", "") for obs in observations[:5]]
        self.timeline.record_result(
            sc.capability.name,
            sc.target_entity.data.get("host", sc.target_entity.id[:8]),
            new_ids,
            confidence_delta=0.0,  # updated after observation application
            duration=duration,
        )

        return observations

    def _build_decision(
        self,
        step: int,
        chosen: ScoredCapability,
        all_scored: list[ScoredCapability],
        gaps: list,
    ) -> Decision:
        """Build a Decision record BEFORE execution."""
        now = datetime.now(UTC)
        target_host = chosen.target_entity.data.get("host", chosen.target_entity.id[:8])

        # Find matching gap for the chosen entity
        matching_gap = None
        for gap in gaps:
            if gap.entity.id == chosen.target_entity.id:
                matching_gap = gap
                break

        # Build evaluated options (cap at 20)
        evaluated = []
        for sc in all_scored[:20]:
            evaluated.append(EvaluatedOption(
                capability_name=sc.capability.name,
                plugin_name=sc.capability.plugin_name,
                target_entity_id=sc.target_entity.id,
                target_host=sc.target_entity.data.get("host", sc.target_entity.id[:8]),
                score=sc.score,
                score_breakdown=sc.score_breakdown,
                reason=sc.reason,
                was_chosen=(
                    sc.capability.name == chosen.capability.name
                    and sc.target_entity.id == chosen.target_entity.id
                ),
            ))

        # Build reasoning trace
        gap_desc = matching_gap.description if matching_gap else "unknown gap"
        reasoning = (
            f"Gap: {gap_desc}. "
            f"Selected {chosen.capability.name} (score={chosen.score:.3f}) "
            f"from {len(all_scored)} candidates. "
            f"{chosen.reason}"
        )

        context = self._state.snapshot(
            step, self.safety.elapsed, len(gaps),
        )

        return Decision(
            id=Decision.make_id(step, now, chosen.capability.plugin_name, target_host),
            timestamp=now,
            step=step,
            goal=matching_gap.missing if matching_gap else "",
            goal_description=gap_desc,
            goal_priority=matching_gap.priority if matching_gap else 0.0,
            triggering_entity_id=chosen.target_entity.id,
            context=context,
            evaluated_options=evaluated,
            chosen_capability=chosen.capability.name,
            chosen_plugin=chosen.capability.plugin_name,
            chosen_target=target_host,
            chosen_score=chosen.score,
            reasoning_trace=reasoning,
        )

    @staticmethod
    def _fingerprint(sc: Any) -> str:
        """Create a unique fingerprint for a (capability, entity) pair."""
        return f"{sc.capability.plugin_name}:{sc.target_entity.id}"

    def _collect_results(self) -> dict[str, Any]:
        """Collect summary results from the graph."""
        return {
            "entities": self.graph.entity_count,
            "relations": self.graph.relation_count,
            "hosts": len(self.graph.hosts()),
            "services": len(self.graph.services()),
            "endpoints": len(self.graph.endpoints()),
            "technologies": len(self.graph.technologies()),
            "findings": len(self.graph.findings()),
        }
