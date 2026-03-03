"""Main autonomous loop — inspect → plan → score → execute → repeat."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from basilisk.decisions.decision import Decision, EvaluatedOption
from basilisk.events.bus import Event, EventBus, EventType
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.fingerprint import make_execution_fingerprint
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.knowledge.state import KnowledgeState
from basilisk.observations.observation import Observation
from basilisk.orchestrator.observation_processor import ObservationProcessor
from basilisk.orchestrator.planner import Planner
from basilisk.orchestrator.post_step import PostStepHandler
from basilisk.orchestrator.safety import SafetyLimits
from basilisk.orchestrator.selector import Selector
from basilisk.orchestrator.step_builder import StepBuilder
from basilisk.orchestrator.timeline import Timeline
from basilisk.scoring.scorer import ScoredCapability, Scorer

if TYPE_CHECKING:
    from basilisk.memory.history import History
    from basilisk.orchestrator.cost_tracker import CostTracker
    from basilisk.orchestrator.coverage_tracker import CoverageTracker
    from basilisk.orchestrator.executor_protocol import ExecutorProtocol
    from basilisk.orchestrator.goals import GoalEngine
    from basilisk.reasoning.belief import EvidenceAggregator
    from basilisk.reasoning.hypothesis import HypothesisEngine
    from basilisk.verification.confidence import ConfidenceModel
    from basilisk.verification.confirmer import FindingConfirmer
    from basilisk.verification.revalidator import ReValidator

logger = logging.getLogger(__name__)


@dataclass
class LoopResult:
    """Result of the autonomous loop execution."""

    graph: KnowledgeGraph
    timeline: Timeline
    steps: int = 0
    total_observations: int = 0
    termination_reason: str = ""
    duration: float = 0.0
    results: dict[str, Any] = field(default_factory=dict)
    plugin_results: dict[str, Any] = field(default_factory=dict)
    decisions: list[Decision] = field(default_factory=list)
    history: History | None = None


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
        executor: ExecutorProtocol,
        bus: EventBus,
        safety: SafetyLimits,
        on_progress: Callable | None = None,
        history: History | None = None,
        exploration_rate: float = 0.15,
        cost_tracker: CostTracker | None = None,
        goal_engine: GoalEngine | None = None,
        hypothesis_engine: HypothesisEngine | None = None,
        evidence_aggregator: EvidenceAggregator | None = None,
        coverage_tracker: CoverageTracker | None = None,
        confirmer: FindingConfirmer | None = None,
        confidence_model: ConfidenceModel | None = None,
        revalidator: ReValidator | None = None,
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
        self._exploration_rate = exploration_rate
        self._cost_tracker = cost_tracker
        self._goal_engine = goal_engine
        self._hypothesis_engine = hypothesis_engine
        self._evidence_aggregator = evidence_aggregator
        self._coverage_tracker = coverage_tracker
        self._confirmer = confirmer
        self._confidence_model = confidence_model
        self._revalidator = revalidator

        # Delegate to extracted components
        self._step_builder = StepBuilder(
            state=self._state,
            selector=selector,
            scorer=scorer,
            safety=safety,
            graph=graph,
            bus=bus,
            goal_engine=goal_engine,
            coverage_tracker=coverage_tracker,
            exploration_rate=exploration_rate,
        )
        self._obs_processor = ObservationProcessor(
            state=self._state,
            bus=bus,
            history=history,
            cost_tracker=cost_tracker,
        )
        self._post_step = PostStepHandler(
            graph=graph,
            bus=bus,
            hypothesis_engine=hypothesis_engine,
            evidence_aggregator=evidence_aggregator,
            coverage_tracker=coverage_tracker,
            confirmer=confirmer,
            confidence_model=confidence_model,
            revalidator=revalidator,
            executor=executor,
        )

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
            step_start = time.monotonic()
            entities_before = self.graph.entity_count

            # 1-5. Plan step: gaps → capabilities → score → select
            plan = self._step_builder.build(step)
            if plan is None:
                termination_reason = self._step_builder.termination_reason
                break

            # 6. Execute batch concurrently with decision tracing
            tasks = []
            step_decisions: list[Decision] = []
            for sc in plan.chosen:
                fingerprint = make_execution_fingerprint(
                    sc.capability.plugin_name, sc.target_entity,
                )

                # Build decision BEFORE execution
                decision = self._build_decision(step, sc, plan.all_scored, plan.gaps)
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
                    "full_decision": decision,
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
            self.timeline.record_step(step, plan.chosen, gaps_found=len(plan.gaps))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # 7. Apply observations via KnowledgeState
            step_obs = self._obs_processor.process_batch(results, step_decisions, step)
            total_obs += step_obs

            # Post-step processing
            self._post_step.process(plan.chosen, results, step_decisions, step)

            # Step event + progress
            step_duration = time.monotonic() - step_start
            entities_gained = self.graph.entity_count - entities_before
            self.bus.emit(Event(EventType.STEP_COMPLETED, {
                "step": step,
                "observations": step_obs,
                "entities": self.graph.entity_count,
                "relations": self.graph.relation_count,
                "duration": step_duration,
                "entities_gained": entities_gained,
                "batch_size": len(plan.chosen),
            }))

            # Apply knowledge decay every 10 steps
            if step % 10 == 0:
                self.graph.apply_decay()

            logger.info(
                "Step %d: %d tasks, +%d observations, %d entities total",
                step, len(tasks), step_obs, self.graph.entity_count,
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
            duration=self.safety.elapsed,
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

            # Bootstrap HTTP service if target has explicit port
            for port in target.ports:
                svc = Entity.service(target.host, port, "tcp")
                svc.data["service"] = "http"
                self.graph.add_entity(svc)
                self.graph.add_relation(Relation(
                    source_id=entity.id,
                    target_id=svc.id,
                    type=RelationType.EXPOSES,
                ))
                self.bus.emit(Event(EventType.ENTITY_CREATED, {"entity_id": svc.id}))

    async def _execute_one(
        self, sc: ScoredCapability, step: int, decision: Decision,
    ) -> list[Observation]:
        """Execute a single scored capability."""
        start = time.monotonic()
        observations: list[Observation] = []
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
            findings_count = sum(
                1 for o in observations if o.entity_type == EntityType.FINDING
            )
            self.bus.emit(Event(EventType.PLUGIN_FINISHED, {
                "plugin": sc.capability.name,
                "target": sc.target_entity.data.get("host", ""),
                "duration": duration,
                "step": step,
                "findings_count": findings_count,
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

        # Hypothesis context
        related_hyp_ids: list[str] = []
        hyp_resolution_gain = 0.0
        action_type_str = ""
        hypothesis_text = ""
        if self._hypothesis_engine is not None:
            related = self._hypothesis_engine.hypotheses_for_entity(chosen.target_entity.id)
            related_hyp_ids = [h.id for h in related[:5]]
            hyp_resolution_gain = self._hypothesis_engine.resolution_gain(
                chosen.capability.plugin_name, chosen.target_entity.id,
            )
            if related:
                hypothesis_text = getattr(related[0], "text", "")
        if hasattr(chosen.capability, "action_type"):
            action_type_str = str(chosen.capability.action_type)

        # Expected entity types from capability metadata
        expected_entity_types: list[str] = []
        if hasattr(chosen.capability, "produces_knowledge"):
            expected_entity_types = list(chosen.capability.produces_knowledge)

        # Add hypothesis counts to context snapshot
        if self._hypothesis_engine is not None:
            context.active_hypothesis_count = len(self._hypothesis_engine.active_hypotheses)
            context.confirmed_hypothesis_count = sum(
                1 for h in self._hypothesis_engine.all_hypotheses
                if h.status == "confirmed"
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
            related_hypothesis_ids=related_hyp_ids,
            hypothesis_resolution_gain=hyp_resolution_gain,
            action_type=action_type_str,
            hypothesis_text=hypothesis_text,
            expected_entity_types=expected_entity_types,
        )

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
            "containers": len(self.graph.containers()),
            "images": len(self.graph.images()),
        }
