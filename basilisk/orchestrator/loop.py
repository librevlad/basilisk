"""Main autonomous loop — inspect → plan → score → execute → repeat."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from basilisk.events.bus import Event, EventBus, EventType
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.observations.observation import Observation
from basilisk.orchestrator.planner import Planner
from basilisk.orchestrator.safety import SafetyLimits
from basilisk.orchestrator.selector import Selector
from basilisk.orchestrator.timeline import Timeline
from basilisk.scoring.scorer import Scorer

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


class AutonomousLoop:
    """State-driven autonomous engine.

    The loop:
    1. Find knowledge gaps
    2. Match capabilities to gaps
    3. Score and rank candidates
    4. Select a batch
    5. Execute concurrently
    6. Apply observations to the graph
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

    async def run(self, initial_targets: list) -> LoopResult:
        """Main autonomous loop."""
        self.safety.start()

        # Seed graph with initial Host entities
        self._seed_targets(initial_targets)

        step = 0
        total_obs = 0
        termination_reason = "completed"

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
            gaps = self.planner.find_gaps(self.graph)
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

            # 6. Execute batch concurrently
            tasks = []
            for sc in chosen:
                fingerprint = self._fingerprint(sc)
                if self.graph.was_executed(fingerprint):
                    continue
                self.graph.record_execution(fingerprint)
                self.bus.emit(Event(EventType.PLUGIN_STARTED, {
                    "plugin": sc.capability.name,
                    "target": sc.target_entity.data.get("host", ""),
                    "step": step,
                }))
                tasks.append(self._execute_one(sc, step))

            if not tasks:
                termination_reason = "all_executed"
                break

            # Record timeline before execution
            self.timeline.record_step(step, chosen, gaps_found=len(gaps))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # 7. Apply observations
            step_obs_count = 0
            for obs_list in results:
                if isinstance(obs_list, BaseException):
                    logger.warning("Execution error in step %d: %s", step, obs_list)
                    continue
                for obs in obs_list:
                    self._apply_observation(obs)
                    step_obs_count += 1

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

    async def _execute_one(self, sc: Any, step: int) -> list[Observation]:
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
            self.bus.emit(Event(EventType.PLUGIN_FINISHED, {
                "plugin": sc.capability.name,
                "target": sc.target_entity.data.get("host", ""),
                "duration": duration,
                "step": step,
            }))

        # Record result in timeline
        new_ids = [obs.key_fields.get("host", "") for obs in observations[:5]]
        self.timeline.record_result(
            sc.capability.name,
            sc.target_entity.data.get("host", sc.target_entity.id[:8]),
            new_ids,
            confidence_delta=0.0,
            duration=duration,
        )

        return observations

    def _apply_observation(self, obs: Observation) -> None:
        """Apply a single observation to the knowledge graph."""
        entity_id = Entity.make_id(obs.entity_type, **obs.key_fields)
        now = datetime.now(UTC)

        entity = Entity(
            id=entity_id,
            type=obs.entity_type,
            data=obs.entity_data,
            confidence=obs.confidence,
            evidence=[obs.evidence] if obs.evidence else [],
            first_seen=now,
            last_seen=now,
        )

        existing = self.graph.get(entity_id)
        self.graph.add_entity(entity)

        event_type = EventType.ENTITY_UPDATED if existing else EventType.ENTITY_CREATED
        self.bus.emit(Event(event_type, {"entity_id": entity_id}))

        if obs.relation:
            self.graph.add_relation(obs.relation)

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
