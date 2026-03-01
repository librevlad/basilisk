"""Main autonomous loop — inspect → plan → score → execute → repeat."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from basilisk.decisions.decision import Decision, EvaluatedOption
from basilisk.events.bus import Event, EventBus, EventType
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
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
    duration: float = 0.0
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
        exploration_rate: float = 0.15,
        cost_tracker: Any = None,  # CostTracker | None
        goal_engine: Any = None,  # GoalEngine | None
        hypothesis_engine: Any = None,  # HypothesisEngine | None
        evidence_aggregator: Any = None,  # EvidenceAggregator | None
        coverage_tracker: Any = None,  # CoverageTracker | None
        confirmer: Any = None,  # FindingConfirmer | None
        confidence_model: Any = None,  # ConfidenceModel | None
        revalidator: Any = None,  # ReValidator | None
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

            # 2b. Goal-driven gap prioritization
            if self._goal_engine is not None:
                if self._goal_engine.should_advance(gaps, self._coverage_tracker):
                    self._goal_engine.advance()
                gaps = self._goal_engine.prioritize_gaps(gaps)

            self.bus.emit(Event(EventType.GAP_DETECTED, {"count": len(gaps), "step": step}))

            # 3. Match capabilities to gaps
            candidates = self.selector.match(gaps, self.graph)
            if not candidates:
                termination_reason = "no_capabilities"
                logger.info("Autonomous loop: no capabilities can fill remaining gaps")
                break

            # 4. Score and rank
            scored = self.scorer.rank(candidates)

            # 4b. Filter out already-executed pairs and cooldown
            scored = [
                sc for sc in scored
                if not self.graph.was_executed(self._fingerprint(sc))
                and self.safety.is_cooled_down(self._fingerprint(sc))
            ]

            # 5. Select batch (exploration vs exploitation)
            if scored and random.random() < self._exploration_rate:
                # Exploration: random sample for diversity
                k = min(len(scored), self.safety.batch_size)
                chosen = random.sample(scored, k)
            else:
                chosen = self.selector.pick(scored, budget=self.safety.batch_size)
            if not chosen:
                termination_reason = "no_candidates"
                break

            # 6. Execute batch concurrently with decision tracing
            tasks = []
            step_decisions: list[Decision] = []
            for sc in chosen:
                fingerprint = self._fingerprint(sc)

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
                    event_data: dict[str, Any] = {
                        "entity_id": outcome.entity_id,
                        "entity_type": obs.entity_type.value,
                        "key_data": " ".join(f"{k}={v}" for k, v in obs.key_fields.items()),
                        "confidence_delta": outcome.confidence_delta,
                    }
                    # Enrich finding events with display data
                    if obs.entity_type == EntityType.FINDING:
                        event_data["title"] = obs.entity_data.get("title", "")
                        event_data["severity"] = obs.entity_data.get("severity", "")
                        event_data["host"] = obs.key_fields.get("host", "")
                    self.bus.emit(Event(
                        EventType.ENTITY_UPDATED if not outcome.was_new
                        else EventType.ENTITY_CREATED,
                        event_data,
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
                    # Record stats for cost learning
                    if self._cost_tracker is not None:
                        self._cost_tracker.record(
                            decision.chosen_plugin,
                            new_entities=new_entities,
                            findings=obs_count,
                            runtime=decision.outcome_duration,
                        )

            total_obs += step_obs_count

            # 7x. Track coverage
            if self._coverage_tracker is not None:
                for idx, sc in enumerate(chosen):
                    host = sc.target_entity.data.get("host", "")
                    if host:
                        self._coverage_tracker.record_execution(
                            sc.capability.plugin_name, host,
                        )
                    if idx < len(results) and not isinstance(results[idx], BaseException):
                        for obs in results[idx]:
                            if obs.entity_type == EntityType.FINDING:
                                cat = obs.entity_data.get("category", "")
                                obs_host = obs.key_fields.get("host", host)
                                self._coverage_tracker.record_finding(obs_host, cat)

            # 7v. Evaluate verification results
            self._evaluate_verifications(chosen)

            # 7a. Hypothesis generation from updated graph
            if self._hypothesis_engine is not None:
                new_hypotheses = self._hypothesis_engine.generate_hypotheses(self.graph)
                for hyp in new_hypotheses:
                    self.graph.add_hypothesis(hyp)
                    logger.debug("Hypothesis created: %s", hyp.statement[:80])

            # 7b. Record evidence in aggregator
            if self._evidence_aggregator is not None:
                for idx, obs_list in enumerate(results):
                    if isinstance(obs_list, BaseException):
                        continue
                    d = step_decisions[idx] if idx < len(step_decisions) else None
                    plugin_name = d.chosen_plugin if d else ""
                    for obs in obs_list:
                        entity_id = Entity.make_id(obs.entity_type, **obs.key_fields)
                        self._evidence_aggregator.record_evidence(
                            entity_id, plugin_name, 0.0,
                        )

            # 7c. Run belief revision
            if self._evidence_aggregator is not None:
                revisions = self._evidence_aggregator.revise_beliefs()
                for entity_id, old_conf, new_conf in revisions:
                    if new_conf > old_conf:
                        self.bus.emit(Event(EventType.BELIEF_STRENGTHENED, {
                            "entity_id": entity_id,
                            "old_confidence": old_conf,
                            "new_confidence": new_conf,
                        }))
                    else:
                        self.bus.emit(Event(EventType.BELIEF_WEAKENED, {
                            "entity_id": entity_id,
                            "old_confidence": old_conf,
                            "new_confidence": new_conf,
                        }))

            # 7d. Update hypothesis confidence from observations
            if self._hypothesis_engine is not None:
                for idx, obs_list in enumerate(results):
                    if isinstance(obs_list, BaseException):
                        continue
                    d = step_decisions[idx] if idx < len(step_decisions) else None
                    plugin_name = d.chosen_plugin if d else ""
                    for obs in obs_list:
                        entity_id = Entity.make_id(obs.entity_type, **obs.key_fields)
                        from basilisk.reasoning.belief import get_source_family
                        family = get_source_family(plugin_name)
                        changed = self._hypothesis_engine.update_from_observation(
                            entity_id=entity_id,
                            source_plugin=plugin_name,
                            source_family=family,
                            was_new=True,
                            confidence_delta=0.0,
                        )
                        for hyp in changed:
                            if hyp.status == "confirmed":
                                self.bus.emit(Event(EventType.HYPOTHESIS_CONFIRMED, {
                                    "hypothesis_id": hyp.id,
                                    "statement": hyp.statement,
                                }))
                            elif hyp.status == "rejected":
                                self.bus.emit(Event(EventType.HYPOTHESIS_REJECTED, {
                                    "hypothesis_id": hyp.id,
                                    "statement": hyp.statement,
                                }))

            # 7e. Reset aggregator for next step
            if self._evidence_aggregator is not None:
                self._evidence_aggregator.reset_step()

            # 7f. Mark gap rules as satisfied for executed capabilities
            for idx, sc in enumerate(chosen):
                produced = False
                if idx < len(results) and not isinstance(results[idx], BaseException):
                    d = step_decisions[idx] if idx < len(step_decisions) else None
                    produced = d.was_productive if d else False
                self._mark_gap_satisfied(sc, produced=produced)

            # 8. Emit step event
            step_duration = time.monotonic() - step_start
            entities_gained = self.graph.entity_count - entities_before
            self.bus.emit(Event(EventType.STEP_COMPLETED, {
                "step": step,
                "observations": step_obs_count,
                "entities": self.graph.entity_count,
                "relations": self.graph.relation_count,
                "duration": step_duration,
                "entities_gained": entities_gained,
                "batch_size": len(chosen),
            }))

            # Apply knowledge decay every 10 steps
            if step % 10 == 0:
                self.graph.apply_decay()

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
        if self._hypothesis_engine is not None:
            related = self._hypothesis_engine.hypotheses_for_entity(chosen.target_entity.id)
            related_hyp_ids = [h.id for h in related[:5]]
            hyp_resolution_gain = self._hypothesis_engine.resolution_gain(
                chosen.capability.plugin_name, chosen.target_entity.id,
            )
        if hasattr(chosen.capability, "action_type"):
            action_type_str = str(chosen.capability.action_type)

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
        )

    def _mark_gap_satisfied(self, sc: ScoredCapability, *, produced: bool = False) -> None:
        """Mark knowledge gap rules as satisfied for this (cap, entity) pair.

        This prevents gap rules from generating the same gaps endlessly.
        For host-level capabilities, mark the host.
        For endpoint-level, the dedup logic prevents re-execution.

        Args:
            sc: The scored capability that was executed.
            produced: Whether the execution actually produced new entities.
        """
        cap = sc.capability
        entity = sc.target_entity

        # NOTE: host_vuln_tested is NOT set here. Multiple host-level pentesting
        # plugins (xxe_check, jwt_attack, git_exposure, cors_exploit, etc.) need to
        # run on the same host. The execution fingerprint tracking (graph.was_executed)
        # prevents re-running the same plugin, and the loop terminates naturally with
        # no_candidates when all matching plugins have been executed.

        # Mark service discovery complete — only if execution actually produced
        # entities, so that other service-producing plugins (port_scan, shodan_lookup)
        # still get a chance to run on this host if the first one found nothing.
        if (
            "Service" in cap.produces_knowledge
            and entity.type == EntityType.HOST
            and produced
        ):
            entity.data["services_checked"] = True

        # Mark tech detection complete — only if execution actually produced entities,
        # so that other tech-producing plugins still get a chance to run
        if (
            "Technology" in cap.produces_knowledge
            and entity.type == EntityType.HOST
            and produced
        ):
            entity.data["tech_checked"] = True

        # Mark endpoint discovery complete — only if execution produced entities
        if (
            "Endpoint" in cap.produces_knowledge
            and entity.type == EntityType.HOST
            and produced
        ):
            entity.data["endpoints_checked"] = True
            # form_analyzer / web_crawler also produce Endpoint — mark forms checked
            if cap.plugin_name in (
                "form_analyzer", "web_crawler", "link_extractor",
            ):
                entity.data["forms_checked"] = True

        # Mark technology version check complete
        if entity.type == EntityType.TECHNOLOGY:
            entity.data["version_checked"] = True

        # Mark container runtime check complete
        if (
            "Technology:container_runtime" in cap.produces_knowledge
            and entity.type == EntityType.HOST
        ):
            entity.data["container_runtime_checked"] = True

        # Mark container enumeration complete
        if (
            "Container" in cap.produces_knowledge
            and entity.type == EntityType.TECHNOLOGY
            and entity.data.get("is_container_runtime")
        ):
            entity.data["containers_enumerated"] = True

        # Mark container config audit complete
        if cap.plugin_name == "container_config_audit" and entity.type == EntityType.CONTAINER:
            entity.data["config_audited"] = True

        # Mark image analysis complete
        if cap.plugin_name == "image_fingerprint" and entity.type == EntityType.IMAGE:
            entity.data["vulnerabilities_checked"] = True

        # Mark findings as verified when a verification plugin runs
        if cap.reduces_uncertainty and entity.type == EntityType.FINDING:
            entity.data["verified"] = True
            self.bus.emit(Event(EventType.FINDING_VERIFIED, {
                "entity_id": entity.id,
                "plugin": cap.plugin_name,
            }))

        # NOTE: Service entities are NOT marked as tested here.
        # Multiple service-specific plugins (redis_exploit, ssh_brute, etc.)
        # need to run on the same service. The execution fingerprint tracking
        # (graph.was_executed) prevents re-running the same plugin on the same
        # entity, so the gap naturally resolves when all capabilities are exhausted.

    def _evaluate_verifications(self, chosen: list[ScoredCapability]) -> None:
        """Evaluate verification results and update finding confidence.

        For each executed capability that has reduces_uncertainty and targets
        a FINDING entity, look up the plugin result and run it through the
        confirmer + confidence model pipeline.
        """
        if self._confirmer is None or self._confidence_model is None:
            return
        for sc in chosen:
            cap = sc.capability
            entity = sc.target_entity
            if not cap.reduces_uncertainty or entity.type != EntityType.FINDING:
                continue
            host = entity.data.get("host", "")
            pipeline_key = f"{cap.plugin_name}:{host}"
            plugin_result = self.executor.ctx.pipeline.get(pipeline_key)
            if plugin_result is None:
                continue
            confirmation = self._confirmer.evaluate_result(entity, plugin_result)
            category = self._confirmer._extract_category(entity)
            update = self._confidence_model.update_from_verification(
                entity, confirmation.verdict, category=category,
            )
            self._confidence_model.apply(update, self.graph)

            # Plan revalidation for confirmed/likely findings
            if self._revalidator is not None and confirmation.verdict in (
                "confirmed", "likely",
            ):
                requests = self._revalidator.plan_revalidation(entity)
                for req in requests:
                    entity.data["needs_revalidation"] = True
                    entity.data["revalidation_plugins"] = req.suggested_plugins

    @staticmethod
    def _fingerprint(sc: Any) -> str:
        """Create a unique fingerprint for a (capability, entity) pair.

        For Endpoint-targeted plugins (pentesting, exploitation), use plugin:host
        because these plugins scan ALL injection points on the host in a single run.
        For other entity types, use the full entity ID.
        """
        if sc.target_entity.type == EntityType.ENDPOINT:
            host = sc.target_entity.data.get("host", sc.target_entity.id)
            return f"{sc.capability.plugin_name}:{host}"
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
            "containers": len(self.graph.containers()),
            "images": len(self.graph.images()),
        }
