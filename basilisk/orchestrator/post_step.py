"""Post-step processing — coverage, verification, hypothesis, belief revision."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from basilisk.decisions.decision import Decision
from basilisk.events.bus import Event, EventType
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.orchestrator.constants import (
    GAP_CONFIG_AUDITED,
    GAP_CONTAINER_RUNTIME_CHECKED,
    GAP_CONTAINERS_ENUMERATED,
    GAP_ENDPOINTS_CHECKED,
    GAP_FORMS_CHECKED,
    GAP_SERVICES_CHECKED,
    GAP_TECH_CHECKED,
    GAP_VERIFIED,
    GAP_VERSION_CHECKED,
    GAP_VULNERABILITIES_CHECKED,
)

if TYPE_CHECKING:
    from basilisk.events.bus import EventBus
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.orchestrator.coverage_tracker import CoverageTracker
    from basilisk.orchestrator.executor_protocol import ExecutorProtocol
    from basilisk.reasoning.belief import EvidenceAggregator
    from basilisk.reasoning.hypothesis import HypothesisEngine
    from basilisk.scoring.scorer import ScoredCapability
    from basilisk.verification.confidence import ConfidenceModel
    from basilisk.verification.confirmer import FindingConfirmer
    from basilisk.verification.revalidator import ReValidator

logger = logging.getLogger(__name__)


class PostStepHandler:
    """Post-step processing: coverage, verification, hypothesis, belief revision."""

    def __init__(
        self,
        graph: KnowledgeGraph,
        bus: EventBus,
        *,
        hypothesis_engine: HypothesisEngine | None = None,
        evidence_aggregator: EvidenceAggregator | None = None,
        coverage_tracker: CoverageTracker | None = None,
        confirmer: FindingConfirmer | None = None,
        confidence_model: ConfidenceModel | None = None,
        revalidator: ReValidator | None = None,
        executor: ExecutorProtocol | None = None,
    ) -> None:
        self._graph = graph
        self._bus = bus
        self._hypothesis_engine = hypothesis_engine
        self._evidence_aggregator = evidence_aggregator
        self._coverage_tracker = coverage_tracker
        self._confirmer = confirmer
        self._confidence_model = confidence_model
        self._revalidator = revalidator
        self._executor = executor

    def process(
        self,
        chosen: list[ScoredCapability],
        results: list,
        decisions: list[Decision],
        step: int,
    ) -> None:
        """Run all post-step processing."""
        self._track_coverage(chosen, results)
        self._evaluate_verifications(chosen)
        self._generate_hypotheses()
        self._record_evidence(results, decisions)
        self._revise_beliefs()
        self._update_hypothesis_confidence(results, decisions)
        self._reset_aggregator()
        self._mark_gaps_satisfied(chosen, results, decisions)

    def _track_coverage(
        self, chosen: list[ScoredCapability], results: list,
    ) -> None:
        """Track plugin execution and finding coverage."""
        if self._coverage_tracker is None:
            return
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

    def _evaluate_verifications(self, chosen: list[ScoredCapability]) -> None:
        """Evaluate verification results and update finding confidence."""
        if self._confirmer is None or self._confidence_model is None:
            return
        for sc in chosen:
            cap = sc.capability
            entity = sc.target_entity
            if not cap.reduces_uncertainty or entity.type != EntityType.FINDING:
                continue
            host = entity.data.get("host", "")
            pipeline_key = f"{cap.plugin_name}:{host}"
            pipeline = getattr(self._executor, "ctx", None)
            if pipeline is None:
                continue
            plugin_result = pipeline.pipeline.get(pipeline_key)
            if plugin_result is None:
                continue
            confirmation = self._confirmer.evaluate_result(entity, plugin_result)
            category = self._confirmer._extract_category(entity)
            update = self._confidence_model.update_from_verification(
                entity, confirmation.verdict, category=category,
            )
            self._confidence_model.apply(update, self._graph)

            # Plan revalidation for confirmed/likely findings
            if self._revalidator is not None and confirmation.verdict in (
                "confirmed", "likely",
            ):
                requests = self._revalidator.plan_revalidation(entity)
                for req in requests:
                    entity.data["needs_revalidation"] = True
                    entity.data["revalidation_plugins"] = req.suggested_plugins

    def _generate_hypotheses(self) -> None:
        """Generate new hypotheses from updated graph."""
        if self._hypothesis_engine is None:
            return
        new_hypotheses = self._hypothesis_engine.generate_hypotheses(self._graph)
        for hyp in new_hypotheses:
            self._graph.add_hypothesis(hyp)
            logger.debug("Hypothesis created: %s", hyp.statement[:80])

    def _record_evidence(self, results: list, decisions: list[Decision]) -> None:
        """Record evidence in aggregator."""
        if self._evidence_aggregator is None:
            return
        for idx, obs_list in enumerate(results):
            if isinstance(obs_list, BaseException):
                continue
            d = decisions[idx] if idx < len(decisions) else None
            plugin_name = d.chosen_plugin if d else ""
            for obs in obs_list:
                entity_id = Entity.make_id(obs.entity_type, **obs.key_fields)
                self._evidence_aggregator.record_evidence(
                    entity_id, plugin_name, 0.0,
                )

    def _revise_beliefs(self) -> None:
        """Run belief revision and emit events."""
        if self._evidence_aggregator is None:
            return
        revisions = self._evidence_aggregator.revise_beliefs()
        for entity_id, old_conf, new_conf in revisions:
            if new_conf > old_conf:
                self._bus.emit(Event(EventType.BELIEF_STRENGTHENED, {
                    "entity_id": entity_id,
                    "old_confidence": old_conf,
                    "new_confidence": new_conf,
                }))
            else:
                self._bus.emit(Event(EventType.BELIEF_WEAKENED, {
                    "entity_id": entity_id,
                    "old_confidence": old_conf,
                    "new_confidence": new_conf,
                }))

    def _update_hypothesis_confidence(
        self, results: list, decisions: list[Decision],
    ) -> None:
        """Update hypothesis confidence from observations."""
        if self._hypothesis_engine is None:
            return
        from basilisk.observations.source_families import get_source_family

        for idx, obs_list in enumerate(results):
            if isinstance(obs_list, BaseException):
                continue
            d = decisions[idx] if idx < len(decisions) else None
            plugin_name = d.chosen_plugin if d else ""
            for obs in obs_list:
                entity_id = Entity.make_id(obs.entity_type, **obs.key_fields)
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
                        self._bus.emit(Event(EventType.HYPOTHESIS_CONFIRMED, {
                            "hypothesis_id": hyp.id,
                            "statement": hyp.statement,
                        }))
                    elif hyp.status == "rejected":
                        self._bus.emit(Event(EventType.HYPOTHESIS_REJECTED, {
                            "hypothesis_id": hyp.id,
                            "statement": hyp.statement,
                        }))

    def _reset_aggregator(self) -> None:
        """Reset aggregator for next step."""
        if self._evidence_aggregator is not None:
            self._evidence_aggregator.reset_step()

    def _mark_gaps_satisfied(
        self,
        chosen: list[ScoredCapability],
        results: list,
        decisions: list[Decision],
    ) -> None:
        """Mark gap rules as satisfied for executed capabilities."""
        for idx, sc in enumerate(chosen):
            produced = False
            if idx < len(results) and not isinstance(results[idx], BaseException):
                d = decisions[idx] if idx < len(decisions) else None
                produced = d.was_productive if d else False
            self._mark_gap_satisfied(sc, produced=produced)

    def _mark_gap_satisfied(
        self, sc: ScoredCapability, *, produced: bool = False,
    ) -> None:
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

        # Mark service discovery complete
        if (
            "Service" in cap.produces_knowledge
            and entity.type == EntityType.HOST
            and produced
        ):
            entity.data[GAP_SERVICES_CHECKED] = True

        # Mark tech detection complete
        if (
            "Technology" in cap.produces_knowledge
            and entity.type == EntityType.HOST
            and produced
        ):
            entity.data[GAP_TECH_CHECKED] = True

        # Mark endpoint discovery complete
        if (
            "Endpoint" in cap.produces_knowledge
            and entity.type == EntityType.HOST
            and produced
        ):
            entity.data[GAP_ENDPOINTS_CHECKED] = True
            if cap.plugin_name in (
                "form_analyzer", "web_crawler", "link_extractor",
            ):
                entity.data[GAP_FORMS_CHECKED] = True

        # Mark technology version check complete
        if entity.type == EntityType.TECHNOLOGY:
            entity.data[GAP_VERSION_CHECKED] = True

        # Mark container runtime check complete
        if (
            "Technology:container_runtime" in cap.produces_knowledge
            and entity.type == EntityType.HOST
        ):
            entity.data[GAP_CONTAINER_RUNTIME_CHECKED] = True

        # Mark container enumeration complete
        if (
            "Container" in cap.produces_knowledge
            and entity.type == EntityType.TECHNOLOGY
            and entity.data.get("is_container_runtime")
        ):
            entity.data[GAP_CONTAINERS_ENUMERATED] = True

        # Mark container config audit complete
        if cap.plugin_name == "container_config_audit" and entity.type == EntityType.CONTAINER:
            entity.data[GAP_CONFIG_AUDITED] = True

        # Mark image analysis complete
        if cap.plugin_name == "image_fingerprint" and entity.type == EntityType.IMAGE:
            entity.data[GAP_VULNERABILITIES_CHECKED] = True

        # Mark findings as verified when a verification plugin runs
        if cap.reduces_uncertainty and entity.type == EntityType.FINDING:
            entity.data[GAP_VERIFIED] = True
            self._bus.emit(Event(EventType.FINDING_VERIFIED, {
                "entity_id": entity.id,
                "plugin": cap.plugin_name,
            }))

        # NOTE: Service entities are NOT marked as tested here.
        # Multiple service-specific plugins (redis_exploit, ssh_brute, etc.)
        # need to run on the same service. The execution fingerprint tracking
        # (graph.was_executed) prevents re-running the same plugin on the same
        # entity, so the gap naturally resolves when all capabilities are exhausted.
