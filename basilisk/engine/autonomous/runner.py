"""Autonomous runner — wraps the existing orchestrator with v4 types."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

from basilisk.bridge.result_adapter import ResultAdapter

logger = logging.getLogger(__name__)


class RunResult(BaseModel):
    """Unified result from an autonomous audit run."""

    findings: list = Field(default_factory=list)
    steps: int = 0
    duration: float = 0.0
    termination_reason: str = ""
    graph_data: dict[str, Any] | None = None


class AutonomousRunner:
    """V4 wrapper around the existing AutonomousLoop.

    KnowledgeGraph, Planner, Selector, Scorer live inside this runner
    as internal state. Scenarios never see them directly.
    """

    def __init__(
        self,
        settings: Any,
        scenario_registry: Any = None,
        actor: Any = None,
        max_steps: int = 100,
        campaign_enabled: bool = False,
        plugin_filter: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        on_finding: Callable | None = None,
        on_step: Callable | None = None,
        **kwargs: Any,
    ):
        self._settings = settings
        self._scenario_registry = scenario_registry
        self._actor = actor
        self._max_steps = max_steps
        self._campaign_enabled = campaign_enabled
        self._plugin_filter = plugin_filter
        self._exclude_patterns = exclude_patterns
        self._on_finding = on_finding
        self._on_step = on_step
        self._kwargs = kwargs

    @property
    def _config(self) -> Any:
        return self._settings

    async def run(self, targets: list, settings: Any = None) -> RunResult:
        """Run the autonomous loop internally, return v4 RunResult."""
        settings = settings or self._settings

        from pathlib import Path

        import aiosqlite

        from basilisk.capabilities.mapping import build_capabilities_from_scenarios
        from basilisk.engine.scenario_registry import ScenarioRegistry
        from basilisk.events.bus import EventBus, EventType
        from basilisk.knowledge.graph import KnowledgeGraph
        from basilisk.memory.history import History
        from basilisk.orchestrator.goals import DEFAULT_GOAL_PROGRESSION, GoalEngine
        from basilisk.orchestrator.loop import AutonomousLoop
        from basilisk.orchestrator.planner import Planner
        from basilisk.orchestrator.safety import SafetyLimits
        from basilisk.orchestrator.scenario_executor import ScenarioExecutor
        from basilisk.orchestrator.selector import Selector
        from basilisk.reasoning.belief import EvidenceAggregator
        from basilisk.reasoning.hypothesis import HypothesisEngine
        from basilisk.scoring.scorer import Scorer

        # Build v4 infrastructure
        scenario_registry = ScenarioRegistry()
        scenario_registry.discover()

        graph = KnowledgeGraph()
        planner = Planner()
        capabilities = build_capabilities_from_scenarios(scenario_registry)

        # Apply plugin filter / exclude patterns
        if self._plugin_filter or self._exclude_patterns:
            from fnmatch import fnmatch

            filtered = {}
            for name, cap in capabilities.items():
                if self._plugin_filter and not any(
                    fnmatch(name, p) for p in self._plugin_filter
                ):
                    continue
                if self._exclude_patterns and any(
                    fnmatch(name, p) for p in self._exclude_patterns
                ):
                    continue
                filtered[name] = cap
            capabilities = filtered

        selector = Selector(capabilities)
        history = History()

        hypothesis_engine = HypothesisEngine()
        evidence_aggregator = EvidenceAggregator(graph, hypothesis_engine)

        # Optional verification infrastructure
        confirmer = None
        confidence_model = None
        coverage_tracker = None
        revalidator = None
        vuln_registry = None
        try:
            from basilisk.knowledge.vulns.registry import VulnRegistry
            from basilisk.orchestrator.coverage_tracker import CoverageTracker
            from basilisk.verification.confidence import ConfidenceModel
            from basilisk.verification.confirmer import FindingConfirmer
            from basilisk.verification.revalidator import ReValidator

            vuln_registry = VulnRegistry.load_bundled()
            confirmer = FindingConfirmer(capabilities, vuln_registry=vuln_registry)
            confidence_model = ConfidenceModel(vuln_registry=vuln_registry)
            coverage_tracker = CoverageTracker(vuln_registry=vuln_registry)
            revalidator = ReValidator(confirmer, vuln_registry=vuln_registry)
        except Exception:
            pass

        # Campaign memory (opt-in)
        campaign_memory = None
        campaign_store = None
        if self._campaign_enabled or settings.campaign.enabled:
            try:
                from basilisk.campaign.memory import CampaignMemory
                from basilisk.campaign.store import CampaignStore

                db_path = settings.campaign.data_dir / settings.campaign.db_name
                campaign_store = await CampaignStore.open(db_path)
                campaign_memory = CampaignMemory()
                await campaign_memory.load(campaign_store, [t.host for t in targets])
            except Exception:
                logger.warning("Campaign memory init failed", exc_info=True)
                campaign_memory = None
                campaign_store = None

        scorer = Scorer(
            graph, history=history,
            hypothesis_engine=hypothesis_engine,
            campaign_memory=campaign_memory,
        )
        orch_executor = ScenarioExecutor(
            registry=scenario_registry,
            actor=self._actor,
            settings=settings,
            tools=self._kwargs.get("tools", {}),
            state=self._kwargs.get("state", {}),
        )
        bus = self._kwargs.get("bus") or EventBus()

        # Persistent structured logging
        run_logger = None
        if settings.logging.enabled:
            try:
                from basilisk.logging.run_logger import RunLogger

                run_logger = RunLogger(
                    log_dir=settings.logging.log_dir,
                    target=targets[0].host if targets else "unknown",
                    bus=bus,
                    jsonl=settings.logging.jsonl,
                    human_readable=settings.logging.human_readable,
                    max_runs=settings.logging.max_runs,
                )
                await run_logger.open()
            except Exception:
                logger.warning("RunLogger init failed", exc_info=True)
                run_logger = None

        safety = SafetyLimits(
            max_steps=self._max_steps,
            batch_size=5,
        )
        goal_engine = GoalEngine(goals=list(DEFAULT_GOAL_PROGRESSION))

        # Wire on_finding callback via event bus
        if self._on_finding is not None:
            from basilisk.knowledge.entities import EntityType

            def _finding_handler(event: Any) -> None:
                entity = graph.get(event.data.get("entity_id", ""))
                if entity is not None and entity.type == EntityType.FINDING:
                    self._on_finding(entity)

            bus.subscribe(EventType.ENTITY_CREATED, _finding_handler)

        loop = AutonomousLoop(
            graph=graph,
            planner=planner,
            selector=selector,
            scorer=scorer,
            executor=orch_executor,
            bus=bus,
            safety=safety,
            history=history,
            on_progress=self._on_step,
            goal_engine=goal_engine,
            hypothesis_engine=hypothesis_engine,
            evidence_aggregator=evidence_aggregator,
            coverage_tracker=coverage_tracker,
            confirmer=confirmer,
            confidence_model=confidence_model,
            revalidator=revalidator,
        )

        # Convert v4 targets to v3 targets for the loop
        from basilisk.models.target import Target as V3Target

        v3_targets = []
        for t in targets:
            v3_targets.append(V3Target(host=t.host, ports=t.ports, meta=t.meta))

        try:
            result = await loop.run(v3_targets)

            # Write run summary and close logger
            if run_logger is not None:
                try:
                    await run_logger.log_summary(
                        loop.timeline,
                        loop._history,
                        termination_reason=result.termination_reason,
                        graph=result.graph,
                    )
                    await run_logger.close()
                except Exception:
                    logger.warning("RunLogger summary/close failed", exc_info=True)

            # Persist knowledge graph to SQLite
            try:
                from basilisk.knowledge.store import KnowledgeStore

                kg_path = Path(settings.storage.db_path).parent / "knowledge.db"
                kg_path.parent.mkdir(parents=True, exist_ok=True)
                async with aiosqlite.connect(str(kg_path)) as kg_db:
                    kg_store = KnowledgeStore(kg_db)
                    await kg_store.init_schema()
                    await kg_store.save(result.graph)
            except Exception:
                logger.warning("KG persistence failed", exc_info=True)

            # Save campaign data after successful run
            if campaign_memory is not None and campaign_store is not None:
                try:
                    campaign_memory.update_from_graph(result.graph, history)
                    await campaign_memory.save(campaign_store)
                except Exception:
                    logger.warning("Campaign save failed", exc_info=True)
        finally:
            if campaign_store is not None:
                with contextlib.suppress(Exception):
                    await campaign_store.close()
            if self._actor:
                await self._actor.close()

        # Convert all findings to v4
        all_findings = []
        for pr in result.plugin_results.values():
            sr = ResultAdapter.to_scenario_result(pr)
            all_findings.extend(sr.findings)

        return RunResult(
            findings=all_findings,
            steps=result.steps,
            duration=result.duration,
            termination_reason=result.termination_reason,
            graph_data={
                "entity_count": result.graph.entity_count,
                "relation_count": result.graph.relation_count,
            },
        )
