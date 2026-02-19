"""Tests for the autonomous loop."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from basilisk.capabilities.capability import Capability
from basilisk.events.bus import EventBus
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.models.target import Target
from basilisk.observations.observation import Observation
from basilisk.orchestrator.loop import AutonomousLoop
from basilisk.orchestrator.planner import KnowledgeGap, Planner
from basilisk.orchestrator.safety import SafetyLimits
from basilisk.orchestrator.selector import Selector
from basilisk.scoring.scorer import Scorer


def _make_loop(
    *,
    max_steps: int = 10,
    gaps: list[KnowledgeGap] | None = None,
    observations: list[Observation] | None = None,
) -> tuple[AutonomousLoop, KnowledgeGraph]:
    graph = KnowledgeGraph()

    planner = MagicMock(spec=Planner)
    # First call returns gaps, subsequent calls return empty (converged)
    if gaps is not None:
        planner.find_gaps.side_effect = [gaps, []]
    else:
        planner.find_gaps.return_value = []

    cap = Capability(
        name="test_cap", plugin_name="test_cap", category="recon",
        requires_knowledge=["Host"], produces_knowledge=["Service"],
        cost_score=2.0, noise_score=1.0,
    )
    selector = Selector({"test_cap": cap})
    scorer = Scorer(graph)

    executor = AsyncMock()
    executor.execute.return_value = observations or []
    executor.ctx = MagicMock()
    executor.ctx.pipeline = {}

    bus = EventBus()
    safety = SafetyLimits(max_steps=max_steps, batch_size=3)

    loop = AutonomousLoop(
        graph=graph,
        planner=planner,
        selector=selector,
        scorer=scorer,
        executor=executor,
        bus=bus,
        safety=safety,
    )

    return loop, graph


class TestLoopTermination:
    async def test_terminates_when_no_gaps(self):
        loop, graph = _make_loop(gaps=None)
        targets = [Target.domain("test.com")]
        result = await loop.run(targets)
        assert result.termination_reason == "no_gaps"

    async def test_terminates_on_max_steps(self):
        # Planner always returns gaps → will hit max_steps
        planner = MagicMock(spec=Planner)
        host_entity = Entity.host("test.com")
        planner.find_gaps.return_value = [
            KnowledgeGap(entity=host_entity, missing="services", priority=10.0, description="test"),
        ]

        graph = KnowledgeGraph()
        cap = Capability(
            name="port_scan", plugin_name="port_scan", category="scanning",
            requires_knowledge=["Host"], produces_knowledge=["Service"],
            cost_score=2.0, noise_score=1.0,
        )
        selector = Selector({"port_scan": cap})
        scorer = Scorer(graph)
        executor = AsyncMock()
        executor.execute.return_value = []
        executor.ctx = MagicMock()
        executor.ctx.pipeline = {}

        loop = AutonomousLoop(
            graph=graph, planner=planner, selector=selector, scorer=scorer,
            executor=executor, bus=EventBus(),
            safety=SafetyLimits(max_steps=2, batch_size=1),
        )

        result = await loop.run([Target.domain("test.com")])
        # Should stop after max_steps
        assert "limit_reached" in result.termination_reason or "all_executed" in result.termination_reason


class TestLoopSeedTargets:
    async def test_seeds_host_entities(self):
        loop, graph = _make_loop()
        await loop.run([Target.domain("a.com"), Target.domain("b.com")])
        assert len(graph.hosts()) == 2

    async def test_seeds_correct_host_data(self):
        loop, graph = _make_loop()
        await loop.run([Target.domain("seed.com")])
        hosts = graph.hosts()
        assert hosts[0].data["host"] == "seed.com"


class TestLoopExecution:
    async def test_applies_observations(self):
        host_entity = Entity.host("obs.com")
        obs = Observation(
            entity_type=EntityType.SERVICE,
            entity_data={"host": "obs.com", "port": 80, "protocol": "tcp"},
            key_fields={"host": "obs.com", "port": "80", "protocol": "tcp"},
            source_plugin="test",
        )
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="need ports",
        )

        loop, graph = _make_loop(gaps=[gap], observations=[obs])
        await loop.run([Target.domain("obs.com")])

        # Service entity should be in graph
        services = graph.services()
        assert len(services) >= 1

    async def test_timeline_has_entries(self):
        host_entity = Entity.host("tl.com")
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="test",
        )
        loop, graph = _make_loop(gaps=[gap])
        result = await loop.run([Target.domain("tl.com")])
        # Timeline should have at least something if execution happened
        assert result.timeline is not None

    async def test_events_emitted(self):
        events_received = []
        host_entity = Entity.host("ev.com")
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="test",
        )
        loop, graph = _make_loop(gaps=[gap])
        loop.bus.subscribe("entity_created", lambda e: events_received.append(e))
        await loop.run([Target.domain("ev.com")])
        assert len(events_received) > 0


class TestLoopResult:
    async def test_result_has_graph(self):
        loop, graph = _make_loop()
        result = await loop.run([Target.domain("r.com")])
        assert result.graph is graph

    async def test_result_has_step_count(self):
        loop, graph = _make_loop()
        result = await loop.run([Target.domain("r.com")])
        assert result.steps >= 1

    async def test_result_collects_summary(self):
        loop, graph = _make_loop()
        result = await loop.run([Target.domain("r.com")])
        assert "hosts" in result.results
        assert "entities" in result.results
