"""Tests for the autonomous loop."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from basilisk.capabilities.capability import Capability
from basilisk.events.bus import EventBus, EventType
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import RelationType
from basilisk.memory.history import History
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
    history: History | None = None,
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
    scorer = Scorer(graph, history=history)

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
        history=history,
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
        # With only 1 capability, after step 1 executes it, step 2 has no candidates
        reason = result.termination_reason
        assert "limit_reached" in reason or "no_candidates" in reason


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


class TestLoopSeedWithPort:
    async def test_seed_with_port_creates_service(self):
        loop, graph = _make_loop()
        await loop.run([Target.ip("127.0.0.1:4280", ports=[4280])])
        hosts = graph.hosts()
        assert len(hosts) == 1
        assert hosts[0].data["host"] == "127.0.0.1:4280"
        services = graph.services()
        assert len(services) == 1
        assert services[0].data["port"] == 4280
        assert services[0].data["service"] == "http"

    async def test_seed_with_port_creates_exposes_relation(self):
        loop, graph = _make_loop()
        await loop.run([Target.ip("10.0.0.1:8080", ports=[8080])])
        host = graph.hosts()[0]
        neighbors = graph.neighbors(host.id, RelationType.EXPOSES)
        assert len(neighbors) == 1
        assert neighbors[0].data["port"] == 8080

    async def test_seed_with_multiple_ports(self):
        loop, graph = _make_loop()
        await loop.run([Target.ip("10.0.0.1:80", ports=[80, 443])])
        services = graph.services()
        assert len(services) == 2
        ports = {s.data["port"] for s in services}
        assert ports == {80, 443}

    async def test_seed_domain_no_ports(self):
        loop, graph = _make_loop()
        await loop.run([Target.domain("example.com")])
        services = graph.services()
        assert len(services) == 0


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


class TestLoopDecisions:
    async def test_decisions_in_result(self):
        host_entity = Entity.host("dec.com")
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="need scan",
        )
        loop, graph = _make_loop(gaps=[gap])
        result = await loop.run([Target.domain("dec.com")])
        assert len(result.decisions) >= 1

    async def test_decision_has_reasoning_trace(self):
        host_entity = Entity.host("trace.com")
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="need scan",
        )
        loop, graph = _make_loop(gaps=[gap])
        result = await loop.run([Target.domain("trace.com")])
        if result.decisions:
            assert result.decisions[0].reasoning_trace != ""
            assert "Gap" in result.decisions[0].reasoning_trace

    async def test_decision_has_context_snapshot(self):
        host_entity = Entity.host("snap.com")
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="need scan",
        )
        loop, graph = _make_loop(gaps=[gap])
        result = await loop.run([Target.domain("snap.com")])
        if result.decisions:
            ctx = result.decisions[0].context
            assert ctx.host_count >= 1
            assert ctx.step >= 1

    async def test_decision_evaluated_options(self):
        host_entity = Entity.host("opts.com")
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="need scan",
        )
        loop, graph = _make_loop(gaps=[gap])
        result = await loop.run([Target.domain("opts.com")])
        if result.decisions:
            assert len(result.decisions[0].evaluated_options) >= 1
            chosen = [o for o in result.decisions[0].evaluated_options if o.was_chosen]
            assert len(chosen) == 1

    async def test_decision_confidence_delta_with_observations(self):
        host_entity = Entity.host("delta.com")
        obs = Observation(
            entity_type=EntityType.SERVICE,
            entity_data={"host": "delta.com", "port": 443, "protocol": "tcp"},
            key_fields={"host": "delta.com", "port": "443", "protocol": "tcp"},
            confidence=0.9,
            source_plugin="test",
        )
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="need scan",
        )
        loop, graph = _make_loop(gaps=[gap], observations=[obs])
        result = await loop.run([Target.domain("delta.com")])
        if result.decisions:
            # With new entities produced, confidence_delta should be > 0
            d = result.decisions[0]
            assert d.outcome_new_entities >= 1
            assert d.was_productive is True

    async def test_decision_made_event_emitted(self):
        events = []
        host_entity = Entity.host("event.com")
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="test",
        )
        loop, graph = _make_loop(gaps=[gap])
        loop.bus.subscribe(
            EventType.DECISION_MADE, lambda e: events.append(e),
        )
        await loop.run([Target.domain("event.com")])
        assert len(events) >= 1
        assert "decision_id" in events[0].data
        assert "reasoning" in events[0].data


class TestLoopWithHistory:
    async def test_history_recorded(self):
        history = History()
        host_entity = Entity.host("hist.com")
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="need scan",
        )
        loop, graph = _make_loop(gaps=[gap], history=history)
        result = await loop.run([Target.domain("hist.com")])
        assert len(history) >= 1
        assert result.history is history

    async def test_history_outcome_updated(self):
        history = History()
        host_entity = Entity.host("out.com")
        obs = Observation(
            entity_type=EntityType.SERVICE,
            entity_data={"host": "out.com", "port": 80, "protocol": "tcp"},
            key_fields={"host": "out.com", "port": "80", "protocol": "tcp"},
            source_plugin="test",
        )
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="need scan",
        )
        loop, graph = _make_loop(gaps=[gap], observations=[obs], history=history)
        await loop.run([Target.domain("out.com")])
        assert history.decisions[0].outcome_observations >= 1


class TestLoopPreFiltering:
    async def test_executed_pairs_filtered_before_pick(self):
        """Already-executed (plugin, entity) pairs are filtered before pick(),
        so the loop picks fresh candidates instead of terminating with all_executed."""
        host_entity = Entity.host("filter.com")
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="need scan",
        )

        graph = KnowledgeGraph()
        # Create two capabilities so selector can match both
        cap1 = Capability(
            name="cap_a", plugin_name="cap_a", category="scanning",
            requires_knowledge=["Host"], produces_knowledge=["Service"],
            cost_score=2.0, noise_score=1.0,
        )
        cap2 = Capability(
            name="cap_b", plugin_name="cap_b", category="scanning",
            requires_knowledge=["Host"], produces_knowledge=["Service"],
            cost_score=3.0, noise_score=1.0,
        )

        planner = MagicMock(spec=Planner)
        # Return gaps twice, then empty (converged after 2 steps)
        planner.find_gaps.side_effect = [[gap], [gap], []]

        selector = Selector({"cap_a": cap1, "cap_b": cap2})
        scorer = Scorer(graph)
        executor = AsyncMock()
        executor.execute.return_value = []
        executor.ctx = MagicMock()
        executor.ctx.pipeline = {}

        loop = AutonomousLoop(
            graph=graph, planner=planner, selector=selector, scorer=scorer,
            executor=executor, bus=EventBus(),
            safety=SafetyLimits(max_steps=5, batch_size=1),
        )

        result = await loop.run([Target.domain("filter.com")])
        # With budget=1, step1 picks cap_a, step2 picks cap_b (cap_a already executed).
        # Without pre-filtering, step2 would pick cap_a again and skip → all_executed.
        assert result.termination_reason != "all_executed"
        assert executor.execute.call_count == 2


class TestMarkGapSatisfied:
    async def test_host_vuln_tested_not_set(self):
        """_mark_gap_satisfied should NOT set host_vuln_tested, allowing
        multiple pentesting plugins (xxe, jwt, git_exposure, etc.) to run."""
        host_entity = Entity.host("vuln.com")
        obs = Observation(
            entity_type=EntityType.SERVICE,
            entity_data={"host": "vuln.com", "port": 80, "protocol": "tcp"},
            key_fields={"host": "vuln.com", "port": "80", "protocol": "tcp"},
            source_plugin="test",
        )
        gap = KnowledgeGap(
            entity=host_entity, missing="services", priority=10.0, description="need scan",
        )
        loop, graph = _make_loop(gaps=[gap], observations=[obs])

        # Use a capability that produces Finding (like pentesting plugins do)
        finding_cap = Capability(
            name="http_headers", plugin_name="http_headers", category="analysis",
            requires_knowledge=["Host"], produces_knowledge=["Finding"],
            cost_score=1.0, noise_score=0.0,
        )
        from basilisk.scoring.scorer import ScoredCapability
        sc = ScoredCapability(
            capability=finding_cap,
            target_entity=host_entity,
            score=5.0,
            reason="test",
        )
        graph.add_entity(host_entity)
        loop._mark_gap_satisfied(sc)

        # host_vuln_tested should NOT be in host data
        assert "host_vuln_tested" not in host_entity.data
