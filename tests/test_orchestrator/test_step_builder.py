"""Tests for the step builder."""

from __future__ import annotations

from unittest.mock import MagicMock

from basilisk.capabilities.capability import Capability
from basilisk.events.bus import EventBus
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.state import KnowledgeState
from basilisk.orchestrator.planner import KnowledgeGap, Planner
from basilisk.orchestrator.safety import SafetyLimits
from basilisk.orchestrator.selector import Selector
from basilisk.orchestrator.step_builder import StepBuilder, StepPlan
from basilisk.scoring.scorer import Scorer


def _make_gap() -> KnowledgeGap:
    entity = Entity.host("test.com")
    return KnowledgeGap(
        entity=entity,
        missing="services",
        description="test.com needs service discovery",
        priority=10.0,
    )


def _make_builder(
    *, gaps=None, max_steps=10,
) -> tuple[StepBuilder, KnowledgeGraph]:
    graph = KnowledgeGraph()
    planner = MagicMock(spec=Planner)
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
    safety = SafetyLimits(max_steps=max_steps, batch_size=3)
    safety.start()
    bus = EventBus()
    state = KnowledgeState(graph, planner)

    builder = StepBuilder(
        state=state,
        selector=selector,
        scorer=scorer,
        safety=safety,
        graph=graph,
        bus=bus,
    )
    return builder, graph


class TestStepBuilder:
    def test_returns_none_when_no_gaps(self):
        builder, _ = _make_builder(gaps=None)
        result = builder.build(1)
        assert result is None
        assert builder.termination_reason == "no_gaps"

    def test_returns_step_plan_with_gaps(self):
        gap = _make_gap()
        builder, graph = _make_builder(gaps=[gap])
        # Seed a host entity so selector finds matches
        graph.add_entity(gap.entity)
        result = builder.build(1)
        assert isinstance(result, StepPlan)
        assert len(result.chosen) > 0
        assert len(result.gaps) == 1

    def test_terminates_on_step_limit(self):
        gap = _make_gap()
        builder, graph = _make_builder(gaps=[gap], max_steps=1)
        graph.add_entity(gap.entity)
        # Step 1 should work
        result = builder.build(1)
        assert result is not None
        # Step 2 should terminate
        result2 = builder.build(2)
        assert result2 is None
        assert "limit_reached" in builder.termination_reason

    def test_no_candidates_after_execution(self):
        """After all capabilities are executed, builder returns None."""
        gap = _make_gap()
        builder, graph = _make_builder(gaps=[gap])
        graph.add_entity(gap.entity)

        # Make planner always return the same gap
        builder._state._planner.find_gaps.side_effect = None
        builder._state._planner.find_gaps.return_value = [gap]

        # First build succeeds
        plan = builder.build(1)
        assert plan is not None
        # Mark the chosen capability as executed
        for sc in plan.chosen:
            from basilisk.knowledge.fingerprint import make_execution_fingerprint
            fp = make_execution_fingerprint(sc.capability.plugin_name, sc.target_entity)
            graph.record_execution(fp)
        # Second build should return None (all executed → no_candidates)
        result = builder.build(2)
        assert result is None
        assert builder.termination_reason == "no_candidates"
