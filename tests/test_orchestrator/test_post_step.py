"""Tests for the post-step handler."""

from __future__ import annotations

from unittest.mock import MagicMock

from basilisk.capabilities.capability import Capability
from basilisk.events.bus import EventBus, EventType
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.observations.observation import Observation
from basilisk.orchestrator.constants import (
    GAP_ENDPOINTS_CHECKED,
    GAP_SERVICES_CHECKED,
    GAP_TECH_CHECKED,
    GAP_VERIFIED,
    GAP_VERSION_CHECKED,
)
from basilisk.orchestrator.post_step import PostStepHandler
from basilisk.scoring.scorer import ScoredCapability


def _make_handler(**kwargs) -> tuple[PostStepHandler, KnowledgeGraph, EventBus]:
    graph = KnowledgeGraph()
    bus = EventBus()
    handler = PostStepHandler(graph=graph, bus=bus, **kwargs)
    return handler, graph, bus


def _make_scored(
    plugin_name="test_cap",
    entity=None,
    produces=None,
    reduces_uncertainty=None,
) -> ScoredCapability:
    if entity is None:
        entity = Entity.host("test.com")
    cap = Capability(
        name=plugin_name,
        plugin_name=plugin_name,
        category="recon",
        requires_knowledge=["Host"],
        produces_knowledge=produces or ["Service"],
        reduces_uncertainty=reduces_uncertainty or [],
    )
    return ScoredCapability(
        capability=cap,
        target_entity=entity,
        score=1.0,
        reason="test",
    )


def _make_decision():
    from datetime import UTC, datetime

    from basilisk.decisions.decision import Decision
    now = datetime.now(UTC)
    return Decision(
        id="test-decision-1",
        timestamp=now,
        step=1,
        goal="services",
        goal_description="test gap",
        goal_priority=10.0,
        triggering_entity_id="entity-1",
        evaluated_options=[],
        chosen_capability="test_cap",
        chosen_plugin="test_cap",
        chosen_target="test.com",
        chosen_score=1.0,
        reasoning_trace="test reasoning",
    )


class TestGapSatisfaction:
    def test_marks_services_checked(self):
        handler, _, _ = _make_handler()
        entity = Entity.host("test.com")
        sc = _make_scored(entity=entity, produces=["Service"])
        decision = _make_decision()
        decision.was_productive = True

        handler._mark_gaps_satisfied(
            [sc], [[]], [decision],
        )
        assert entity.data.get(GAP_SERVICES_CHECKED) is True

    def test_marks_services_even_if_not_productive(self):
        """Gap flags are set on execution, not production — prevents re-scanning."""
        handler, _, _ = _make_handler()
        entity = Entity.host("test.com")
        sc = _make_scored(entity=entity, produces=["Service"])
        decision = _make_decision()
        decision.was_productive = False

        handler._mark_gaps_satisfied(
            [sc], [[]], [decision],
        )
        assert entity.data.get(GAP_SERVICES_CHECKED) is True

    def test_marks_tech_checked(self):
        handler, _, _ = _make_handler()
        entity = Entity.host("test.com")
        sc = _make_scored(entity=entity, produces=["Technology"])
        decision = _make_decision()
        decision.was_productive = True

        handler._mark_gaps_satisfied([sc], [[]], [decision])
        assert entity.data.get(GAP_TECH_CHECKED) is True

    def test_marks_endpoints_checked(self):
        handler, _, _ = _make_handler()
        entity = Entity.host("test.com")
        sc = _make_scored(entity=entity, produces=["Endpoint"])
        decision = _make_decision()
        decision.was_productive = True

        handler._mark_gaps_satisfied([sc], [[]], [decision])
        assert entity.data.get(GAP_ENDPOINTS_CHECKED) is True

    def test_marks_tech_even_if_not_productive(self):
        handler, _, _ = _make_handler()
        entity = Entity.host("test.com")
        sc = _make_scored(entity=entity, produces=["Technology"])
        decision = _make_decision()
        decision.was_productive = False

        handler._mark_gaps_satisfied([sc], [[]], [decision])
        assert entity.data.get(GAP_TECH_CHECKED) is True

    def test_marks_endpoints_even_if_not_productive(self):
        handler, _, _ = _make_handler()
        entity = Entity.host("test.com")
        sc = _make_scored(entity=entity, produces=["Endpoint"])
        decision = _make_decision()
        decision.was_productive = False

        handler._mark_gaps_satisfied([sc], [[]], [decision])
        assert entity.data.get(GAP_ENDPOINTS_CHECKED) is True

    def test_marks_version_checked_for_technology(self):
        handler, _, _ = _make_handler()
        entity = Entity.technology("test.com", "nginx")
        sc = _make_scored(entity=entity, produces=["Vulnerability"])
        decision = _make_decision()
        decision.was_productive = False

        handler._mark_gaps_satisfied([sc], [[]], [decision])
        assert entity.data.get(GAP_VERSION_CHECKED) is True

    def test_marks_finding_verified(self):
        handler, _, bus = _make_handler()
        entity = Entity.finding("test.com", "XSS", "high")
        sc = _make_scored(
            entity=entity,
            produces=["Finding"],
            reduces_uncertainty=["Finding:xss"],
        )
        decision = _make_decision()
        decision.was_productive = False

        events = []
        bus.subscribe(EventType.FINDING_VERIFIED, lambda e: events.append(e))

        handler._mark_gaps_satisfied([sc], [[]], [decision])
        assert entity.data.get(GAP_VERIFIED) is True
        assert len(events) == 1


class TestCoverageTracking:
    def test_tracks_execution(self):
        coverage = MagicMock()
        handler, _, _ = _make_handler(coverage_tracker=coverage)
        entity = Entity.host("test.com")
        sc = _make_scored(entity=entity)

        handler._track_coverage([sc], [[]])
        coverage.record_execution.assert_called_once_with("test_cap", "test.com")

    def test_tracks_findings(self):
        coverage = MagicMock()
        handler, _, _ = _make_handler(coverage_tracker=coverage)
        entity = Entity.host("test.com")
        sc = _make_scored(entity=entity)

        finding_obs = Observation(
            entity_type=EntityType.FINDING,
            key_fields={"host": "test.com", "title": "XSS"},
            entity_data={"host": "test.com", "category": "xss"},
            confidence=0.9,
            source_plugin="xss_basic",
        )

        handler._track_coverage([sc], [[finding_obs]])
        coverage.record_finding.assert_called_once_with("test.com", "xss")


class TestHypothesisGeneration:
    def test_generates_hypotheses(self):
        hyp_engine = MagicMock()
        hyp_engine.generate_hypotheses.return_value = []
        handler, _, _ = _make_handler(hypothesis_engine=hyp_engine)

        handler._generate_hypotheses()
        hyp_engine.generate_hypotheses.assert_called_once()

    def test_adds_hypotheses_to_graph(self):
        hyp = MagicMock()
        hyp.statement = "Test hypothesis about shared technology"
        hyp_engine = MagicMock()
        hyp_engine.generate_hypotheses.return_value = [hyp]
        graph = MagicMock()
        bus = EventBus()
        handler = PostStepHandler(
            graph=graph, bus=bus, hypothesis_engine=hyp_engine,
        )

        handler._generate_hypotheses()
        graph.add_hypothesis.assert_called_once_with(hyp)


class TestEvidenceRecording:
    def test_passes_confidence_delta_from_decision(self):
        """Evidence aggregator receives real confidence delta, not 0.0."""
        aggregator = MagicMock()
        handler, _, _ = _make_handler(evidence_aggregator=aggregator)

        obs = Observation(
            entity_type=EntityType.HOST,
            key_fields={"host": "test.com"},
            entity_data={"host": "test.com"},
            confidence=0.8,
            source_plugin="port_scan",
        )
        decision = _make_decision()
        decision.outcome_confidence_delta = 0.3
        decision.outcome_new_entities = 2

        handler._record_evidence([[obs]], [decision])
        aggregator.record_evidence.assert_called_once()
        call_args = aggregator.record_evidence.call_args
        assert call_args[0][2] == 0.3  # delta = 0.3 / 1 obs

    def test_distributes_delta_across_observations(self):
        """Multiple observations split the total confidence delta."""
        aggregator = MagicMock()
        handler, _, _ = _make_handler(evidence_aggregator=aggregator)

        obs1 = Observation(
            entity_type=EntityType.HOST,
            key_fields={"host": "a.com"},
            entity_data={"host": "a.com"},
            confidence=0.8,
            source_plugin="dns",
        )
        obs2 = Observation(
            entity_type=EntityType.SERVICE,
            key_fields={"host": "a.com", "port": "80", "protocol": "tcp"},
            entity_data={"port": 80},
            confidence=0.8,
            source_plugin="dns",
        )
        decision = _make_decision()
        decision.outcome_confidence_delta = 0.6
        decision.outcome_new_entities = 2

        handler._record_evidence([[obs1, obs2]], [decision])
        assert aggregator.record_evidence.call_count == 2
        for call in aggregator.record_evidence.call_args_list:
            assert abs(call[0][2] - 0.3) < 0.001  # 0.6 / 2


class TestHypothesisConfidenceUpdate:
    def test_passes_was_new_from_decision(self):
        """Hypothesis engine receives was_new from decision, not hardcoded True."""
        hyp_engine = MagicMock()
        hyp_engine.update_from_observation.return_value = []
        handler, _, _ = _make_handler(hypothesis_engine=hyp_engine)

        obs = Observation(
            entity_type=EntityType.HOST,
            key_fields={"host": "test.com"},
            entity_data={"host": "test.com"},
            confidence=0.8,
            source_plugin="port_scan",
        )
        decision = _make_decision()
        decision.outcome_confidence_delta = 0.0
        decision.outcome_new_entities = 0  # nothing new

        handler._update_hypothesis_confidence([[obs]], [decision])
        call_args = hyp_engine.update_from_observation.call_args
        assert call_args.kwargs["was_new"] is False
        assert call_args.kwargs["confidence_delta"] == 0.0

    def test_passes_positive_delta_when_productive(self):
        """Hypothesis engine receives real delta when decision was productive."""
        hyp_engine = MagicMock()
        hyp_engine.update_from_observation.return_value = []
        handler, _, _ = _make_handler(hypothesis_engine=hyp_engine)

        obs = Observation(
            entity_type=EntityType.HOST,
            key_fields={"host": "test.com"},
            entity_data={"host": "test.com"},
            confidence=0.8,
            source_plugin="port_scan",
        )
        decision = _make_decision()
        decision.outcome_confidence_delta = 0.5
        decision.outcome_new_entities = 3

        handler._update_hypothesis_confidence([[obs]], [decision])
        call_args = hyp_engine.update_from_observation.call_args
        assert call_args.kwargs["was_new"] is True
        assert call_args.kwargs["confidence_delta"] == 0.5


class TestBeliefRevision:
    def test_emits_belief_strengthened(self):
        aggregator = MagicMock()
        aggregator.revise_beliefs.return_value = [("e1", 0.5, 0.8)]
        handler, _, bus = _make_handler(evidence_aggregator=aggregator)

        events = []
        bus.subscribe(EventType.BELIEF_STRENGTHENED, lambda e: events.append(e))

        handler._revise_beliefs()
        assert len(events) == 1
        assert events[0].data["old_confidence"] == 0.5
        assert events[0].data["new_confidence"] == 0.8

    def test_emits_belief_weakened(self):
        aggregator = MagicMock()
        aggregator.revise_beliefs.return_value = [("e1", 0.8, 0.5)]
        handler, _, bus = _make_handler(evidence_aggregator=aggregator)

        events = []
        bus.subscribe(EventType.BELIEF_WEAKENED, lambda e: events.append(e))

        handler._revise_beliefs()
        assert len(events) == 1
