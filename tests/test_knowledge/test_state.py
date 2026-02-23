"""Tests for KnowledgeState delta tracking."""

from __future__ import annotations

from unittest.mock import MagicMock

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.knowledge.state import KnowledgeState, ObservationOutcome
from basilisk.observations.observation import Observation
from basilisk.orchestrator.planner import KnowledgeGap, Planner


def _obs(
    host: str = "test.com",
    entity_type: EntityType = EntityType.SERVICE,
    port: int = 80,
    confidence: float = 0.8,
) -> Observation:
    return Observation(
        entity_type=entity_type,
        entity_data={"host": host, "port": port, "protocol": "tcp"},
        key_fields={"host": host, "port": str(port), "protocol": "tcp"},
        confidence=confidence,
        source_plugin="test",
    )


class TestObservationOutcome:
    def test_confidence_delta_positive(self):
        o = ObservationOutcome(
            entity_id="x", was_new=True,
            confidence_before=0.0, confidence_after=0.8,
        )
        assert o.confidence_delta == 0.8

    def test_confidence_delta_zero(self):
        o = ObservationOutcome(
            entity_id="x", was_new=False,
            confidence_before=1.0, confidence_after=1.0,
        )
        assert o.confidence_delta == 0.0


class TestKnowledgeStateApply:
    def test_new_entity_returns_was_new(self):
        graph = KnowledgeGraph()
        state = KnowledgeState(graph)
        outcome = state.apply_observation(_obs())
        assert outcome.was_new is True
        assert outcome.confidence_before == 0.0
        assert outcome.confidence_after == 0.8

    def test_duplicate_entity_merges_confidence(self):
        graph = KnowledgeGraph()
        state = KnowledgeState(graph)

        outcome1 = state.apply_observation(_obs(confidence=0.6))
        assert outcome1.was_new is True

        outcome2 = state.apply_observation(_obs(confidence=0.6))
        assert outcome2.was_new is False
        assert outcome2.confidence_before == 0.6
        # Probabilistic OR: 1 - (1-0.6)*(1-0.6) = 0.84
        assert abs(outcome2.confidence_after - 0.84) < 0.01
        assert outcome2.confidence_delta > 0

    def test_graph_entity_count_increases(self):
        graph = KnowledgeGraph()
        state = KnowledgeState(graph)
        state.apply_observation(_obs(host="a.com", port=80))
        state.apply_observation(_obs(host="a.com", port=443))
        assert graph.entity_count == 2

    def test_same_entity_no_duplicate(self):
        graph = KnowledgeGraph()
        state = KnowledgeState(graph)
        state.apply_observation(_obs())
        state.apply_observation(_obs())
        assert graph.entity_count == 1

    def test_relation_applied(self):
        graph = KnowledgeGraph()
        host = Entity.host("rel.com")
        graph.add_entity(host)
        state = KnowledgeState(graph)

        svc_id = Entity.make_id(EntityType.SERVICE, host="rel.com", port="80", protocol="tcp")
        obs = Observation(
            entity_type=EntityType.SERVICE,
            entity_data={"host": "rel.com", "port": 80, "protocol": "tcp"},
            key_fields={"host": "rel.com", "port": "80", "protocol": "tcp"},
            relation=Relation(
                source_id=host.id, target_id=svc_id, type=RelationType.EXPOSES,
            ),
            source_plugin="test",
        )
        state.apply_observation(obs)
        assert graph.relation_count == 1


class TestKnowledgeStateSnapshot:
    def test_snapshot_values(self):
        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("a.com"))
        graph.add_entity(Entity.host("b.com"))
        graph.add_entity(Entity.service("a.com", 80))

        state = KnowledgeState(graph)
        snap = state.snapshot(step=3, elapsed=12.5, gap_count=2)

        assert snap.entity_count == 3
        assert snap.host_count == 2
        assert snap.service_count == 1
        assert snap.step == 3
        assert snap.elapsed_seconds == 12.5
        assert snap.gap_count == 2

    def test_snapshot_deterministic(self):
        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("det.com"))
        state = KnowledgeState(graph)

        s1 = state.snapshot(1, 5.0, 0)
        s2 = state.snapshot(1, 5.0, 0)
        assert s1 == s2


class TestKnowledgeStateFindGaps:
    def test_delegates_to_planner(self):
        graph = KnowledgeGraph()
        planner = MagicMock(spec=Planner)
        host = Entity.host("gap.com")
        gap = KnowledgeGap(entity=host, missing="services", priority=10.0, description="test")
        planner.find_gaps.return_value = [gap]

        state = KnowledgeState(graph, planner=planner)
        gaps = state.find_gaps()
        assert len(gaps) == 1
        assert gaps[0].missing == "services"
        planner.find_gaps.assert_called_once_with(graph)

    def test_without_planner_uses_graph(self):
        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("noplanner.com"))
        state = KnowledgeState(graph)
        # Should not raise — delegates to graph.find_missing_knowledge()
        gaps = state.find_gaps()
        assert isinstance(gaps, list)
