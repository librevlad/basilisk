"""Tests for new Decision fields — hypothesis_text, expected/observed entity types."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

from basilisk.decisions.decision import Decision
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.observations.observation import Observation
from basilisk.orchestrator.observation_processor import ObservationProcessor
from basilisk.reporting.builder import ReportBuilder


class TestHypothesisText:
    """hypothesis_text field stores the primary hypothesis being tested."""

    def test_hypothesis_text_default(self):
        d = Decision(id="ht1")
        assert d.hypothesis_text == ""

    def test_hypothesis_text_populated(self):
        d = Decision(
            id="ht2",
            hypothesis_text="Service likely runs Apache with known CVEs",
        )
        assert d.hypothesis_text == "Service likely runs Apache with known CVEs"


class TestExpectedEntityTypes:
    """expected_entity_types stores types from capability.produces_knowledge."""

    def test_expected_entity_types_default(self):
        d = Decision(id="eet1")
        assert d.expected_entity_types == []

    def test_expected_entity_types_from_capability(self):
        d = Decision(
            id="eet2",
            expected_entity_types=["service", "technology"],
        )
        assert d.expected_entity_types == ["service", "technology"]


class TestObservedEntityTypes:
    """observed_entity_types is filled after execution by ObservationProcessor."""

    def test_observed_entity_types_default(self):
        d = Decision(id="oet1")
        assert d.observed_entity_types == []

    def test_observed_entity_types_after_execution(self):
        """ObservationProcessor populates observed_entity_types from observations."""
        state = MagicMock()
        state.apply_observation.return_value = SimpleNamespace(
            entity_id="e1", was_new=True, confidence_delta=0.1,
        )
        bus = MagicMock()

        processor = ObservationProcessor(state=state, bus=bus)

        obs1 = Observation(
            entity_type=EntityType.SERVICE,
            key_fields={"host": "a.com", "port": "80", "protocol": "tcp"},
            entity_data={"port": 80, "service": "http"},
            source_plugin="port_scan",
        )
        obs2 = Observation(
            entity_type=EntityType.TECHNOLOGY,
            key_fields={"host": "a.com", "name": "nginx"},
            entity_data={"name": "nginx", "version": "1.25"},
            source_plugin="tech_fingerprint",
        )

        decision = Decision(id="oet_test", step=1)
        processor.process_batch([[obs1, obs2]], [decision], step=1)

        assert sorted(decision.observed_entity_types) == ["service", "technology"]


class TestDecisionSerialization:
    """Builder serialization includes all 3 new fields."""

    def test_decision_serialization_includes_new_fields(self):
        from basilisk.core.session import ScanSession

        s = ScanSession("test.example.com", max_steps=10)
        g = s.graph
        host = Entity.host("test.example.com")
        g.add_entity(host)

        ts = datetime(2026, 3, 1, tzinfo=UTC)
        d = Decision(
            id=Decision.make_id(1, ts, "port_scan", "test.example.com"),
            timestamp=ts,
            step=1,
            goal="services",
            goal_description="Host needs port scan",
            goal_priority=10.0,
            chosen_plugin="port_scan",
            chosen_target="test.example.com",
            chosen_score=0.95,
            reasoning_trace="Gap: Host needs port scan.",
            hypothesis_text="Target likely exposes HTTP service",
            expected_entity_types=["SERVICE", "ENDPOINT"],
            observed_entity_types=["SERVICE"],
            outcome_observations=5,
            outcome_new_entities=2,
            was_productive=True,
        )
        s.full_decisions = [d]

        model = ReportBuilder.from_session(s)
        assert len(model.decisions) == 1
        dec = model.decisions[0]
        assert dec["hypothesis_text"] == "Target likely exposes HTTP service"
        assert dec["expected_entity_types"] == ["SERVICE", "ENDPOINT"]
        assert dec["observed_entity_types"] == ["SERVICE"]
