"""Tests for the observation processor."""

from __future__ import annotations

from unittest.mock import MagicMock

from basilisk.decisions.decision import Decision
from basilisk.events.bus import EventBus, EventType
from basilisk.knowledge.entities import EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.state import KnowledgeState
from basilisk.observations.observation import Observation
from basilisk.orchestrator.observation_processor import ObservationProcessor
from basilisk.orchestrator.planner import Planner


def _make_processor() -> tuple[ObservationProcessor, EventBus, KnowledgeGraph]:
    graph = KnowledgeGraph()
    planner = MagicMock(spec=Planner)
    planner.find_gaps.return_value = []
    state = KnowledgeState(graph, planner)
    bus = EventBus()
    processor = ObservationProcessor(state=state, bus=bus)
    return processor, bus, graph


def _make_obs(entity_type=EntityType.HOST, host="test.com"):
    return Observation(
        entity_type=entity_type,
        key_fields={"host": host},
        entity_data={"host": host},
        confidence=0.9,
        source_plugin="test_plugin",
    )


def _make_decision(step=1):
    from datetime import UTC, datetime
    now = datetime.now(UTC)
    return Decision(
        id="test-decision-1",
        timestamp=now,
        step=step,
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


class TestObservationProcessor:
    def test_empty_results(self):
        processor, _, _ = _make_processor()
        count = processor.process_batch([], [], step=1)
        assert count == 0

    def test_processes_observations(self):
        processor, bus, graph = _make_processor()
        obs = _make_obs()
        decision = _make_decision()
        decision.outcome_duration = 0.5

        events = []
        bus.subscribe(EventType.ENTITY_CREATED, lambda e: events.append(e))

        count = processor.process_batch([[obs]], [decision], step=1)
        assert count == 1
        assert len(events) == 1
        assert decision.outcome_observations == 1
        assert decision.outcome_new_entities == 1

    def test_skips_exceptions(self):
        processor, _, _ = _make_processor()
        count = processor.process_batch(
            [RuntimeError("fail")], [_make_decision()], step=1,
        )
        assert count == 0

    def test_enriches_finding_events(self):
        processor, bus, _ = _make_processor()
        finding_obs = Observation(
            entity_type=EntityType.FINDING,
            key_fields={"host": "test.com", "title": "XSS"},
            entity_data={
                "host": "test.com", "title": "XSS", "severity": "high",
                "description": "found xss", "evidence": "proof",
            },
            confidence=0.9,
            source_plugin="xss_basic",
        )
        decision = _make_decision()
        decision.outcome_duration = 0.1

        events = []
        bus.subscribe(EventType.ENTITY_CREATED, lambda e: events.append(e))

        processor.process_batch([[finding_obs]], [decision], step=1)
        assert len(events) == 1
        assert events[0].data["title"] == "XSS"
        assert events[0].data["severity"] == "high"

    def test_enriches_service_events(self):
        processor, bus, _ = _make_processor()
        svc_obs = Observation(
            entity_type=EntityType.SERVICE,
            key_fields={"host": "test.com", "port": "443", "protocol": "tcp"},
            entity_data={"host": "test.com", "port": 443, "service": "https"},
            confidence=0.9,
            source_plugin="port_scan",
        )
        decision = _make_decision()
        decision.outcome_duration = 0.1

        events = []
        bus.subscribe(EventType.ENTITY_CREATED, lambda e: events.append(e))

        processor.process_batch([[svc_obs]], [decision], step=1)
        assert len(events) == 1
        assert events[0].data["port"] == 443

    def test_updates_decision_productivity(self):
        processor, _, _ = _make_processor()
        obs = _make_obs()
        decision = _make_decision()
        decision.outcome_duration = 0.5

        processor.process_batch([[obs]], [decision], step=1)
        assert decision.was_productive is True
        assert decision.outcome_new_entities == 1

    def test_emits_decision_outcome(self):
        processor, bus, _ = _make_processor()
        obs = _make_obs()
        decision = _make_decision()
        decision.outcome_duration = 0.5

        events = []
        bus.subscribe(EventType.DECISION_OUTCOME, lambda e: events.append(e))

        processor.process_batch([[obs]], [decision], step=1)
        assert len(events) == 1
        assert events[0].data["decision_id"] == "test-decision-1"
