"""Tests for ScanSession — coordination layer for audit execution."""

from __future__ import annotations

import time

from basilisk.core.session import ScanSession, SessionEventType
from basilisk.events.bus import Event, EventBus, EventType
from basilisk.knowledge.graph import KnowledgeGraph


class TestScanSessionInit:
    """Test ScanSession initialization."""

    def test_defaults(self):
        s = ScanSession("example.com")
        assert s.target == "example.com"
        assert s.mode == "auto"
        assert s.max_steps == 100
        assert s.status == "running"
        assert s.step == 0
        assert s.gap_count == 0
        assert isinstance(s.graph, KnowledgeGraph)
        assert isinstance(s.bus, EventBus)
        assert s.timeline_events == []
        assert s.decisions == []
        assert s.plugins == []
        assert s.step_history == []
        assert s.reasoning_events == []
        assert s.training_data is None

    def test_custom_graph_and_bus(self):
        graph = KnowledgeGraph()
        bus = EventBus()
        s = ScanSession("example.com", graph=graph, bus=bus)
        assert s.graph is graph
        assert s.bus is bus

    def test_scan_id_deterministic(self):
        id1 = ScanSession._make_scan_id("example.com", 12345.0)
        id2 = ScanSession._make_scan_id("example.com", 12345.0)
        assert id1 == id2
        assert len(id1) == 16

    def test_scan_id_different_inputs(self):
        id1 = ScanSession._make_scan_id("a.com", 1.0)
        id2 = ScanSession._make_scan_id("b.com", 1.0)
        assert id1 != id2

    def test_elapsed(self):
        s = ScanSession("example.com")
        assert s.elapsed >= 0.0
        time.sleep(0.01)
        assert s.elapsed > 0.0

    def test_started_at(self):
        s = ScanSession("example.com")
        assert s.started_at is not None


class TestScanSessionFinalize:
    """Test finalize methods."""

    def test_finalize(self):
        s = ScanSession("example.com")
        s.finalize("no_gaps")
        assert s.status == "completed"
        assert s.termination_reason == "no_gaps"

    def test_finalize_training(self):
        from unittest.mock import MagicMock

        s = ScanSession("example.com")
        report = MagicMock()
        report.profile_name = "dvwa"
        report.coverage = 0.85
        report.verification_rate = 0.7
        report.passed = True

        tf = MagicMock()
        tf.expected.title = "SQL Injection"
        tf.expected.severity = "high"
        tf.discovered = True
        tf.verified = True
        tf.discovery_step = 3
        tracker = MagicMock()
        tracker.tracked = [tf]

        s.finalize_training(report, tracker)
        assert s.status == "completed"
        assert s.termination_reason == "training_complete"
        assert s.mode == "train"
        assert s.training_data is not None
        assert s.training_data["profile_name"] == "dvwa"
        assert s.training_data["passed"] is True
        assert len(s.training_data["expected_findings"]) == 1


class TestScanSessionEvents:
    """Test event handling."""

    def _make(self) -> ScanSession:
        return ScanSession("test.com")

    def test_gap_detected(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.GAP_DETECTED, data={"count": 5}))
        assert s.gap_count == 5

    def test_plugin_started_and_finished(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.PLUGIN_STARTED, data={
            "plugin": "port_scan", "target": "test.com", "step": 1,
        }))
        assert len(s.timeline_events) == 1
        assert s.timeline_events[0].event_type == SessionEventType.SCENARIO_STARTED

        s.bus.emit(Event(type=EventType.PLUGIN_FINISHED, data={
            "plugin": "port_scan", "target": "test.com", "step": 1,
            "duration": 2.5, "findings_count": 3,
        }))
        assert len(s.plugins) == 1
        assert s.plugins[0].name == "port_scan"
        assert s.plugins[0].findings_count == 3
        assert len(s.timeline_events) == 2
        assert s.timeline_events[1].event_type == SessionEventType.SCENARIO_FINISHED

    def test_plugin_failed(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.PLUGIN_FINISHED, data={
            "plugin": "broken", "target": "test.com", "step": 1,
            "findings_count": -1,
        }))
        assert s.timeline_events[0].event_type == SessionEventType.SCENARIO_FAILED

    def test_step_completed(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.STEP_COMPLETED, data={
            "step": 1, "entities": 10, "relations": 5,
        }))
        assert s.step == 1
        assert len(s.step_history) == 1
        assert s.step_history[0].entities == 10
        assert s.step_history[0].entities_gained == 10

        s.bus.emit(Event(type=EventType.STEP_COMPLETED, data={
            "step": 2, "entities": 15, "relations": 8,
        }))
        assert s.step == 2
        assert s.step_history[1].entities_gained == 5

    def test_entity_created_finding(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.ENTITY_CREATED, data={
            "entity_type": "finding", "title": "SQL Injection", "severity": "high",
        }))
        assert len(s.timeline_events) == 1
        assert s.timeline_events[0].event_type == SessionEventType.FINDING_CREATED
        assert s.timeline_events[0].data["title"] == "SQL Injection"

    def test_entity_created_surface(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.ENTITY_CREATED, data={
            "entity_type": "service", "host": "test.com",
        }))
        assert len(s.timeline_events) == 1
        assert s.timeline_events[0].event_type == SessionEventType.SURFACE_DISCOVERED

    def test_entity_created_host_no_timeline(self):
        """Host creation doesn't generate timeline event (only service/endpoint/tech)."""
        s = self._make()
        s.bus.emit(Event(type=EventType.ENTITY_CREATED, data={
            "entity_type": "host", "host": "test.com",
        }))
        assert len(s.timeline_events) == 0

    def test_decision_made(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.DECISION_MADE, data={
            "step": 1, "plugin": "port_scan", "target": "test.com",
            "score": 0.95, "reasoning": "initial",
        }))
        assert len(s.decisions) == 1
        assert s.decisions[0].plugin == "port_scan"
        assert s.decisions[0].score == 0.95

    def test_decision_outcome(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.DECISION_MADE, data={
            "step": 1, "plugin": "port_scan", "target": "test.com", "score": 0.9,
        }))
        s.bus.emit(Event(type=EventType.DECISION_OUTCOME, data={
            "step": 1, "plugin": "port_scan",
            "was_productive": True, "duration": 2.0, "new_entities": 5,
        }))
        assert s.decisions[0].productive is True
        assert s.decisions[0].duration == 2.0
        assert s.decisions[0].new_entities == 5

    def test_finding_verified(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.FINDING_VERIFIED, data={
            "title": "SQL Injection",
        }))
        assert len(s.timeline_events) == 1
        assert s.timeline_events[0].event_type == SessionEventType.FINDING_CONFIRMED

    def test_hypothesis_confirmed(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.HYPOTHESIS_CONFIRMED, data={"id": "h1"}))
        assert s.hypotheses_confirmed == 1
        assert len(s.reasoning_events) == 1
        assert s.reasoning_events[0].event_type == "hypothesis_confirmed"

    def test_hypothesis_rejected(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.HYPOTHESIS_REJECTED, data={"id": "h2"}))
        assert s.hypotheses_rejected == 1
        assert len(s.reasoning_events) == 1

    def test_belief_strengthened(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.BELIEF_STRENGTHENED, data={"entity": "x"}))
        assert s.beliefs_strengthened == 1
        assert len(s.reasoning_events) == 1
        assert len(s.timeline_events) == 1
        assert s.timeline_events[0].event_type == SessionEventType.BELIEF_CHANGED

    def test_belief_weakened(self):
        s = self._make()
        s.bus.emit(Event(type=EventType.BELIEF_WEAKENED, data={"entity": "y"}))
        assert s.beliefs_weakened == 1

    def test_graph_is_source_of_truth(self):
        """Session does NOT duplicate entity data — graph is the source."""
        s = self._make()
        from basilisk.knowledge.entities import Entity

        s.graph.add_entity(Entity.host("test.com"))
        s.graph.add_entity(Entity.finding("test.com", "SQLi", severity="high"))

        # Session has no findings list — they live in the graph
        assert not hasattr(s, "findings") or getattr(s, "findings", None) is None
        assert len(s.graph.findings()) == 1
        assert len(s.graph.hosts()) == 1

    def test_full_decision_captured(self):
        """Full Decision objects are stored when present in event data."""
        from datetime import UTC, datetime

        from basilisk.decisions.decision import Decision

        s = self._make()
        d = Decision(
            id="abc123",
            step=1,
            chosen_plugin="port_scan",
            chosen_target="test.com",
            chosen_score=0.95,
            reasoning_trace="initial recon",
            timestamp=datetime.now(UTC),
        )
        s.bus.emit(Event(type=EventType.DECISION_MADE, data={
            "step": 1, "plugin": "port_scan", "target": "test.com",
            "score": 0.95, "reasoning": "initial recon",
            "full_decision": d,
        }))
        assert len(s.full_decisions) == 1
        assert s.full_decisions[0].id == "abc123"
        # Summary decision also stored
        assert len(s.decisions) == 1

    def test_full_decision_not_stored_when_absent(self):
        """Without full_decision in event, full_decisions list stays empty."""
        s = self._make()
        s.bus.emit(Event(type=EventType.DECISION_MADE, data={
            "step": 1, "plugin": "port_scan", "target": "test.com", "score": 0.9,
        }))
        assert len(s.full_decisions) == 0
        assert len(s.decisions) == 1


class TestScanSessionConvenience:
    """Test persist_graph() and build_report() convenience methods."""

    async def test_persist_graph(self, tmp_path):
        from basilisk.knowledge.entities import Entity

        s = ScanSession("test.com")
        s.graph.add_entity(Entity.host("test.com"))
        db_path = tmp_path / "test_kg.db"
        await s.persist_graph(db_path)
        assert db_path.exists()

    async def test_persist_graph_loads_back(self, tmp_path):
        import aiosqlite

        from basilisk.knowledge.entities import Entity
        from basilisk.knowledge.store import KnowledgeStore

        s = ScanSession("test.com")
        host = Entity.host("test.com")
        s.graph.add_entity(host)
        db_path = tmp_path / "test_kg.db"
        await s.persist_graph(db_path)

        async with aiosqlite.connect(str(db_path)) as db:
            store = KnowledgeStore(db)
            loaded = await store.load()
            assert loaded.entity_count >= 1

    def test_build_report_via_builder(self):
        from basilisk.reporting.builder import ReportBuilder
        from basilisk.reporting.model import ReportModel

        s = ScanSession("test.com")
        report = ReportBuilder.from_session(s)
        assert isinstance(report, ReportModel)
        assert report.target == "test.com"

    def test_build_report_has_findings(self):
        from basilisk.knowledge.entities import Entity
        from basilisk.reporting.builder import ReportBuilder

        s = ScanSession("test.com")
        s.graph.add_entity(Entity.host("test.com"))
        s.graph.add_entity(Entity.finding("test.com", "XSS", severity="high"))
        report = ReportBuilder.from_session(s)
        assert len(report.findings_raw) == 1
        assert report.findings_raw[0]["severity"] == "HIGH"
