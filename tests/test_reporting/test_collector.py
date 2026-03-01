"""Tests for ReportCollector — event-driven state accumulation."""

from __future__ import annotations

from basilisk.events.bus import Event, EventBus, EventType
from basilisk.reporting.collector import ReportCollector


class TestReportCollectorEvents:
    """Test that events correctly mutate ReportCollector state."""

    def _make(self, max_steps: int = 100) -> tuple[EventBus, ReportCollector]:
        bus = EventBus()
        collector = ReportCollector(target="test.com", max_steps=max_steps)
        collector.subscribe(bus)
        return bus, collector

    def test_gap_detected(self):
        bus, c = self._make()
        bus.emit(Event(EventType.GAP_DETECTED, {"count": 7, "step": 1}))
        assert c.gap_count == 7

    def test_plugin_started_and_finished(self):
        bus, c = self._make()
        bus.emit(Event(EventType.PLUGIN_STARTED, {
            "plugin": "port_scan", "target": "10.0.0.1", "step": 1,
        }))
        assert len(c._active_plugins) == 1

        bus.emit(Event(EventType.PLUGIN_FINISHED, {
            "plugin": "port_scan", "target": "10.0.0.1",
            "step": 1, "duration": 2.5, "findings_count": 3,
        }))
        assert len(c._active_plugins) == 0
        assert len(c.plugins) == 1
        assert c.plugins[0].name == "port_scan"
        assert c.plugins[0].duration == 2.5
        assert c.plugins[0].findings_count == 3

    def test_plugin_finished_without_started(self):
        bus, c = self._make()
        bus.emit(Event(EventType.PLUGIN_FINISHED, {
            "plugin": "ssl_check", "target": "x", "step": 1,
            "duration": 1.0, "findings_count": 0,
        }))
        assert len(c.plugins) == 1

    def test_step_completed(self):
        bus, c = self._make()
        bus.emit(Event(EventType.STEP_COMPLETED, {
            "step": 3, "entities": 20, "relations": 10,
        }))
        assert c.step == 3
        assert c.total_entities == 20
        assert c.total_relations == 10
        assert len(c.step_history) == 1
        assert c.step_history[0].entities_gained == 20

    def test_step_completed_entities_gained(self):
        bus, c = self._make()
        bus.emit(Event(EventType.STEP_COMPLETED, {
            "step": 1, "entities": 10, "relations": 5,
        }))
        bus.emit(Event(EventType.STEP_COMPLETED, {
            "step": 2, "entities": 18, "relations": 9,
        }))
        assert c.step_history[0].entities_gained == 10
        assert c.step_history[1].entities_gained == 8

    def test_entity_created_finding(self):
        bus, c = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_id": "f1", "entity_type": "finding",
            "title": "SQL Injection", "severity": "high",
            "host": "10.0.0.1", "evidence": "1=1 returned data",
            "tags": ["sqli"], "confidence": 0.9, "step": 2,
        }))
        assert c.entity_counts["finding"] == 1
        assert len(c.findings) == 1
        assert c.findings[0].title == "SQL Injection"
        assert c.findings[0].severity == "high"
        assert c.findings[0].evidence == "1=1 returned data"
        assert c.findings[0].confidence == 0.9

    def test_entity_created_service(self):
        bus, c = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_id": "s1", "entity_type": "service",
        }))
        assert c.entity_counts["service"] == 1
        assert len(c.findings) == 0

    def test_entity_updated_noop(self):
        bus, c = self._make()
        bus.emit(Event(EventType.ENTITY_UPDATED, {"entity_id": "x"}))
        assert c.total_entities == 0

    def test_decision_made(self):
        bus, c = self._make()
        bus.emit(Event(EventType.DECISION_MADE, {
            "decision_id": "d1", "plugin": "sqli_basic",
            "target": "10.0.0.1", "step": 5,
            "score": 0.87, "reasoning": "high priority gap",
        }))
        assert len(c.decisions) == 1
        assert c.decisions[0].plugin == "sqli_basic"
        assert c.decisions[0].score == 0.87
        assert c.decisions[0].reasoning == "high priority gap"

    def test_finding_verified(self):
        bus, c = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_id": "f1", "entity_type": "finding",
            "title": "XSS", "severity": "medium", "host": "x",
        }))
        assert c.findings[0].verified is False
        bus.emit(Event(EventType.FINDING_VERIFIED, {"title": "XSS"}))
        assert c.findings[0].verified is True

    def test_finding_verified_unknown_title(self):
        bus, c = self._make()
        bus.emit(Event(EventType.FINDING_VERIFIED, {"title": "nonexistent"}))
        assert len(c.findings) == 0

    def test_belief_strengthened(self):
        bus, c = self._make()
        bus.emit(Event(EventType.BELIEF_STRENGTHENED, {
            "entity_id": "x", "old_confidence": 0.5, "new_confidence": 0.8,
        }))
        assert c.beliefs_strengthened == 1
        assert len(c.reasoning_events) == 1
        assert c.reasoning_events[0].event_type == "belief_strengthened"

    def test_belief_weakened(self):
        bus, c = self._make()
        bus.emit(Event(EventType.BELIEF_WEAKENED, {
            "entity_id": "x", "old_confidence": 0.8, "new_confidence": 0.5,
        }))
        assert c.beliefs_weakened == 1

    def test_hypothesis_confirmed(self):
        bus, c = self._make()
        c.hypotheses_active = 2
        bus.emit(Event(EventType.HYPOTHESIS_CONFIRMED, {
            "hypothesis_id": "h1", "statement": "test",
        }))
        assert c.hypotheses_confirmed == 1
        assert c.hypotheses_active == 1
        assert len(c.reasoning_events) == 1

    def test_hypothesis_rejected(self):
        bus, c = self._make()
        c.hypotheses_active = 1
        bus.emit(Event(EventType.HYPOTHESIS_REJECTED, {
            "hypothesis_id": "h2", "statement": "test",
        }))
        assert c.hypotheses_rejected == 1
        assert c.hypotheses_active == 0

    def test_hypothesis_active_never_negative(self):
        bus, c = self._make()
        bus.emit(Event(EventType.HYPOTHESIS_CONFIRMED, {
            "hypothesis_id": "h1", "statement": "test",
        }))
        assert c.hypotheses_active == 0


class TestReportCollectorProperties:
    """Test computed properties."""

    def test_severity_counts(self):
        c = ReportCollector()
        from basilisk.reporting.collector import ReportFinding

        c.findings = [
            ReportFinding(title="a", severity="high", host="x"),
            ReportFinding(title="b", severity="critical", host="x"),
            ReportFinding(title="c", severity="high", host="y"),
        ]
        assert c.severity_counts == {"HIGH": 2, "CRITICAL": 1}

    def test_risk_score(self):
        c = ReportCollector()
        from basilisk.reporting.collector import ReportFinding

        c.findings = [
            ReportFinding(title="a", severity="critical", host="x"),
            ReportFinding(title="b", severity="high", host="y"),
        ]
        # critical=4.0 + high=2.5 = 6.5
        assert c.risk_score == 6.5

    def test_risk_score_capped(self):
        c = ReportCollector()
        from basilisk.reporting.collector import ReportFinding

        c.findings = [
            ReportFinding(title=f"f{i}", severity="critical", host="x")
            for i in range(10)
        ]
        assert c.risk_score == 10.0

    def test_elapsed(self):
        import time

        c = ReportCollector(started_at=time.monotonic() - 5.0)
        assert c.elapsed >= 5.0

    def test_finalize(self):
        c = ReportCollector()
        c.finalize("no_gaps")
        assert c.status == "completed"
        assert c.termination_reason == "no_gaps"

    def test_finalize_training(self):
        from unittest.mock import MagicMock

        c = ReportCollector()

        report = MagicMock()
        report.profile_name = "test_profile"
        report.coverage = 0.85
        report.verification_rate = 0.7
        report.passed = True

        tracker = MagicMock()
        tf1 = MagicMock()
        tf1.expected.title = "SQLi"
        tf1.expected.severity = "high"
        tf1.discovered = True
        tf1.verified = True
        tf1.discovery_step = 3
        tracker.tracked = [tf1]

        c.finalize_training(report, tracker)
        assert c.status == "completed"
        assert c.mode == "train"
        assert c.training is not None
        assert c.training["profile_name"] == "test_profile"
        assert c.training["coverage"] == 0.85
        assert len(c.training["expected_findings"]) == 1
        assert c.training["expected_findings"][0]["title"] == "SQLi"
