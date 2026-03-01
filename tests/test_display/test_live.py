"""Tests for LiveDisplay — event-driven state mutations (headless, no Live context)."""

from __future__ import annotations

from basilisk.display.live import LiveDisplay
from basilisk.events.bus import Event, EventBus, EventType


class TestLiveDisplayEvents:
    """Test that events correctly mutate DisplayState."""

    def _make_display(self, max_steps: int = 100) -> tuple[EventBus, LiveDisplay]:
        bus = EventBus()
        display = LiveDisplay(bus, max_steps=max_steps)
        return bus, display

    def test_gap_detected(self):
        bus, display = self._make_display()
        bus.emit(Event(EventType.GAP_DETECTED, {"count": 12, "step": 1}))
        assert display.state.gap_count == 12

    def test_plugin_started(self):
        bus, display = self._make_display()
        bus.emit(Event(EventType.PLUGIN_STARTED, {
            "plugin": "sqli_basic", "target": "10.10.10.5", "step": 1,
        }))
        assert len(display.state.active_plugins) == 1
        assert display.state.active_plugins[0].name == "sqli_basic"
        assert display.state.active_plugins[0].target == "10.10.10.5"

    def test_plugin_finished_moves_to_recent(self):
        bus, display = self._make_display()
        bus.emit(Event(EventType.PLUGIN_STARTED, {
            "plugin": "sqli_basic", "target": "10.10.10.5", "step": 1,
        }))
        bus.emit(Event(EventType.PLUGIN_FINISHED, {
            "plugin": "sqli_basic", "target": "10.10.10.5",
            "duration": 1.5, "step": 1, "findings_count": 2,
        }))
        assert len(display.state.active_plugins) == 0
        assert len(display.state.recent_plugins) == 1
        assert display.state.recent_plugins[0].duration == 1.5
        assert display.state.recent_plugins[0].findings_count == 2

    def test_step_completed(self):
        bus, display = self._make_display()
        bus.emit(Event(EventType.STEP_COMPLETED, {
            "step": 5, "entities": 42, "relations": 15,
            "duration": 2.0, "observations": 10,
        }))
        assert display.state.step == 5
        assert display.state.total_entities == 42
        assert display.state.total_relations == 15

    def test_entity_created_increments_count(self):
        bus, display = self._make_display()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_id": "abc123", "entity_type": "service",
            "key_data": "host=x port=80", "confidence_delta": 0.0,
        }))
        assert display.state.entity_counts["service"] == 1

    def test_entity_created_finding_adds_to_list(self):
        bus, display = self._make_display()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_id": "f1", "entity_type": "finding",
            "title": "SQL Injection", "severity": "high", "host": "10.10.10.5",
            "key_data": "host=10.10.10.5", "confidence_delta": 0.0,
        }))
        assert display.state.entity_counts["finding"] == 1
        assert len(display.state.findings) == 1
        assert display.state.findings[0].title == "SQL Injection"
        assert display.state.findings[0].severity == "high"

    def test_belief_strengthened(self):
        bus, display = self._make_display()
        bus.emit(Event(EventType.BELIEF_STRENGTHENED, {
            "entity_id": "x", "old_confidence": 0.5, "new_confidence": 0.8,
        }))
        assert display.state.beliefs_strengthened == 1

    def test_belief_weakened(self):
        bus, display = self._make_display()
        bus.emit(Event(EventType.BELIEF_WEAKENED, {
            "entity_id": "x", "old_confidence": 0.8, "new_confidence": 0.5,
        }))
        assert display.state.beliefs_weakened == 1

    def test_hypothesis_confirmed(self):
        bus, display = self._make_display()
        bus.emit(Event(EventType.HYPOTHESIS_CONFIRMED, {
            "hypothesis_id": "h1", "statement": "test",
        }))
        assert display.state.hypotheses_confirmed == 1

    def test_hypothesis_rejected(self):
        bus, display = self._make_display()
        bus.emit(Event(EventType.HYPOTHESIS_REJECTED, {
            "hypothesis_id": "h2", "statement": "test",
        }))
        assert display.state.hypotheses_rejected == 1

    def test_recent_plugins_bounded(self):
        bus, display = self._make_display()
        for i in range(15):
            bus.emit(Event(EventType.PLUGIN_STARTED, {
                "plugin": f"plugin_{i}", "target": "x", "step": 1,
            }))
            bus.emit(Event(EventType.PLUGIN_FINISHED, {
                "plugin": f"plugin_{i}", "target": "x",
                "duration": 0.1, "step": 1, "findings_count": 0,
            }))
        assert len(display.state.recent_plugins) <= 10

    def test_stop_returns_state(self):
        bus, display = self._make_display()
        state = display.stop()
        assert state.finished is True
        assert state is display.state
