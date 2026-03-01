"""Tests for DisplayState."""

from __future__ import annotations

import time

from basilisk.display.state import DisplayState, FindingEntry


class TestDisplayState:
    """Test DisplayState properties and calculations."""

    def test_default_state(self):
        state = DisplayState()
        assert state.step == 0
        assert state.max_steps == 100
        assert state.total_entities == 0
        assert state.total_findings == 0
        assert state.gap_count == 0
        assert state.finished is False

    def test_elapsed(self):
        state = DisplayState(started_at=time.monotonic() - 5.0)
        assert state.elapsed >= 5.0

    def test_step_progress(self):
        state = DisplayState(step=25, max_steps=100)
        assert state.step_progress == 0.25

    def test_step_progress_zero_max(self):
        state = DisplayState(step=0, max_steps=0)
        assert state.step_progress == 0.0

    def test_step_progress_clamped(self):
        state = DisplayState(step=150, max_steps=100)
        assert state.step_progress == 1.0

    def test_severity_counts_empty(self):
        state = DisplayState()
        assert state.severity_counts == {}

    def test_severity_counts(self):
        state = DisplayState(findings=[
            FindingEntry(title="a", severity="high", host="x"),
            FindingEntry(title="b", severity="medium", host="y"),
            FindingEntry(title="c", severity="high", host="z"),
            FindingEntry(title="d", severity="info", host="x"),
        ])
        counts = state.severity_counts
        assert counts["HIGH"] == 2
        assert counts["MEDIUM"] == 1
        assert counts["INFO"] == 1

    def test_total_findings(self):
        state = DisplayState(findings=[
            FindingEntry(title="a", severity="high", host="x"),
            FindingEntry(title="b", severity="low", host="y"),
        ])
        assert state.total_findings == 2

    def test_entity_counts_default(self):
        state = DisplayState()
        assert state.entity_counts["host"] == 0
        assert state.entity_counts["service"] == 0
        assert state.entity_counts["finding"] == 0
