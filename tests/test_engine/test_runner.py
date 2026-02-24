"""Tests for RunResult model and AutonomousRunner wiring."""

from __future__ import annotations

from unittest.mock import MagicMock

from basilisk.domain.finding import Finding
from basilisk.engine.autonomous.runner import AutonomousRunner, RunResult


class TestRunResult:
    def test_basic_construction(self):
        r = RunResult(
            findings=[Finding.info("Test")],
            steps=10,
            duration=42.0,
            termination_reason="no_gaps",
        )
        assert len(r.findings) == 1
        assert r.steps == 10
        assert r.termination_reason == "no_gaps"

    def test_defaults(self):
        r = RunResult()
        assert r.findings == []
        assert r.steps == 0
        assert r.graph_data is None

    def test_with_graph_data(self):
        r = RunResult(graph_data={"entity_count": 50, "relation_count": 30})
        assert r.graph_data["entity_count"] == 50


class TestAutonomousRunnerParams:
    """Verify AutonomousRunner stores all wiring params."""

    def _make_runner(self, **kwargs):
        settings = MagicMock()
        return AutonomousRunner(settings=settings, **kwargs)

    def test_plugin_filter_stored(self):
        runner = self._make_runner(plugin_filter=["sqli_*"])
        assert runner._plugin_filter == ["sqli_*"]

    def test_exclude_patterns_stored(self):
        runner = self._make_runner(exclude_patterns=["heavy_*"])
        assert runner._exclude_patterns == ["heavy_*"]

    def test_callbacks_stored(self):
        def cb_finding(_f):
            pass

        def cb_step(_s):
            pass

        runner = self._make_runner(on_finding=cb_finding, on_step=cb_step)
        assert runner._on_finding is cb_finding
        assert runner._on_step is cb_step

    def test_defaults_empty(self):
        runner = self._make_runner()
        assert runner._plugin_filter is None
        assert runner._exclude_patterns is None
        assert runner._on_finding is None
        assert runner._on_step is None

    def test_campaign_enabled_stored(self):
        runner = self._make_runner(campaign_enabled=True)
        assert runner._campaign_enabled is True

    def test_campaign_disabled_default(self):
        runner = self._make_runner()
        assert runner._campaign_enabled is False
