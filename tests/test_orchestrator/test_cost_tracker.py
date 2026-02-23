"""Tests for capability cost learning."""

from __future__ import annotations

from basilisk.orchestrator.cost_tracker import CostTracker, PluginStats


class TestPluginStats:
    def test_defaults(self):
        stats = PluginStats()
        assert stats.runs == 0
        assert stats.success_rate == 0.0
        assert stats.avg_new_entities == 0.0
        assert stats.avg_runtime == 0.0
        assert stats.avg_findings == 0.0

    def test_success_rate(self):
        stats = PluginStats(runs=4, successes=3)
        assert stats.success_rate == 0.75

    def test_averages(self):
        stats = PluginStats(
            runs=2, total_new_entities=6, total_findings=4, total_runtime=10.0,
        )
        assert stats.avg_new_entities == 3.0
        assert stats.avg_findings == 2.0
        assert stats.avg_runtime == 5.0


class TestCostTracker:
    def test_no_history_returns_base(self):
        tracker = CostTracker()
        assert tracker.adjusted_cost("unknown", 5.0) == 5.0

    def test_single_run_returns_base(self):
        tracker = CostTracker()
        tracker.record("plugin_a", new_entities=1, findings=0, runtime=1.0)
        # Only 1 run, need at least 2 for adjustment
        assert tracker.adjusted_cost("plugin_a", 5.0) == 5.0

    def test_all_successful_gives_discount(self):
        tracker = CostTracker()
        for _ in range(5):
            tracker.record("good_plugin", new_entities=3, findings=1, runtime=1.0)
        adjusted = tracker.adjusted_cost("good_plugin", 5.0)
        assert adjusted < 5.0  # discount applied

    def test_all_failed_gives_penalty(self):
        tracker = CostTracker()
        for _ in range(5):
            tracker.record("bad_plugin", new_entities=0, findings=0, runtime=1.0)
        adjusted = tracker.adjusted_cost("bad_plugin", 5.0)
        assert adjusted > 5.0  # penalty applied

    def test_mixed_results_moderate(self):
        tracker = CostTracker()
        tracker.record("mixed", new_entities=2, findings=1, runtime=1.0)
        tracker.record("mixed", new_entities=0, findings=0, runtime=1.0)
        adjusted = tracker.adjusted_cost("mixed", 5.0)
        # 50% success → multiplier = 2.0 - 1.3 * 0.5 = 1.35
        assert 5.0 < adjusted < 10.0

    def test_get_stats(self):
        tracker = CostTracker()
        assert tracker.get_stats("unknown") is None
        tracker.record("test", new_entities=1, findings=0, runtime=2.0)
        stats = tracker.get_stats("test")
        assert stats is not None
        assert stats.runs == 1
        assert stats.total_runtime == 2.0

    def test_all_stats(self):
        tracker = CostTracker()
        tracker.record("a", new_entities=1, findings=0, runtime=1.0)
        tracker.record("b", new_entities=0, findings=1, runtime=2.0)
        assert len(tracker.all_stats) == 2
        assert "a" in tracker.all_stats
        assert "b" in tracker.all_stats

    def test_adjusted_cost_floor(self):
        tracker = CostTracker()
        for _ in range(10):
            tracker.record("super_good", new_entities=10, findings=5, runtime=0.5)
        adjusted = tracker.adjusted_cost("super_good", 2.0)
        # Should not go below 0.5x floor
        assert adjusted >= 1.0
