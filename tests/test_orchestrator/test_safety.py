"""Tests for safety limits."""

from __future__ import annotations

import time

from basilisk.orchestrator.safety import SafetyLimits


class TestSafetyLimits:
    def test_can_continue_within_limits(self):
        safety = SafetyLimits(max_steps=10)
        safety.start()
        assert safety.can_continue(1)
        assert safety.can_continue(10)

    def test_cannot_continue_past_max_steps(self):
        safety = SafetyLimits(max_steps=5)
        safety.start()
        assert not safety.can_continue(6)

    def test_cannot_continue_past_duration(self):
        safety = SafetyLimits(max_steps=100, max_duration_seconds=0.01)
        safety.start()
        time.sleep(0.02)
        assert not safety.can_continue(1)

    def test_elapsed_before_start(self):
        safety = SafetyLimits()
        assert safety.elapsed == 0.0

    def test_elapsed_after_start(self):
        safety = SafetyLimits()
        safety.start()
        time.sleep(0.01)
        assert safety.elapsed > 0
