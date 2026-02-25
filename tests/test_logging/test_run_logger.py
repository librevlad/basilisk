"""Tests for RunLogger — EventBus subscriber that writes logs."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from basilisk.events.bus import Event, EventBus, EventType
from basilisk.logging.run_logger import RunLogger


class TestRunLogger:
    async def test_creates_directory(self, tmp_path):
        log_dir = tmp_path / "logs"
        bus = EventBus()
        logger = RunLogger(log_dir, "example.com", bus)
        await logger.open()

        assert logger.run_dir.exists()
        assert logger.run_dir.parent == log_dir
        assert "example.com" in logger.run_dir.name
        await logger.close()

    async def test_subscribes_to_events(self, tmp_path):
        log_dir = tmp_path / "logs"
        bus = EventBus()
        rl = RunLogger(log_dir, "test.com", bus)
        await rl.open()

        # Emit some events
        bus.emit(Event(EventType.GAP_DETECTED, {"count": 5, "step": 1}))
        bus.emit(Event(EventType.DECISION_MADE, {
            "decision_id": "abc",
            "plugin": "port_scan",
            "target": "test.com",
            "step": 1,
            "score": 0.95,
            "reasoning": "Host needs services",
        }))
        bus.emit(Event(EventType.PLUGIN_STARTED, {
            "plugin": "port_scan",
            "target": "test.com",
            "step": 1,
        }))
        bus.emit(Event(EventType.PLUGIN_FINISHED, {
            "plugin": "port_scan",
            "target": "test.com",
            "duration": 2.5,
            "step": 1,
            "findings_count": 0,
        }))
        bus.emit(Event(EventType.STEP_COMPLETED, {
            "step": 1,
            "duration": 3.0,
            "entities_gained": 5,
            "batch_size": 1,
        }))

        # Allow async tasks to complete
        import asyncio
        await asyncio.sleep(0.1)
        await rl.close()

        # Check JSONL
        jsonl_path = rl.run_dir / "events.jsonl"
        assert jsonl_path.exists()
        lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 5
        first = json.loads(lines[0])
        assert first["event_type"] == "GAP_DETECTED"

        # Check run.log
        log_path = rl.run_dir / "run.log"
        assert log_path.exists()
        text = log_path.read_text(encoding="utf-8")
        assert "[GAPS]" in text
        assert "[DECISION]" in text
        assert "[PLUGIN]" in text
        assert "[STEP]" in text

    async def test_summary(self, tmp_path):
        log_dir = tmp_path / "logs"
        bus = EventBus()
        rl = RunLogger(log_dir, "target.com", bus)
        await rl.open()

        # Build mock timeline
        timeline = MagicMock()
        timeline.total_steps = 5
        timeline.entries = []
        timeline.summary.return_value = "  Step 1: port_scan -> target.com (1.2s) +3 entities"

        # Build mock history
        history = MagicMock()
        history.decisions = [MagicMock() for _ in range(5)]

        # Build mock graph
        graph = MagicMock()
        graph.entity_count = 20
        graph.hosts.return_value = [MagicMock()] * 3
        graph.services.return_value = [MagicMock()] * 5
        graph.endpoints.return_value = [MagicMock()] * 8
        finding = MagicMock()
        finding.data = {"severity": "high", "title": "XSS in /search", "severity_value": 3}
        finding.confidence = 0.88
        graph.findings.return_value = [finding]

        await rl.log_summary(
            timeline, history,
            termination_reason="no_gaps",
            graph=graph,
        )
        await rl.close()

        text = (rl.run_dir / "run.log").read_text(encoding="utf-8")
        assert "RUN SUMMARY" in text
        assert "target.com" in text
        assert "Steps:" in text
        assert "no_gaps" in text
        assert "TOP FINDINGS:" in text
        assert "XSS in /search" in text

    async def test_disabled_writers(self, tmp_path):
        log_dir = tmp_path / "logs"
        bus = EventBus()
        rl = RunLogger(log_dir, "test.com", bus, jsonl=False, human_readable=False)
        await rl.open()

        bus.emit(Event(EventType.STEP_COMPLETED, {"step": 1}))

        import asyncio
        await asyncio.sleep(0.05)
        await rl.close()

        # No files should be created (dir exists but no files)
        files = list(rl.run_dir.iterdir())
        assert len(files) == 0
