"""Tests for ReportWriter — async periodic file writing."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from basilisk.events.bus import Event, EventBus, EventType
from basilisk.reporting.writer import ReportWriter, _safe_dirname


class TestSafeDirname:
    """Test directory name sanitization."""

    def test_simple_domain(self):
        assert _safe_dirname("example.com") == "example.com"

    def test_ip_with_port(self):
        assert _safe_dirname("10.0.0.1:8080") == "10.0.0.1_8080"

    def test_special_characters(self):
        result = _safe_dirname("http://evil<>site/path?q=1")
        assert "<" not in result
        assert ">" not in result
        assert "?" not in result

    def test_long_name_truncated(self):
        result = _safe_dirname("a" * 200)
        assert len(result) <= 80


class TestReportWriterInit:
    """Test writer initialization."""

    def test_default_report_dir(self):
        bus = EventBus()
        writer = ReportWriter(bus, target="test.com", max_steps=50)
        assert "test.com" in str(writer.report_dir)
        assert writer.report_dir.parent == Path("reports")

    def test_custom_report_dir(self):
        bus = EventBus()
        custom = Path("/tmp/my_report")
        writer = ReportWriter(bus, target="test.com", report_dir=custom)
        assert writer.report_dir == custom

    def test_collector_configured(self):
        bus = EventBus()
        writer = ReportWriter(bus, target="test.com", max_steps=50, mode="train")
        assert writer.collector.target == "test.com"
        assert writer.collector.max_steps == 50
        assert writer.collector.mode == "train"

    def test_events_flow_to_collector(self):
        bus = EventBus()
        writer = ReportWriter(bus, target="test.com")
        bus.emit(Event(EventType.GAP_DETECTED, {"count": 5}))
        assert writer.collector.gap_count == 5


class TestReportWriterLifecycle:
    """Test start/finalize lifecycle."""

    async def test_start_creates_dir_and_files(self, tmp_path):
        bus = EventBus()
        report_dir = tmp_path / "report_test"
        writer = ReportWriter(bus, target="test.com", report_dir=report_dir)

        result_dir = await writer.start()
        assert result_dir == report_dir
        assert report_dir.exists()
        assert (report_dir / "report.html").exists()
        assert (report_dir / "report.json").exists()

        # HTML should have auto-refresh
        html = (report_dir / "report.html").read_text(encoding="utf-8")
        assert 'http-equiv="refresh"' in html

        # JSON should be valid
        data = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
        assert data["target"] == "test.com"
        assert data["status"] == "running"

        await writer.finalize(termination_reason="test_done")

    async def test_finalize_removes_auto_refresh(self, tmp_path):
        bus = EventBus()
        report_dir = tmp_path / "report_final"
        writer = ReportWriter(bus, target="test.com", report_dir=report_dir)

        await writer.start()
        await writer.finalize(termination_reason="no_gaps")

        html = (report_dir / "report.html").read_text(encoding="utf-8")
        assert 'http-equiv="refresh"' not in html

        data = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
        assert data["status"] == "completed"
        assert data["termination_reason"] == "no_gaps"

    async def test_finalize_without_start(self, tmp_path):
        bus = EventBus()
        report_dir = tmp_path / "report_no_start"
        writer = ReportWriter(bus, target="test.com", report_dir=report_dir)

        # Should not raise — finalize creates dir if needed
        report_dir.mkdir(parents=True)
        await writer.finalize(termination_reason="early_stop")
        assert (report_dir / "report.html").exists()

    async def test_periodic_writes(self, tmp_path):
        bus = EventBus()
        report_dir = tmp_path / "report_periodic"
        writer = ReportWriter(
            bus, target="test.com", report_dir=report_dir, interval=0.1,
        )

        await writer.start()

        # Emit some events
        bus.emit(Event(EventType.STEP_COMPLETED, {
            "step": 1, "entities": 10, "relations": 5,
        }))

        # Wait for at least one periodic write
        await asyncio.sleep(0.25)

        data = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
        assert data["summary"]["steps"] == 1
        assert data["summary"]["total_entities"] == 10

        await writer.finalize(termination_reason="done")

    async def test_finalize_training(self, tmp_path):
        bus = EventBus()
        report_dir = tmp_path / "report_train"
        writer = ReportWriter(
            bus, target="train.app", report_dir=report_dir, mode="train",
        )
        await writer.start()

        report = MagicMock()
        report.profile_name = "test_profile"
        report.coverage = 0.9
        report.verification_rate = 0.8
        report.passed = True

        tracker = MagicMock()
        tf = MagicMock()
        tf.expected.title = "XSS"
        tf.expected.severity = "medium"
        tf.discovered = True
        tf.verified = False
        tf.discovery_step = 4
        tracker.tracked = [tf]

        result = await writer.finalize_training(report, tracker)
        assert result == report_dir

        data = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
        assert data["training"] is not None
        assert data["training"]["profile_name"] == "test_profile"
        assert data["training"]["passed"] is True
        assert len(data["training"]["expected_findings"]) == 1

        html = (report_dir / "report.html").read_text(encoding="utf-8")
        assert 'id="training"' in html
        assert "PASSED" in html

    async def test_write_exception_does_not_crash(self, tmp_path):
        bus = EventBus()
        report_dir = tmp_path / "report_err"
        writer = ReportWriter(bus, target="test.com", report_dir=report_dir)

        await writer.start()

        # Patch _write_file to raise
        with patch.object(writer, "_write_file", side_effect=OSError("disk full")):
            # Trigger a write via event + sleep
            bus.emit(Event(EventType.STEP_COMPLETED, {"step": 1, "entities": 5, "relations": 2}))
            await asyncio.sleep(0.15)

        # Should still finalize gracefully (unpatch)
        await writer.finalize(termination_reason="survived_error")
        assert (report_dir / "report.html").exists()


class TestAtomicWrite:
    """Test atomic write mechanics."""

    async def test_no_tmp_files_left(self, tmp_path):
        bus = EventBus()
        report_dir = tmp_path / "report_atomic"
        writer = ReportWriter(bus, target="test.com", report_dir=report_dir)

        await writer.start()
        await writer.finalize(termination_reason="done")

        # No .tmp files should remain
        tmp_files = list(report_dir.glob(".*tmp"))
        assert len(tmp_files) == 0
