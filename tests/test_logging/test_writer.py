"""Tests for JSONL and text file writers."""

from __future__ import annotations

import json

from basilisk.logging.writer import JsonlWriter, TextWriter


class TestJsonlWriter:
    async def test_writes_valid_json(self, tmp_path):
        path = tmp_path / "events.jsonl"
        writer = JsonlWriter(path)
        await writer.open()

        events = [
            {"event_type": "STEP_COMPLETED", "step": 1, "entities": 5},
            {"event_type": "PLUGIN_STARTED", "plugin": "port_scan"},
            {"event_type": "DECISION_MADE", "score": 0.85},
        ]
        for ev in events:
            await writer.write(ev)
        await writer.close()

        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 3
        for i, line in enumerate(lines):
            parsed = json.loads(line)
            assert parsed["event_type"] == events[i]["event_type"]

    async def test_flush_on_close(self, tmp_path):
        path = tmp_path / "events.jsonl"
        writer = JsonlWriter(path)
        await writer.open()
        await writer.write({"test": True})
        await writer.close()

        content = path.read_text(encoding="utf-8")
        assert '"test": true' in content

    async def test_noop_when_not_opened(self, tmp_path):
        path = tmp_path / "events.jsonl"
        writer = JsonlWriter(path)
        # write without open should not raise
        await writer.write({"test": True})
        await writer.close()
        assert not path.exists()


class TestTextWriter:
    async def test_writes_lines(self, tmp_path):
        path = tmp_path / "run.log"
        writer = TextWriter(path)
        await writer.open()

        await writer.write("[12:00:00] [STEP 1] [DECISION] port_scan -> example.com")
        await writer.write("[12:00:01] [STEP 1] [PLUGIN] Started: port_scan")
        await writer.close()

        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        assert "[DECISION]" in lines[0]
        assert "[PLUGIN]" in lines[1]

    async def test_flush_on_close(self, tmp_path):
        path = tmp_path / "run.log"
        writer = TextWriter(path)
        await writer.open()
        await writer.write("test line")
        await writer.close()

        assert "test line" in path.read_text(encoding="utf-8")

    async def test_noop_when_not_opened(self, tmp_path):
        path = tmp_path / "run.log"
        writer = TextWriter(path)
        await writer.write("ignored")
        await writer.close()
        assert not path.exists()
