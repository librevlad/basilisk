"""Tests for report renderers — JSON, CSV, HTML."""

import json

from basilisk.core.pipeline import PipelineState
from basilisk.models.result import Finding, PluginResult
from basilisk.reporting.csv import CsvRenderer
from basilisk.reporting.engine import ReportEngine
from basilisk.reporting.html import HtmlRenderer
from basilisk.reporting.json import JsonRenderer


def _make_state() -> PipelineState:
    state = PipelineState()
    state.status = "completed"
    state.total_findings = 3
    state.results = [
        PluginResult.success(
            "ssl_check", "example.com",
            findings=[
                Finding.high("Expired SSL", evidence="cert expired"),
                Finding.medium("Missing HSTS"),
            ],
            duration=1.5,
        ),
        PluginResult.success(
            "http_headers", "api.example.com",
            findings=[Finding.low("Server header exposed", evidence="Server: nginx")],
            duration=0.8,
        ),
    ]
    return state


class TestJsonRenderer:
    def test_render(self, tmp_path):
        state = _make_state()
        renderer = JsonRenderer()
        path = renderer.render(state, tmp_path)

        assert path.exists()
        assert path.suffix == ".json"

        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["status"] == "completed"
        assert data["total_findings"] == 3
        assert len(data["results"]) == 2


class TestCsvRenderer:
    def test_render(self, tmp_path):
        state = _make_state()
        renderer = CsvRenderer()
        path = renderer.render(state, tmp_path)

        assert path.exists()
        assert path.suffix == ".csv"

        lines = path.read_text(encoding="utf-8-sig").strip().split("\n")
        assert len(lines) == 4  # header + 3 findings
        assert "severity" in lines[0]


class TestHtmlRenderer:
    def test_render(self, tmp_path):
        state = _make_state()
        renderer = HtmlRenderer()
        path = renderer.render(state, tmp_path)

        assert path.exists()
        assert path.suffix == ".html"

        html = path.read_text(encoding="utf-8")
        assert "Basilisk" in html
        assert "Expired SSL" in html
        assert "example.com" in html


class TestReportEngine:
    def test_multi_format(self, tmp_path):
        state = _make_state()
        engine = ReportEngine()
        engine.register("json", JsonRenderer())
        engine.register("csv", CsvRenderer())
        engine.register("html", HtmlRenderer())

        paths = engine.generate(state, tmp_path, formats=["json", "csv", "html"])
        assert len(paths) == 3
        assert all(p.exists() for p in paths)

    def test_selective_formats(self, tmp_path):
        state = _make_state()
        engine = ReportEngine()
        engine.register("json", JsonRenderer())
        engine.register("csv", CsvRenderer())

        paths = engine.generate(state, tmp_path, formats=["json"])
        assert len(paths) == 1
