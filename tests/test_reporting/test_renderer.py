"""Tests for report renderer — HTML and JSON generation."""

from __future__ import annotations

import json

from basilisk.reporting.collector import (
    ReportCollector,
    ReportDecision,
    ReportFinding,
    ReportPlugin,
    StepSnapshot,
)
from basilisk.reporting.renderer import assemble_data, render_html, render_json


def _sample_collector() -> ReportCollector:
    """Build a collector with representative data."""
    c = ReportCollector(target="test.example.com", mode="auto", max_steps=50)
    c.step = 10
    c.total_entities = 42
    c.total_relations = 20
    c.gap_count = 3
    c.entity_counts["host"] = 2
    c.entity_counts["service"] = 8
    c.entity_counts["endpoint"] = 15
    c.entity_counts["technology"] = 5
    c.findings = [
        ReportFinding(
            title="SQL Injection in /login",
            severity="high",
            host="test.example.com",
            evidence="1' OR '1'='1 returned 200",
            description="Auth bypass via SQLi",
            tags=["sqli", "auth"],
            confidence=0.92,
            verified=True,
            step=5,
        ),
        ReportFinding(
            title="Missing HSTS Header",
            severity="info",
            host="test.example.com",
            step=2,
        ),
    ]
    c.decisions = [
        ReportDecision(step=1, plugin="port_scan", target="test.example.com", score=0.95,
                       reasoning="initial recon"),
        ReportDecision(step=5, plugin="sqli_basic", target="test.example.com", score=0.87,
                       reasoning="high priority gap", productive=True, new_entities=3),
    ]
    c.plugins = [
        ReportPlugin(name="port_scan", target="test.example.com", duration=1.5,
                     findings_count=0, step=1),
        ReportPlugin(name="sqli_basic", target="test.example.com", duration=3.2,
                     findings_count=1, step=5),
    ]
    c.step_history = [
        StepSnapshot(step=1, entities=10, relations=5, gaps=8, entities_gained=10),
        StepSnapshot(step=2, entities=18, relations=9, gaps=6, entities_gained=8),
        StepSnapshot(step=5, entities=42, relations=20, gaps=3, entities_gained=5),
    ]
    c.hypotheses_confirmed = 2
    c.hypotheses_rejected = 1
    c.beliefs_strengthened = 5
    c.beliefs_weakened = 1
    return c


class TestAssembleData:
    """Test assemble_data output structure."""

    def test_has_required_keys(self):
        c = _sample_collector()
        data = assemble_data(c)
        assert data["version"] == "4.0.0"
        assert data["target"] == "test.example.com"
        assert data["mode"] == "auto"
        assert data["status"] == "running"
        assert "summary" in data
        assert "findings" in data
        assert "decisions" in data
        assert "plugins" in data
        assert "step_history" in data
        assert "reasoning" in data
        assert "training" in data

    def test_summary_values(self):
        c = _sample_collector()
        data = assemble_data(c)
        s = data["summary"]
        assert s["steps"] == 10
        assert s["max_steps"] == 50
        assert s["total_entities"] == 42
        assert s["total_findings"] == 2
        assert s["total_gaps"] == 3
        assert s["entity_counts"]["host"] == 2
        assert s["entity_counts"]["service"] == 8

    def test_findings_serialized(self):
        c = _sample_collector()
        data = assemble_data(c)
        assert len(data["findings"]) == 2
        f = data["findings"][0]
        assert f["title"] == "SQL Injection in /login"
        assert f["severity"] == "HIGH"
        assert f["verified"] is True
        assert f["confidence"] == 0.92

    def test_decisions_serialized(self):
        c = _sample_collector()
        data = assemble_data(c)
        assert len(data["decisions"]) == 2
        assert data["decisions"][1]["productive"] is True

    def test_reasoning_serialized(self):
        c = _sample_collector()
        data = assemble_data(c)
        r = data["reasoning"]
        assert r["hypotheses_confirmed"] == 2
        assert r["beliefs_strengthened"] == 5

    def test_training_none(self):
        c = _sample_collector()
        data = assemble_data(c)
        assert data["training"] is None

    def test_empty_collector(self):
        c = ReportCollector()
        data = assemble_data(c)
        assert data["summary"]["steps"] == 0
        assert len(data["findings"]) == 0
        assert data["training"] is None


class TestRenderJson:
    """Test JSON rendering."""

    def test_valid_json(self):
        c = _sample_collector()
        data = assemble_data(c)
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["target"] == "test.example.com"

    def test_empty_data(self):
        data = assemble_data(ReportCollector())
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["version"] == "4.0.0"


class TestRenderHtml:
    """Test HTML rendering."""

    def test_contains_doctype(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert html.startswith("<!DOCTYPE html>")

    def test_contains_target(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "test.example.com" in html

    def test_auto_refresh_present(self):
        data = assemble_data(_sample_collector())
        html = render_html(data, auto_refresh=True)
        assert 'http-equiv="refresh"' in html

    def test_auto_refresh_absent(self):
        data = assemble_data(_sample_collector())
        html = render_html(data, auto_refresh=False)
        assert 'http-equiv="refresh"' not in html

    def test_contains_sections(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert 'id="command-center"' in html
        assert 'id="kill-chain"' in html
        assert 'id="kg-growth"' in html
        assert 'id="findings"' in html
        assert 'id="decisions"' in html
        assert 'id="attack-surface"' in html
        assert 'id="plugins"' in html
        assert 'id="reasoning"' in html

    def test_findings_rendered(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "SQL Injection in /login" in html
        assert "sev-HIGH" in html
        assert "VERIFIED" in html

    def test_css_variables(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "--neon-green: #00ff6a" in html
        assert "--critical: #ff1744" in html
        assert "JetBrains Mono" in html

    def test_js_embedded(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "toggleFilter" in html
        assert "applyFilters" in html
        assert "IntersectionObserver" in html

    def test_data_embedded_as_json(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "const DATA =" in html

    def test_empty_findings(self):
        data = assemble_data(ReportCollector())
        html = render_html(data)
        assert "No findings yet" in html

    def test_empty_decisions(self):
        data = assemble_data(ReportCollector())
        html = render_html(data)
        assert "No decisions yet" in html

    def test_empty_growth(self):
        data = assemble_data(ReportCollector())
        html = render_html(data)
        assert "No data yet" in html

    def test_sidebar_risk_score(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "Risk Score" in html

    def test_kill_chain_phases(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "Recon" in html
        assert "Mapping" in html
        assert "Exploit" in html
        assert "Privesc" in html
        assert "Verify" in html

    def test_training_section_absent_when_none(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert 'id="training"' not in html

    def test_training_section_present(self):
        c = _sample_collector()
        c.training = {
            "profile_name": "test_app",
            "coverage": 0.85,
            "verification_rate": 0.7,
            "passed": True,
            "expected_findings": [
                {"title": "SQLi", "severity": "high",
                 "discovered": True, "verified": True, "discovery_step": 3},
            ],
        }
        data = assemble_data(c)
        html = render_html(data)
        assert 'id="training"' in html
        assert "PASSED" in html
        assert "test_app" in html

    def test_html_escaping(self):
        """Ensure special characters are escaped."""
        c = ReportCollector(target="<script>alert(1)</script>")
        data = assemble_data(c)
        html = render_html(data)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
