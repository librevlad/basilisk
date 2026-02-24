"""Tests for domain scenario models."""

from __future__ import annotations

from basilisk.domain.finding import Finding
from basilisk.domain.scenario import ScenarioMeta, ScenarioResult
from basilisk.domain.surface import Surface


class TestScenarioMeta:
    def test_basic_meta(self):
        meta = ScenarioMeta(
            name="test_scenario",
            display_name="Test Scenario",
            category="pentesting",
            description="A test scenario",
        )
        assert meta.name == "test_scenario"
        assert meta.timeout == 30.0
        assert meta.cost_score == 1.0

    def test_meta_with_knowledge(self):
        meta = ScenarioMeta(
            name="sqli_check",
            display_name="SQL Injection",
            category="pentesting",
            requires_knowledge=["Host", "Service:http", "Endpoint:params"],
            produces_knowledge=["Finding", "Vulnerability"],
            cost_score=3.0,
            noise_score=5.0,
        )
        assert "Endpoint:params" in meta.requires_knowledge
        assert meta.cost_score == 3.0

    def test_meta_defaults(self):
        meta = ScenarioMeta(
            name="x", display_name="X", category="recon",
        )
        assert meta.depends_on == []
        assert meta.produces == []
        assert not meta.requires_auth


class TestScenarioResult:
    def test_success_result(self):
        r = ScenarioResult(
            scenario="test",
            target="example.com",
            findings=[Finding.info("Test finding")],
            status="success",
            duration=1.5,
        )
        assert r.ok
        assert len(r.findings) == 1

    def test_error_result(self):
        r = ScenarioResult(
            scenario="test",
            target="example.com",
            status="error",
            error="Connection refused",
        )
        assert not r.ok

    def test_surfaces_discovered(self):
        r = ScenarioResult(
            scenario="web_crawler",
            target="example.com",
            surfaces_discovered=[
                Surface(host="example.com", url="https://example.com/login"),
            ],
        )
        assert len(r.surfaces_discovered) == 1
