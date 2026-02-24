"""Tests for result adapter — v3/v4 Finding and Result conversion."""

from __future__ import annotations

from basilisk.bridge.result_adapter import ResultAdapter
from basilisk.domain.finding import Finding as V4Finding
from basilisk.domain.finding import Proof
from basilisk.models.result import Finding as V3Finding
from basilisk.models.result import PluginResult, Severity


class TestResultAdapter:
    def test_v3_finding_to_v4(self):
        v3 = V3Finding(
            severity=Severity.HIGH,
            title="XSS in /search",
            description="Reflected XSS",
            evidence="<script>alert(1)</script>",
            confidence=0.9,
            tags=["xss", "web"],
        )
        v4 = ResultAdapter.to_v4_finding(v3, "xss_check")
        assert v4.title == "XSS in /search"
        assert v4.severity == Severity.HIGH
        assert v4.proof is not None
        assert v4.proof.description == "<script>alert(1)</script>"
        assert v4.confidence == 0.9
        assert "xss" in v4.tags
        assert v4.scenario_name == "xss_check"

    def test_v3_finding_to_v4_no_evidence(self):
        v3 = V3Finding(severity=Severity.INFO, title="Info")
        v4 = ResultAdapter.to_v4_finding(v3)
        assert v4.proof is None

    def test_v4_finding_to_v3(self):
        v4 = V4Finding(
            title="SQLi",
            severity=Severity.CRITICAL,
            proof=Proof(description="' OR 1=1--"),
            tags=frozenset({"sqli"}),
        )
        v3 = ResultAdapter.to_v3_finding(v4)
        assert v3.title == "SQLi"
        assert v3.evidence == "' OR 1=1--"
        assert "sqli" in v3.tags

    def test_round_trip_finding(self):
        v3_orig = V3Finding(
            severity=Severity.MEDIUM,
            title="Open Redirect",
            description="Redirects to external",
            evidence="Location: https://evil.com",
            tags=["redirect"],
            confidence=0.8,
        )
        v4 = ResultAdapter.to_v4_finding(v3_orig)
        v3_back = ResultAdapter.to_v3_finding(v4)
        assert v3_back.title == v3_orig.title
        assert v3_back.severity == v3_orig.severity
        assert v3_back.evidence == v3_orig.evidence
        assert v3_back.confidence == v3_orig.confidence

    def test_plugin_result_to_scenario_result(self):
        pr = PluginResult.success(
            "ssl_check", "example.com",
            findings=[V3Finding.info("SSL OK")],
            data={"ssl_version": "TLS 1.3"},
        )
        pr.duration = 1.5
        sr = ResultAdapter.to_scenario_result(pr)
        assert sr.scenario == "ssl_check"
        assert sr.target == "example.com"
        assert sr.ok
        assert len(sr.findings) == 1
        assert sr.data["ssl_version"] == "TLS 1.3"
        assert sr.duration == 1.5

    def test_scenario_result_to_plugin_result(self):
        from basilisk.domain.scenario import ScenarioResult
        sr = ScenarioResult(
            scenario="test", target="example.com",
            findings=[V4Finding.info("Test")],
            data={"key": "val"},
            status="success",
            duration=2.0,
        )
        pr = ResultAdapter.to_v3_result(sr)
        assert pr.plugin == "test"
        assert pr.ok
        assert len(pr.findings) == 1
        assert pr.data["key"] == "val"

    def test_error_result_conversion(self):
        pr = PluginResult.fail("broken", "host", "Connection refused")
        sr = ResultAdapter.to_scenario_result(pr)
        assert not sr.ok
        assert sr.error == "Connection refused"

    def test_empty_findings(self):
        pr = PluginResult.success("scan", "host")
        sr = ResultAdapter.to_scenario_result(pr)
        assert sr.findings == []
