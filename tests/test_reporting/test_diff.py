"""Tests for historical report diff."""

from __future__ import annotations

from basilisk.reporting.diff import ReportDiff, compare_reports
from basilisk.reporting.model import ReportModel, ReportStatistics, VulnerabilityInstance


def _vuln(vid: str, severity: str = "HIGH", confidence: float = 0.9) -> VulnerabilityInstance:
    """Helper to create a VulnerabilityInstance."""
    return VulnerabilityInstance(
        vulnerability_id=vid,
        vuln_type="sqli",
        severity=severity,
        affected_surfaces=["/login"],
        scenarios=["sqli_basic"],
        confidence_aggregate=confidence,
        proofs=["test"],
    )


def _report(
    vulns: list[VulnerabilityInstance] | None = None,
    topology: dict | None = None,
    risk_score: float = 0.0,
) -> ReportModel:
    """Helper to build a minimal ReportModel."""
    return ReportModel(
        target="example.com",
        vulnerabilities=vulns or [],
        topology=topology or {},
        statistics=ReportStatistics(risk_score=risk_score),
    )


class TestCompareDiff:
    """Test compare_reports()."""

    def test_no_diff_identical_reports(self):
        v = _vuln("v1")
        r = _report(vulns=[v], topology={"example.com": {"services": [{"port": 80}]}})
        diff = compare_reports(r, r)
        assert diff.new_vulnerabilities == []
        assert diff.resolved_vulnerabilities == []
        assert diff.severity_changes == []
        assert diff.confidence_changes == []
        assert diff.new_hosts == []
        assert diff.removed_hosts == []
        assert diff.new_services == 0
        assert diff.removed_services == 0

    def test_new_vulnerability_detected(self):
        a = _report(vulns=[_vuln("v1")])
        b = _report(vulns=[_vuln("v1"), _vuln("v2")])
        diff = compare_reports(a, b)
        assert diff.new_vulnerabilities == ["v2"]
        assert diff.resolved_vulnerabilities == []

    def test_resolved_vulnerability(self):
        a = _report(vulns=[_vuln("v1"), _vuln("v2")])
        b = _report(vulns=[_vuln("v1")])
        diff = compare_reports(a, b)
        assert diff.resolved_vulnerabilities == ["v2"]
        assert diff.new_vulnerabilities == []

    def test_severity_change(self):
        a = _report(vulns=[_vuln("v1", severity="MEDIUM")])
        b = _report(vulns=[_vuln("v1", severity="HIGH")])
        diff = compare_reports(a, b)
        assert len(diff.severity_changes) == 1
        assert diff.severity_changes[0]["old_severity"] == "MEDIUM"
        assert diff.severity_changes[0]["new_severity"] == "HIGH"

    def test_confidence_change(self):
        a = _report(vulns=[_vuln("v1", confidence=0.5)])
        b = _report(vulns=[_vuln("v1", confidence=0.9)])
        diff = compare_reports(a, b)
        assert len(diff.confidence_changes) == 1
        assert diff.confidence_changes[0]["old_confidence"] == 0.5
        assert diff.confidence_changes[0]["new_confidence"] == 0.9

    def test_no_confidence_change_for_tiny_delta(self):
        a = _report(vulns=[_vuln("v1", confidence=0.9)])
        b = _report(vulns=[_vuln("v1", confidence=0.9005)])
        diff = compare_reports(a, b)
        assert diff.confidence_changes == []

    def test_new_host(self):
        a = _report(topology={"a.com": {"services": []}})
        b = _report(topology={"a.com": {"services": []}, "b.com": {"services": []}})
        diff = compare_reports(a, b)
        assert diff.new_hosts == ["b.com"]
        assert diff.removed_hosts == []

    def test_removed_host(self):
        a = _report(topology={"a.com": {"services": []}, "b.com": {"services": []}})
        b = _report(topology={"a.com": {"services": []}})
        diff = compare_reports(a, b)
        assert diff.removed_hosts == ["b.com"]
        assert diff.new_hosts == []

    def test_new_services(self):
        a = _report(topology={"a.com": {"services": [{"port": 80}]}})
        b = _report(topology={"a.com": {"services": [{"port": 80}, {"port": 443}]}})
        diff = compare_reports(a, b)
        assert diff.new_services == 1
        assert diff.removed_services == 0

    def test_removed_services(self):
        a = _report(topology={"a.com": {"services": [{"port": 80}, {"port": 443}]}})
        b = _report(topology={"a.com": {"services": [{"port": 80}]}})
        diff = compare_reports(a, b)
        assert diff.removed_services == 1
        assert diff.new_services == 0

    def test_empty_reports(self):
        a = _report()
        b = _report()
        diff = compare_reports(a, b)
        assert isinstance(diff, ReportDiff)
        assert diff.new_vulnerabilities == []

    def test_multiple_changes(self):
        a = _report(
            vulns=[_vuln("v1", severity="LOW"), _vuln("v2")],
            topology={"a.com": {"services": [{"port": 80}]}},
        )
        b = _report(
            vulns=[_vuln("v1", severity="HIGH"), _vuln("v3")],
            topology={
                "a.com": {"services": [{"port": 80}]},
                "b.com": {"services": [{"port": 443}]},
            },
        )
        diff = compare_reports(a, b)
        assert diff.new_vulnerabilities == ["v3"]
        assert diff.resolved_vulnerabilities == ["v2"]
        assert len(diff.severity_changes) == 1
        assert diff.new_hosts == ["b.com"]
        assert diff.new_services == 1

    def test_coverage_delta(self):
        a = _report(risk_score=3.5)
        b = _report(risk_score=6.0)
        diff = compare_reports(a, b)
        assert diff.coverage_delta == 2.5

    def test_coverage_delta_negative(self):
        a = _report(risk_score=8.0)
        b = _report(risk_score=5.5)
        diff = compare_reports(a, b)
        assert diff.coverage_delta == -2.5

    def test_coverage_delta_zero(self):
        a = _report(risk_score=4.0)
        b = _report(risk_score=4.0)
        diff = compare_reports(a, b)
        assert diff.coverage_delta == 0.0

    def test_new_endpoints_detected(self):
        a = _report(topology={
            "a.com": {"services": [], "endpoints": ["/login"]},
        })
        b = _report(topology={
            "a.com": {"services": [], "endpoints": ["/login", "/admin"]},
        })
        diff = compare_reports(a, b)
        assert diff.new_endpoints == ["a.com/admin"]
        assert diff.removed_endpoints == []

    def test_removed_endpoints_detected(self):
        a = _report(topology={
            "a.com": {"services": [], "endpoints": ["/login", "/admin"]},
        })
        b = _report(topology={
            "a.com": {"services": [], "endpoints": ["/login"]},
        })
        diff = compare_reports(a, b)
        assert diff.removed_endpoints == ["a.com/admin"]
        assert diff.new_endpoints == []

    def test_endpoints_across_hosts(self):
        a = _report(topology={
            "a.com": {"services": [], "endpoints": ["/api"]},
        })
        b = _report(topology={
            "a.com": {"services": [], "endpoints": ["/api"]},
            "b.com": {"services": [], "endpoints": ["/health"]},
        })
        diff = compare_reports(a, b)
        assert diff.new_endpoints == ["b.com/health"]
