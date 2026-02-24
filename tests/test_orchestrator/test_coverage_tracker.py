"""Tests for CoverageTracker."""

from __future__ import annotations

from basilisk.knowledge.vulns.registry import VulnDefinition, VulnRegistry
from basilisk.orchestrator.coverage_tracker import (
    CoverageTracker,
    VulnCategoryStatus,
)


def _registry() -> VulnRegistry:
    return VulnRegistry([
        VulnDefinition(id="sqli_error", name="SQLi", category="sqli",
                        detection_plugins=["sqli_basic"]),
        VulnDefinition(id="xss_reflected", name="XSS", category="xss",
                        detection_plugins=["xss_basic"]),
        VulnDefinition(id="ssti_basic", name="SSTI", category="ssti",
                        detection_plugins=["ssti_check"]),
    ])


class TestCoverageTracker:
    def test_init_empty(self):
        ct = CoverageTracker()
        assert ct.overall_coverage() == 0.0

    def test_record_execution(self):
        ct = CoverageTracker()
        ct.record_execution("sqli_basic", "example.com")
        cov = ct.host_coverage("example.com")
        assert "sqli_basic" in cov.plugins_executed
        assert cov.categories_tested.get("sqli") == VulnCategoryStatus.TESTED

    def test_record_execution_explicit_category(self):
        ct = CoverageTracker()
        ct.record_execution("custom_plugin", "example.com", category="xss")
        cov = ct.host_coverage("example.com")
        assert cov.categories_tested.get("xss") == VulnCategoryStatus.TESTED

    def test_record_finding(self):
        ct = CoverageTracker()
        ct.record_execution("sqli_basic", "example.com")
        ct.record_finding("example.com", "sqli")
        cov = ct.host_coverage("example.com")
        assert cov.categories_tested["sqli"] == VulnCategoryStatus.DETECTED
        assert cov.findings_count == 1

    def test_record_finding_verified(self):
        ct = CoverageTracker()
        ct.record_execution("sqli_basic", "example.com")
        ct.record_finding("example.com", "sqli", verified=True)
        cov = ct.host_coverage("example.com")
        assert cov.categories_tested["sqli"] == VulnCategoryStatus.VERIFIED
        assert cov.verified_count == 1

    def test_record_verification(self):
        ct = CoverageTracker()
        ct.record_execution("sqli_basic", "example.com")
        ct.record_finding("example.com", "sqli")
        ct.record_verification("example.com", "sqli")
        cov = ct.host_coverage("example.com")
        assert cov.categories_tested["sqli"] == VulnCategoryStatus.VERIFIED

    def test_overall_coverage_single_host(self):
        ct = CoverageTracker(vuln_registry=_registry())
        ct.record_execution("sqli_basic", "example.com")
        coverage = ct.overall_coverage()
        # 1 category tested out of 3 categories * 1 host
        assert abs(coverage - 1 / 3) < 0.01

    def test_overall_coverage_multiple_hosts(self):
        ct = CoverageTracker(vuln_registry=_registry())
        ct.record_execution("sqli_basic", "a.com")
        ct.record_execution("xss_basic", "b.com")
        coverage = ct.overall_coverage()
        # 2 tested out of 3 categories * 2 hosts = 6
        assert abs(coverage - 2 / 6) < 0.01

    def test_untested_categories(self):
        ct = CoverageTracker(vuln_registry=_registry())
        ct.record_execution("sqli_basic", "example.com")
        untested = ct.untested_categories("example.com")
        assert "sqli" not in untested
        assert "xss" in untested
        assert "ssti" in untested

    def test_coverage_snapshot(self):
        ct = CoverageTracker(vuln_registry=_registry())
        ct.record_execution("sqli_basic", "example.com")
        ct.record_finding("example.com", "sqli")
        snap = ct.coverage_snapshot()
        assert snap["hosts_tracked"] == 1
        assert snap["total_categories"] == 3
        assert "example.com" in snap["per_host"]
        assert snap["per_host"]["example.com"]["tested"] >= 1
        assert snap["per_host"]["example.com"]["detected"] >= 1

    def test_no_duplicate_plugins(self):
        ct = CoverageTracker()
        ct.record_execution("sqli_basic", "example.com")
        ct.record_execution("sqli_basic", "example.com")
        cov = ct.host_coverage("example.com")
        assert cov.plugins_executed.count("sqli_basic") == 1

    def test_detected_not_overwritten_by_tested(self):
        ct = CoverageTracker()
        ct.record_finding("example.com", "sqli")
        ct.record_execution("sqli_basic", "example.com")
        cov = ct.host_coverage("example.com")
        assert cov.categories_tested["sqli"] == VulnCategoryStatus.DETECTED

    def test_verified_not_overwritten_by_detected(self):
        ct = CoverageTracker()
        ct.record_finding("example.com", "sqli", verified=True)
        ct.record_finding("example.com", "sqli")
        cov = ct.host_coverage("example.com")
        assert cov.categories_tested["sqli"] == VulnCategoryStatus.VERIFIED

    def test_default_categories_used_without_registry(self):
        ct = CoverageTracker()
        assert len(ct._categories) > 20

    def test_host_coverage_creates_host(self):
        ct = CoverageTracker()
        cov = ct.host_coverage("new.com")
        assert cov.host == "new.com"
        assert cov.findings_count == 0

    def test_empty_category_not_recorded(self):
        ct = CoverageTracker()
        ct.record_finding("example.com", "")
        cov = ct.host_coverage("example.com")
        assert cov.findings_count == 1
        assert "" not in cov.categories_tested
