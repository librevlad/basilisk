"""Tests for the vulnerability registry."""

from __future__ import annotations

from basilisk.knowledge.vulns.registry import (
    ConfidenceThresholds,
    VulnDefinition,
    VulnRegistry,
)


def _sample_vulns() -> list[VulnDefinition]:
    return [
        VulnDefinition(
            id="sqli_error",
            name="SQL Injection (Error-based)",
            category="sqli",
            cwe_ids=["CWE-89"],
            owasp_ids=["A03:2021"],
            severity_range=["high", "critical"],
            detection_plugins=["sqli_basic", "sqli_advanced"],
            verification_plugins=["sqli_extract"],
            verification_techniques=["error_based", "union_based"],
            false_positive_indicators=["generic error page"],
            confidence_thresholds=ConfidenceThresholds(
                detection_floor=0.4,
                verification_bonus=0.35,
            ),
        ),
        VulnDefinition(
            id="sqli_blind",
            name="SQL Injection (Blind)",
            category="sqli",
            detection_plugins=["sqli_basic"],
            verification_plugins=["sqli_extract"],
        ),
        VulnDefinition(
            id="xss_reflected",
            name="XSS (Reflected)",
            category="xss",
            detection_plugins=["xss_basic", "xss_advanced"],
            verification_plugins=[],
        ),
        VulnDefinition(
            id="ssti_basic",
            name="Server-Side Template Injection",
            category="ssti",
            detection_plugins=["ssti_check"],
            verification_plugins=["ssti_verify"],
        ),
    ]


class TestVulnDefinition:
    def test_default_thresholds(self):
        v = VulnDefinition(id="test", name="Test", category="test")
        assert v.confidence_thresholds.detection_floor == 0.4
        assert v.confidence_thresholds.verification_bonus == 0.3

    def test_custom_thresholds(self):
        ct = ConfidenceThresholds(detection_floor=0.5, verification_bonus=0.4)
        v = VulnDefinition(id="test", name="Test", category="test", confidence_thresholds=ct)
        assert v.confidence_thresholds.detection_floor == 0.5


class TestVulnRegistry:
    def test_init_empty(self):
        reg = VulnRegistry()
        assert len(reg) == 0

    def test_init_with_vulns(self):
        reg = VulnRegistry(_sample_vulns())
        assert len(reg) == 4

    def test_get_existing(self):
        reg = VulnRegistry(_sample_vulns())
        v = reg.get("sqli_error")
        assert v is not None
        assert v.name == "SQL Injection (Error-based)"

    def test_get_missing(self):
        reg = VulnRegistry(_sample_vulns())
        assert reg.get("nonexistent") is None

    def test_by_category(self):
        reg = VulnRegistry(_sample_vulns())
        sqli = reg.by_category("sqli")
        assert len(sqli) == 2
        assert all(v.category == "sqli" for v in sqli)

    def test_by_category_empty(self):
        reg = VulnRegistry(_sample_vulns())
        assert reg.by_category("nosqli") == []

    def test_detection_plugins_for(self):
        reg = VulnRegistry(_sample_vulns())
        plugins = reg.detection_plugins_for("sqli")
        assert "sqli_basic" in plugins
        assert "sqli_advanced" in plugins
        # Should be deduped
        assert len(plugins) == len(set(plugins))

    def test_verification_plugins_for(self):
        reg = VulnRegistry(_sample_vulns())
        plugins = reg.verification_plugins_for("sqli")
        assert "sqli_extract" in plugins

    def test_verification_plugins_empty(self):
        reg = VulnRegistry(_sample_vulns())
        plugins = reg.verification_plugins_for("xss")
        assert plugins == []

    def test_confidence_thresholds_for(self):
        reg = VulnRegistry(_sample_vulns())
        ct = reg.confidence_thresholds_for("sqli")
        assert ct.verification_bonus == 0.35

    def test_confidence_thresholds_default(self):
        reg = VulnRegistry(_sample_vulns())
        ct = reg.confidence_thresholds_for("nosqli")
        assert ct.detection_floor == 0.4  # default

    def test_match_finding_by_category(self):
        reg = VulnRegistry(_sample_vulns())
        v = reg.match_finding("Some SQLi thing", category="sqli")
        assert v is not None
        assert v.category == "sqli"

    def test_match_finding_by_title_keyword(self):
        reg = VulnRegistry(_sample_vulns())
        v = reg.match_finding("Found sqli in /login", category="")
        assert v is not None
        assert v.category == "sqli"

    def test_match_finding_no_match(self):
        reg = VulnRegistry(_sample_vulns())
        v = reg.match_finding("Random finding", category="")
        assert v is None

    def test_load_bundled(self):
        reg = VulnRegistry.load_bundled()
        assert len(reg) >= 30
        # Check a known definition
        sqli = reg.by_category("sqli")
        assert len(sqli) >= 1

    def test_categories(self):
        reg = VulnRegistry(_sample_vulns())
        cats = reg.categories()
        assert "sqli" in cats
        assert "xss" in cats
        assert "ssti" in cats

    def test_all(self):
        vulns = _sample_vulns()
        reg = VulnRegistry(vulns)
        assert len(reg.all()) == len(vulns)
