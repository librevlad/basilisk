"""Tests for FindingConfirmer."""

from __future__ import annotations

from basilisk.capabilities.capability import ActionType, Capability
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.vulns.registry import VulnDefinition, VulnRegistry
from basilisk.models.result import Finding, PluginResult
from basilisk.verification.confirmer import FindingConfirmer


def _cap(name: str, reduces: list[str] | None = None, **kw) -> Capability:
    return Capability(
        name=name,
        plugin_name=name,
        category="pentesting",
        requires_knowledge=["Endpoint:params"],
        produces_knowledge=["Finding"],
        cost_score=3.0,
        noise_score=3.0,
        reduces_uncertainty=reduces or [],
        action_type=ActionType.VERIFICATION if reduces else ActionType.EXPERIMENT,
        **kw,
    )


def _finding(host: str = "example.com", title: str = "SQLi in /login", **kw) -> Entity:
    return Entity.finding(host, title, **kw)


def _registry() -> VulnRegistry:
    return VulnRegistry([
        VulnDefinition(
            id="sqli_error",
            name="SQL Injection",
            category="sqli",
            detection_plugins=["sqli_basic"],
            verification_plugins=["sqli_extract"],
        ),
        VulnDefinition(
            id="xss_reflected",
            name="XSS",
            category="xss",
            detection_plugins=["xss_basic"],
            verification_plugins=[],
        ),
    ])


class TestFindingConfirmer:
    def test_can_verify_with_registry(self):
        caps = {"sqli_extract": _cap("sqli_extract", reduces=["Finding:sqli"])}
        confirmer = FindingConfirmer(caps, vuln_registry=_registry())
        finding = _finding(title="SQLi in /login", category="sqli")
        assert confirmer.can_verify(finding) is True

    def test_can_verify_without_registry(self):
        caps = {"sqli_extract": _cap("sqli_extract", reduces=["Finding:sqli"])}
        confirmer = FindingConfirmer(caps)
        finding = _finding(title="SQLi in /login")
        assert confirmer.can_verify(finding) is True

    def test_cannot_verify(self):
        caps = {"some_plugin": _cap("some_plugin")}
        confirmer = FindingConfirmer(caps)
        finding = _finding(title="Unknown vuln")
        assert confirmer.can_verify(finding) is False

    def test_suggest_verifiers_from_registry(self):
        caps = {"sqli_extract": _cap("sqli_extract", reduces=["Finding:sqli"])}
        confirmer = FindingConfirmer(caps, vuln_registry=_registry())
        finding = _finding(title="SQLi in /login", category="sqli")
        verifiers = confirmer.suggest_verifiers(finding)
        assert "sqli_extract" in verifiers

    def test_suggest_verifiers_from_capabilities(self):
        caps = {
            "ssti_verify": _cap("ssti_verify", reduces=["Finding:ssti"]),
        }
        confirmer = FindingConfirmer(caps)
        finding = _finding(title="SSTI in /template", category="ssti")
        verifiers = confirmer.suggest_verifiers(finding)
        assert "ssti_verify" in verifiers

    def test_suggest_verifiers_dedup(self):
        caps = {"sqli_extract": _cap("sqli_extract", reduces=["Finding:sqli"])}
        confirmer = FindingConfirmer(caps, vuln_registry=_registry())
        finding = _finding(title="SQLi", category="sqli")
        verifiers = confirmer.suggest_verifiers(finding)
        assert len(verifiers) == len(set(verifiers))

    def test_evaluate_result_confirmed(self):
        caps = {}
        confirmer = FindingConfirmer(caps)
        finding = _finding(host="example.com", title="SQLi")

        result = PluginResult.success("sqli_extract", "example.com", findings=[
            Finding.high("Confirmed SQLi", evidence="proof"),
        ])
        cr = confirmer.evaluate_result(finding, result)
        assert cr.verdict == "confirmed"
        assert cr.confidence_delta > 0

    def test_evaluate_result_likely(self):
        caps = {}
        confirmer = FindingConfirmer(caps)
        finding = _finding(host="example.com", title="SQLi")

        result = PluginResult.success("sqli_extract", "example.com", findings=[
            Finding.low("Minor related finding"),
        ])
        cr = confirmer.evaluate_result(finding, result)
        assert cr.verdict == "likely"

    def test_evaluate_result_false_positive(self):
        caps = {}
        confirmer = FindingConfirmer(caps)
        finding = _finding(host="example.com", title="SQLi")

        result = PluginResult.success("sqli_extract", "example.com", findings=[])
        cr = confirmer.evaluate_result(finding, result)
        assert cr.verdict == "false_positive"
        assert cr.confidence_delta < 0

    def test_evaluate_result_failed(self):
        caps = {}
        confirmer = FindingConfirmer(caps)
        finding = _finding(host="example.com", title="SQLi")

        result = PluginResult.fail("sqli_extract", "example.com", error="timeout")
        cr = confirmer.evaluate_result(finding, result)
        assert cr.verdict == "inconclusive"

    def test_extract_category_from_data(self):
        finding = _finding(category="xss")
        assert FindingConfirmer._extract_category(finding) == "xss"

    def test_extract_category_from_title(self):
        finding = _finding(title="Found SSRF vulnerability")
        assert FindingConfirmer._extract_category(finding) == "ssrf"
