"""Tests for ReValidator."""

from __future__ import annotations

from basilisk.capabilities.capability import ActionType, Capability
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.vulns.registry import VulnDefinition, VulnRegistry
from basilisk.verification.confirmer import FindingConfirmer
from basilisk.verification.revalidator import RevalidationStrategy, ReValidator


def _cap(name: str, reduces: list[str] | None = None) -> Capability:
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
    )


def _finding(host: str = "example.com", title: str = "SQLi", **kw) -> Entity:
    return Entity.finding(host, title, **kw)


def _registry_with_techniques() -> VulnRegistry:
    return VulnRegistry([
        VulnDefinition(
            id="sqli_error",
            name="SQL Injection",
            category="sqli",
            detection_plugins=["sqli_basic"],
            verification_plugins=["sqli_extract"],
            verification_techniques=["error_based", "union_based", "time_based"],
        ),
    ])


class TestReValidator:
    def test_plan_different_technique(self):
        caps = {"sqli_extract": _cap("sqli_extract", reduces=["Finding:sqli"])}
        confirmer = FindingConfirmer(caps, vuln_registry=_registry_with_techniques())
        reval = ReValidator(confirmer, vuln_registry=_registry_with_techniques())

        finding = _finding(title="SQLi in /login", category="sqli")
        plans = reval.plan_revalidation(finding)
        assert len(plans) >= 1
        assert plans[0].strategy == RevalidationStrategy.DIFFERENT_TECHNIQUE

    def test_plan_different_payload(self):
        caps = {"sqli_extract": _cap("sqli_extract", reduces=["Finding:sqli"])}
        registry = VulnRegistry([
            VulnDefinition(
                id="sqli_error",
                name="SQL Injection",
                category="sqli",
                verification_plugins=["sqli_extract"],
                verification_techniques=["error_based"],  # only 1 technique
            ),
        ])
        confirmer = FindingConfirmer(caps, vuln_registry=registry)
        reval = ReValidator(confirmer, vuln_registry=registry)

        finding = _finding(title="SQLi", category="sqli")
        plans = reval.plan_revalidation(finding)
        assert plans[0].strategy == RevalidationStrategy.DIFFERENT_PAYLOAD

    def test_plan_repeat_fallback(self):
        caps = {"unrelated": _cap("unrelated")}
        confirmer = FindingConfirmer(caps)
        reval = ReValidator(confirmer)

        finding = _finding(title="Unknown vuln")
        plans = reval.plan_revalidation(finding)
        assert plans[0].strategy == RevalidationStrategy.REPEAT
        assert plans[0].suggested_plugins == []

    def test_select_plugins(self):
        caps = {"sqli_extract": _cap("sqli_extract", reduces=["Finding:sqli"])}
        confirmer = FindingConfirmer(caps, vuln_registry=_registry_with_techniques())
        reval = ReValidator(confirmer, vuln_registry=_registry_with_techniques())

        finding = _finding(title="SQLi", category="sqli")
        plans = reval.plan_revalidation(finding)
        plugins = reval.select_plugins(plans[0])
        assert "sqli_extract" in plugins

    def test_plan_includes_host(self):
        caps = {"sqli_extract": _cap("sqli_extract", reduces=["Finding:sqli"])}
        confirmer = FindingConfirmer(caps, vuln_registry=_registry_with_techniques())
        reval = ReValidator(confirmer, vuln_registry=_registry_with_techniques())

        finding = _finding(host="target.com", title="SQLi", category="sqli")
        plans = reval.plan_revalidation(finding)
        assert plans[0].target_host == "target.com"

    def test_select_plugins_empty_for_repeat(self):
        caps = {}
        confirmer = FindingConfirmer(caps)
        reval = ReValidator(confirmer)

        finding = _finding(title="Unknown")
        plans = reval.plan_revalidation(finding)
        plugins = reval.select_plugins(plans[0])
        assert plugins == []
