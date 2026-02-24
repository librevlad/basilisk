"""Result adapters — convert between v3 PluginResult and v4 ScenarioResult/Finding."""

from __future__ import annotations

from basilisk.domain.finding import Finding as V4Finding
from basilisk.domain.finding import Proof
from basilisk.domain.scenario import ScenarioResult
from basilisk.models.result import Finding as V3Finding
from basilisk.models.result import PluginResult


class ResultAdapter:
    """Converts between v3 PluginResult and v4 ScenarioResult."""

    @staticmethod
    def to_v4_finding(v3: V3Finding, plugin_name: str = "") -> V4Finding:
        """Convert a v3 Finding to a v4 Finding."""
        proof = None
        if v3.evidence:
            proof = Proof(description=v3.evidence)
        return V4Finding(
            title=v3.title,
            severity=v3.severity,
            description=v3.description,
            proof=proof,
            remediation=v3.remediation,
            tags=frozenset(v3.tags),
            confidence=v3.confidence,
            scenario_name=plugin_name,
        )

    @staticmethod
    def to_scenario_result(result: PluginResult) -> ScenarioResult:
        """Convert a v3 PluginResult to a v4 ScenarioResult."""
        v4_findings = [
            ResultAdapter.to_v4_finding(f, result.plugin) for f in result.findings
        ]
        return ScenarioResult(
            scenario=result.plugin,
            target=result.target,
            findings=v4_findings,
            data=result.data,
            status=result.status,
            duration=result.duration,
            error=result.error,
        )

    @staticmethod
    def to_v3_finding(v4: V4Finding) -> V3Finding:
        """Convert a v4 Finding back to a v3 Finding."""
        evidence = ""
        if v4.proof and v4.proof.description:
            evidence = v4.proof.description
        return V3Finding(
            title=v4.title,
            severity=v4.severity,
            description=v4.description,
            evidence=evidence,
            remediation=v4.remediation,
            tags=list(v4.tags),
            confidence=v4.confidence,
        )

    @staticmethod
    def to_v3_result(result: ScenarioResult) -> PluginResult:
        """Convert a v4 ScenarioResult back to a v3 PluginResult."""
        v3_findings = [ResultAdapter.to_v3_finding(f) for f in result.findings]
        return PluginResult(
            plugin=result.scenario,
            target=result.target,
            findings=v3_findings,
            data=result.data,
            status=result.status,
            duration=result.duration,
            error=result.error,
        )
