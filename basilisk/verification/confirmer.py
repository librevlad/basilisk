"""Finding confirmer — suggest verifiers and evaluate verification results."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from basilisk.capabilities.capability import Capability
    from basilisk.knowledge.entities import Entity
    from basilisk.knowledge.vulns.registry import VulnRegistry
    from basilisk.models.result import PluginResult

logger = logging.getLogger(__name__)


class ConfirmationResult(BaseModel):
    """Result of evaluating a verification attempt."""

    finding_entity_id: str
    verdict: str = "inconclusive"  # confirmed|likely|false_positive|inconclusive
    confidence_delta: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class FindingConfirmer:
    """Suggests verification plugins for findings and evaluates results.

    Uses two sources to find verifiers:
    1. VulnRegistry.verification_plugins_for(category)
    2. Capabilities with reduces_uncertainty matching the finding category
    """

    def __init__(
        self,
        capabilities: dict[str, Capability],
        vuln_registry: VulnRegistry | None = None,
    ) -> None:
        self._capabilities = capabilities
        self._registry = vuln_registry

    def can_verify(self, finding_entity: Entity) -> bool:
        """True if at least one verification plugin exists for this finding."""
        return len(self.suggest_verifiers(finding_entity)) > 0

    def suggest_verifiers(self, finding_entity: Entity) -> list[str]:
        """Return plugin names that can verify this finding.

        1. Check VulnRegistry for category-specific verifiers
        2. Check capabilities with reduces_uncertainty matching the category
        3. Dedup and return
        """
        category = self._extract_category(finding_entity)
        seen: set[str] = set()
        result: list[str] = []

        # Source 1: VulnRegistry
        if self._registry and category:
            for plugin in self._registry.verification_plugins_for(category):
                if plugin not in seen and plugin in self._capabilities:
                    result.append(plugin)
                    seen.add(plugin)

        # Source 2: Capabilities with matching reduces_uncertainty
        category_pattern = f"Finding:{category}" if category else "Finding"
        for cap in self._capabilities.values():
            if cap.plugin_name in seen:
                continue
            for ru in cap.reduces_uncertainty:
                if ru == category_pattern or (not category and ru.startswith("Finding")):
                    result.append(cap.plugin_name)
                    seen.add(cap.plugin_name)
                    break

        return result

    def evaluate_result(
        self,
        finding_entity: Entity,
        verification_result: PluginResult,
    ) -> ConfirmationResult:
        """Evaluate a verification plugin result against the original finding.

        Heuristics:
        - If verification produced HIGH/CRITICAL findings for same host → confirmed
        - If verification produced findings but lower severity → likely
        - If verification succeeded but found nothing → false_positive
        - Otherwise → inconclusive
        """
        entity_id = finding_entity.id
        original_title = finding_entity.data.get("title", "").lower()

        if not verification_result.ok:
            return ConfirmationResult(finding_entity_id=entity_id)

        evidence = []
        has_high = False
        has_any = False

        for f in verification_result.findings:
            # Finding model has no host; the PluginResult.target has the host
            has_any = True
            evidence.append(f.title)
            if f.severity.value >= 3:  # HIGH or CRITICAL
                has_high = True

        if has_high:
            return ConfirmationResult(
                finding_entity_id=entity_id,
                verdict="confirmed",
                confidence_delta=0.3,
                evidence=evidence,
            )
        if has_any:
            return ConfirmationResult(
                finding_entity_id=entity_id,
                verdict="likely",
                confidence_delta=0.1,
                evidence=evidence,
            )
        if verification_result.ok and not has_any:
            return ConfirmationResult(
                finding_entity_id=entity_id,
                verdict="false_positive",
                confidence_delta=-0.3,
                evidence=[f"Verification plugin found no matching findings for '{original_title}'"],
            )

        return ConfirmationResult(finding_entity_id=entity_id)

    @staticmethod
    def _extract_category(finding_entity: Entity) -> str:
        """Extract vuln category from a finding entity's data."""
        # Try explicit category field
        cat = finding_entity.data.get("category", "")
        if cat:
            return cat

        # Try to infer from title
        title = finding_entity.data.get("title", "").lower()
        for keyword in (
            "sqli", "xss", "ssti", "ssrf", "lfi", "rce", "nosqli", "xxe",
            "csrf", "cors", "jwt", "idor", "crlf", "upload", "deserialization",
        ):
            if keyword in title:
                return keyword

        return ""
