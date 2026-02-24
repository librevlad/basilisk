"""Coverage tracker — per-host per-category audit coverage tracking."""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from basilisk.knowledge.vulns.registry import VulnRegistry

logger = logging.getLogger(__name__)

# Default vuln categories to track (used when no VulnRegistry available)
DEFAULT_CATEGORIES: list[str] = [
    "sqli", "xss", "ssti", "ssrf", "lfi", "rce", "nosqli", "xxe",
    "csrf", "cors", "jwt", "idor", "open_redirect", "crlf",
    "http_smuggling", "cache_poison", "path_traversal", "upload",
    "deserialization", "auth_bypass", "default_creds", "git_exposure",
    "sensitive_files", "container_escape", "container_misconfig", "pp",
]


class VulnCategoryStatus(StrEnum):
    """Status of a vulnerability category for a specific host."""

    UNTESTED = "untested"
    TESTED = "tested"
    DETECTED = "detected"
    VERIFIED = "verified"


class HostCoverage(BaseModel):
    """Coverage state for a single host."""

    host: str
    categories_tested: dict[str, VulnCategoryStatus] = Field(default_factory=dict)
    plugins_executed: list[str] = Field(default_factory=list)
    findings_count: int = 0
    verified_count: int = 0


# Map plugin names to vuln categories they cover
_PLUGIN_CATEGORY_MAP: dict[str, list[str]] = {
    "sqli_basic": ["sqli"], "sqli_advanced": ["sqli"],
    "xss_basic": ["xss"], "xss_advanced": ["xss"], "xss_dom": ["xss"],
    "ssti_check": ["ssti"], "ssti_verify": ["ssti"],
    "ssrf_check": ["ssrf"], "ssrf_advanced": ["ssrf"],
    "lfi_check": ["lfi"], "path_traversal": ["path_traversal", "lfi"],
    "command_injection": ["rce"],
    "nosqli_check": ["nosqli"], "nosqli_verify": ["nosqli"],
    "xxe_check": ["xxe"],
    "csrf_check": ["csrf"],
    "cors_scan": ["cors"], "cors_exploit": ["cors"],
    "jwt_attack": ["jwt"],
    "idor_check": ["idor"], "idor_exploit": ["idor"],
    "open_redirect": ["open_redirect"],
    "crlf_injection": ["crlf"],
    "http_smuggling": ["http_smuggling"],
    "cache_poison": ["cache_poison"],
    "file_upload_check": ["upload"],
    "deserialization_check": ["deserialization"],
    "auth_bypass": ["auth_bypass"],
    "default_creds": ["default_creds"],
    "git_exposure": ["git_exposure"],
    "sensitive_files": ["sensitive_files"],
    "container_config_audit": ["container_misconfig"],
    "container_escape_probe": ["container_escape"],
    "prototype_pollution": ["pp"],
    "param_tampering": ["param_tampering"],
}


class CoverageTracker:
    """Tracks per-host per-category vulnerability testing coverage.

    Records which plugins have been executed, which categories have been
    tested, and the overall audit coverage percentage.
    """

    def __init__(self, vuln_registry: VulnRegistry | None = None) -> None:
        self._host_coverage: dict[str, HostCoverage] = {}
        self._vuln_registry = vuln_registry
        self._categories = (
            vuln_registry.categories() if vuln_registry else DEFAULT_CATEGORIES
        )

    def _ensure_host(self, host: str) -> HostCoverage:
        """Get or create coverage record for a host."""
        if host not in self._host_coverage:
            self._host_coverage[host] = HostCoverage(host=host)
        return self._host_coverage[host]

    def record_execution(self, plugin_name: str, host: str, category: str = "") -> None:
        """Record that a plugin was executed against a host."""
        cov = self._ensure_host(host)
        if plugin_name not in cov.plugins_executed:
            cov.plugins_executed.append(plugin_name)

        # Determine categories covered by this plugin
        categories = [category] if category else []
        if not categories:
            categories = _PLUGIN_CATEGORY_MAP.get(plugin_name, [])

        for cat in categories:
            if (
                cat not in cov.categories_tested
                or cov.categories_tested[cat] == VulnCategoryStatus.UNTESTED
            ):
                cov.categories_tested[cat] = VulnCategoryStatus.TESTED

    def record_finding(self, host: str, category: str, *, verified: bool = False) -> None:
        """Record that a finding was detected (and optionally verified)."""
        cov = self._ensure_host(host)
        cov.findings_count += 1

        if category:
            if verified:
                cov.categories_tested[category] = VulnCategoryStatus.VERIFIED
                cov.verified_count += 1
            elif cov.categories_tested.get(category) != VulnCategoryStatus.VERIFIED:
                cov.categories_tested[category] = VulnCategoryStatus.DETECTED

    def record_verification(self, host: str, category: str) -> None:
        """Record that a category's findings have been verified."""
        cov = self._ensure_host(host)
        if category:
            cov.categories_tested[category] = VulnCategoryStatus.VERIFIED
            cov.verified_count += 1

    def host_coverage(self, host: str) -> HostCoverage:
        """Get coverage state for a specific host."""
        return self._ensure_host(host)

    def overall_coverage(self) -> float:
        """Compute overall coverage as fraction of categories tested across all hosts.

        Returns 0.0 to 1.0.
        """
        if not self._host_coverage or not self._categories:
            return 0.0

        total_slots = len(self._host_coverage) * len(self._categories)
        tested_slots = 0

        for cov in self._host_coverage.values():
            for cat in self._categories:
                status = cov.categories_tested.get(cat, VulnCategoryStatus.UNTESTED)
                if status != VulnCategoryStatus.UNTESTED:
                    tested_slots += 1

        return tested_slots / total_slots if total_slots > 0 else 0.0

    def untested_categories(self, host: str) -> list[str]:
        """Return categories not yet tested for a host."""
        cov = self._ensure_host(host)
        return [
            cat for cat in self._categories
            if cov.categories_tested.get(cat, VulnCategoryStatus.UNTESTED)
            == VulnCategoryStatus.UNTESTED
        ]

    def coverage_snapshot(self) -> dict[str, Any]:
        """Return a summary snapshot suitable for reporting."""
        return {
            "hosts_tracked": len(self._host_coverage),
            "total_categories": len(self._categories),
            "overall_coverage": round(self.overall_coverage(), 3),
            "per_host": {
                host: {
                    "tested": sum(
                        1 for s in cov.categories_tested.values()
                        if s != VulnCategoryStatus.UNTESTED
                    ),
                    "detected": sum(
                        1 for s in cov.categories_tested.values()
                        if s in (VulnCategoryStatus.DETECTED, VulnCategoryStatus.VERIFIED)
                    ),
                    "verified": sum(
                        1 for s in cov.categories_tested.values()
                        if s == VulnCategoryStatus.VERIFIED
                    ),
                    "findings": cov.findings_count,
                    "plugins_executed": len(cov.plugins_executed),
                }
                for host, cov in self._host_coverage.items()
            },
        }
