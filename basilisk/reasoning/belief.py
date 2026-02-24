"""Evidence aggregator — multi-source belief revision within a step."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.reasoning.hypothesis import HypothesisEngine

logger = logging.getLogger(__name__)

# Map plugin names to source families for independence weighting
SOURCE_FAMILIES: dict[str, str] = {
    # DNS
    "dns_enum": "dns",
    "dns_zone_transfer": "dns",
    "whois": "dns",
    "reverse_ip": "dns",
    "asn_lookup": "dns",
    # Network scanning
    "port_scan": "network_scan",
    "service_detect": "network_scan",
    "shodan_lookup": "network_scan",
    # HTTP probing
    "tech_detect": "http_probe",
    "waf_detect": "http_probe",
    "http_headers": "http_probe",
    "cms_detect": "http_probe",
    "favicon_hash": "http_probe",
    "web_crawler": "http_probe",
    "robots_parser": "http_probe",
    "sitemap_parser": "http_probe",
    "cors_scan": "http_probe",
    "cdn_detect": "http_probe",
    "csp_analyzer": "http_probe",
    # Exploitation
    "sqli_basic": "exploit",
    "sqli_advanced": "exploit",
    "xss_basic": "exploit",
    "xss_advanced": "exploit",
    "xss_dom": "exploit",
    "ssrf_check": "exploit",
    "ssti_basic": "exploit",
    "ssti_advanced": "exploit",
    "command_injection": "exploit",
    "lfi_check": "exploit",
    "jwt_attack": "exploit",
    # Config / leak
    "git_exposure": "config_leak",
    "sensitive_files": "config_leak",
    "js_secret_scan": "config_leak",
    "default_creds": "config_leak",
    "container_config_audit": "config_leak",
    # Verification
    "ssti_verify": "verification",
    "nosqli_verify": "verification",
    "container_verification": "verification",
    "cors_exploit": "verification",
    # Additional exploit/verification plugins
    "ssrf_advanced": "exploit",
    "sqli_extract": "exploit",
    "lfi_harvest": "exploit",
    "file_upload_bypass": "exploit",
    "version_detect": "http_probe",
    "waf_bypass": "exploit",
    "graphql_exploit": "exploit",
    "pp_exploit": "exploit",
    "idor_exploit": "exploit",
}


def get_source_family(plugin_name: str) -> str:
    """Get the source family for a plugin, defaulting to 'general'."""
    return SOURCE_FAMILIES.get(plugin_name, "general")


class EvidenceAggregator:
    """Track evidence across a step and apply belief revision.

    After a step, entities observed by 2+ independent source families
    get a confidence bonus. Contradictions get a penalty.
    """

    def __init__(
        self,
        graph: KnowledgeGraph,
        hypothesis_engine: HypothesisEngine | None = None,
    ) -> None:
        self._graph = graph
        self._hypothesis_engine = hypothesis_engine
        # Per-step evidence: entity_id → [(plugin, family, delta)]
        self._step_evidence: dict[str, list[tuple[str, str, float]]] = defaultdict(list)

    def record_evidence(
        self,
        entity_id: str,
        source_plugin: str,
        confidence_delta: float,
    ) -> None:
        """Record an evidence observation for this step."""
        family = get_source_family(source_plugin)
        self._step_evidence[entity_id].append((source_plugin, family, confidence_delta))

    def revise_beliefs(self) -> list[tuple[str, float, float]]:
        """Apply belief revision based on accumulated step evidence.

        For entities with evidence from 2+ source families:
        - Independence bonus: +0.05 per additional family (max +0.15)
        - Contradiction: if families disagree on direction, -0.1

        Returns list of (entity_id, old_confidence, new_confidence).
        """
        revisions: list[tuple[str, float, float]] = []

        for entity_id, evidence_list in self._step_evidence.items():
            entity = self._graph.get(entity_id)
            if entity is None:
                continue

            # Group by source family
            families: dict[str, list[float]] = defaultdict(list)
            for _plugin, family, delta in evidence_list:
                families[family].append(delta)

            family_count = len(families)
            if family_count < 2:
                continue

            old_conf = entity.confidence

            # Independence bonus: +0.05 per extra family, max +0.15
            independence_bonus = min((family_count - 1) * 0.05, 0.15)

            # Check for contradictions (some families positive, some negative)
            positive_families = sum(
                1 for deltas in families.values() if sum(deltas) > 0
            )
            negative_families = sum(
                1 for deltas in families.values() if sum(deltas) < 0
            )
            contradiction_penalty = -0.1 if positive_families > 0 and negative_families > 0 else 0.0

            adjustment = independence_bonus + contradiction_penalty
            entity.confidence = max(0.1, min(1.0, entity.confidence + adjustment))

            if entity.confidence != old_conf:
                revisions.append((entity_id, old_conf, entity.confidence))

        return revisions

    def reset_step(self) -> None:
        """Clear step evidence for the next iteration."""
        self._step_evidence.clear()
