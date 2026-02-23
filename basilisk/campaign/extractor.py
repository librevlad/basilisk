"""Extract campaign data from a KnowledgeGraph and Decision history."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from basilisk.campaign.models import (
    PluginEfficacy,
    ServiceRecord,
    TargetProfile,
    TechFingerprint,
    TechRecord,
)
from basilisk.knowledge.entities import EntityType
from basilisk.knowledge.relations import RelationType

if TYPE_CHECKING:
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.memory.history import History


def extract_target_profiles(graph: KnowledgeGraph) -> list[TargetProfile]:
    """Build TargetProfile for every HOST entity in the graph."""
    now = datetime.now(UTC)
    profiles: list[TargetProfile] = []

    for host_entity in graph.hosts():
        host = host_entity.data.get("host", "")
        if not host:
            continue

        # Collect services via EXPOSES relations (neighbors returns entities)
        services: list[ServiceRecord] = []
        for svc in graph.neighbors(host_entity.id, RelationType.EXPOSES):
            if svc.type == EntityType.SERVICE:
                services.append(ServiceRecord(
                    port=svc.data.get("port", 0),
                    protocol=svc.data.get("protocol", "tcp"),
                    service=svc.data.get("service", ""),
                ))

        # Collect technologies via RUNS relations
        technologies: list[TechRecord] = []
        for tech in graph.neighbors(host_entity.id, RelationType.RUNS):
            if tech.type == EntityType.TECHNOLOGY:
                technologies.append(TechRecord(
                    name=tech.data.get("name", ""),
                    version=tech.data.get("version", ""),
                    is_cms=tech.data.get("is_cms", False),
                    is_waf=tech.data.get("is_waf", False),
                ))

        # Count endpoints
        endpoints_count = sum(
            1 for ep in graph.neighbors(host_entity.id, RelationType.HAS_ENDPOINT)
            if ep.type == EntityType.ENDPOINT
        )

        # Count findings (reverse: FINDING -> HOST via RELATES_TO)
        finding_severities: dict[str, int] = {}
        findings_count = 0
        for f in graph.reverse_neighbors(host_entity.id, RelationType.RELATES_TO):
            if f.type == EntityType.FINDING:
                findings_count += 1
                sev = f.data.get("severity", "info").upper()
                finding_severities[sev] = finding_severities.get(sev, 0) + 1

        profiles.append(TargetProfile(
            host=host,
            last_audited=now,
            known_services=services,
            known_technologies=technologies,
            known_endpoints_count=endpoints_count,
            known_findings_count=findings_count,
            finding_severities=finding_severities,
        ))

    return profiles


def extract_plugin_efficacy(history: History) -> list[PluginEfficacy]:
    """Build PluginEfficacy records from Decision history."""
    stats: dict[str, PluginEfficacy] = {}

    for decision in history.decisions:
        plugin = decision.chosen_plugin
        if not plugin:
            continue

        if plugin not in stats:
            stats[plugin] = PluginEfficacy(plugin_name=plugin)
        eff = stats[plugin]

        eff.total_runs += 1
        new_ents = decision.outcome_new_entities or 0
        findings = decision.outcome_observations or 0
        duration = decision.outcome_duration or 0.0

        eff.total_new_entities += new_ents
        eff.total_findings += findings
        eff.total_runtime += duration

        if new_ents > 0 or (decision.outcome_confidence_delta or 0.0) > 0.01:
            eff.total_successes += 1

    return list(stats.values())


def extract_tech_fingerprints(graph: KnowledgeGraph) -> list[TechFingerprint]:
    """Group technologies by base domain."""
    now = datetime.now(UTC)
    domain_techs: dict[str, set[str]] = {}

    for tech_entity in graph.technologies():
        host = tech_entity.data.get("host", "")
        name = tech_entity.data.get("name", "")
        if not host or not name:
            continue
        base = _extract_base_domain(host)
        domain_techs.setdefault(base, set()).add(name.lower())

    return [
        TechFingerprint(
            base_domain=domain,
            technologies=sorted(techs),
            observation_count=1,
            last_seen=now,
        )
        for domain, techs in domain_techs.items()
    ]


def _extract_base_domain(host: str) -> str:
    """Extract the base domain (last two labels) from a hostname."""
    parts = host.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host
