"""Capability selection — match gaps to capabilities and pick a batch."""

from __future__ import annotations

from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import RelationType
from basilisk.orchestrator.planner import KnowledgeGap
from basilisk.scoring.scorer import ScoredCapability

# Map gap.missing → required capability produces_knowledge patterns
_GAP_TO_PRODUCES: dict[str, list[str]] = {
    "services": ["Service"],
    "dns": ["Host:dns_data"],
    "technology": ["Technology"],
    "endpoints": ["Endpoint"],
    "vulnerability_testing": ["Finding", "Vulnerability", "Finding:sqli", "Finding:xss"],
    "version": ["Vulnerability", "Finding"],
    "confirmation": [],  # any capability that targets this entity
}


class Selector:
    """Match knowledge gaps to capabilities, then pick a non-overlapping batch."""

    def __init__(self, capabilities: dict[str, Capability]) -> None:
        self.capabilities = capabilities

    def match(
        self, gaps: list[KnowledgeGap], graph: KnowledgeGraph,
    ) -> list[tuple[Capability, Entity]]:
        """For each gap, find capabilities that can fill it.

        Returns (capability, target_entity) pairs.
        """
        candidates: list[tuple[Capability, Entity]] = []
        seen: set[tuple[str, str]] = set()

        for gap in gaps:
            produces_patterns = _GAP_TO_PRODUCES.get(gap.missing, [])

            for cap in self.capabilities.values():
                # Check if capability produces what the gap needs
                if produces_patterns and not _produces_match(cap, produces_patterns):
                    continue

                # For "confirmation" gaps, any capability that takes this entity type
                if (
                    gap.missing == "confirmation"
                    and not _requires_entity_type(cap, gap.entity.type)
                ):
                    continue

                # Check if capability requirements are satisfied
                if not _requirements_met(cap, gap.entity, graph):
                    continue

                key = (cap.name, gap.entity.id)
                if key not in seen:
                    seen.add(key)
                    candidates.append((cap, gap.entity))

        return candidates

    @staticmethod
    def pick(scored: list[ScoredCapability], budget: int = 5) -> list[ScoredCapability]:
        """Select top-N non-overlapping capabilities.

        Greedy: take highest-scored, skip if same plugin+entity already picked.
        """
        chosen: list[ScoredCapability] = []
        used: set[tuple[str, str]] = set()

        for sc in scored:
            if len(chosen) >= budget:
                break
            key = (sc.capability.plugin_name, sc.target_entity.id)
            if key in used:
                continue
            used.add(key)
            chosen.append(sc)

        return chosen


def _produces_match(cap: Capability, patterns: list[str]) -> bool:
    """Check if capability produces anything matching the patterns."""
    for prod in cap.produces_knowledge:
        for pattern in patterns:
            if ":" in pattern:
                # Exact match with subtype: "Finding:sqli"
                if prod == pattern or prod.startswith(pattern.split(":")[0]):
                    return True
            elif prod == pattern or prod.startswith(pattern):
                return True
    return False


def _requires_entity_type(cap: Capability, entity_type: EntityType) -> bool:
    """Check if capability requires this entity type."""
    type_str = entity_type.value.capitalize()
    return any(
        req == type_str or req.startswith(type_str)
        for req in cap.requires_knowledge
    )


def _requirements_met(cap: Capability, entity: Entity, graph: KnowledgeGraph) -> bool:
    """Check if the graph has everything this capability needs.

    For Host-targeted capabilities: just need the Host entity to exist.
    For Service-targeted: need a Service connected to a Host.
    For Endpoint-targeted: need an Endpoint connected to a Host.
    For Technology-targeted: need a Technology connected to a Host.
    """
    for req in cap.requires_knowledge:
        base_type = req.split(":")[0]

        if base_type == "Host":
            if entity.type == EntityType.HOST:
                continue
            # Entity must be connected to a host
            return False

        if base_type == "Service":
            if entity.type == EntityType.SERVICE:
                continue
            # Check if host has services
            if entity.type == EntityType.HOST:
                services = graph.neighbors(entity.id, RelationType.EXPOSES)
                if not services:
                    return False
                # Check for specific service type (e.g. "Service:http")
                if ":" in req:
                    svc_type = req.split(":", 1)[1]
                    if not any(_matches_service_type(s, svc_type) for s in services):
                        return False
                continue
            return False

        if base_type == "Endpoint":
            if entity.type == EntityType.ENDPOINT:
                # Check subtype (e.g. "Endpoint:params")
                if ":" in req:
                    sub = req.split(":", 1)[1]
                    if sub == "params" and not entity.data.get("has_params"):
                        return False
                    if sub == "graphql" and not entity.data.get("is_graphql"):
                        return False
                    if sub == "admin" and not entity.data.get("is_admin"):
                        return False
                continue
            if entity.type == EntityType.HOST:
                endpoints = graph.neighbors(entity.id, RelationType.HAS_ENDPOINT)
                if not endpoints:
                    return False
                continue
            return False

        if base_type == "Technology":
            if entity.type == EntityType.TECHNOLOGY:
                continue
            if entity.type == EntityType.HOST:
                techs = graph.neighbors(entity.id, RelationType.RUNS)
                if not techs:
                    return False
                continue
            return False

        if base_type == "Credential":
            if entity.type == EntityType.CREDENTIAL:
                continue
            # Check if any credentials access this host
            if entity.type == EntityType.HOST:
                creds = graph.reverse_neighbors(entity.id, RelationType.ACCESSES)
                if not creds:
                    return False
                continue
            return False

        if base_type == "Vulnerability":
            if entity.type == EntityType.VULNERABILITY:
                continue
            return False

    return True


def _matches_service_type(service_entity: Entity, svc_type: str) -> bool:
    """Check if a service entity matches a service type like 'http', 'ssh', 'ftp'."""
    port = service_entity.data.get("port")
    protocol = service_entity.data.get("protocol", "")
    service_name = str(service_entity.data.get("service", "")).lower()

    if svc_type == "http":
        return port in (80, 443, 8080, 8443) or "http" in service_name
    if svc_type == "https":
        return port in (443, 8443) or protocol == "https"
    if svc_type == "ssh":
        return port == 22 or "ssh" in service_name
    if svc_type == "ftp":
        return port == 21 or "ftp" in service_name
    if svc_type == "smb":
        return port in (445, 139) or "smb" in service_name
    if svc_type == "redis":
        return port == 6379 or "redis" in service_name
    if svc_type == "mysql":
        return port == 3306 or "mysql" in service_name
    if svc_type == "mssql":
        return port == 1433 or "mssql" in service_name
    if svc_type == "ldap":
        return port in (389, 636) or "ldap" in service_name
    if svc_type == "snmp":
        return port in (161, 162) or "snmp" in service_name
    if svc_type == "nfs":
        return port == 2049 or "nfs" in service_name
    if svc_type == "rpc":
        return port == 111 or "rpc" in service_name
    if svc_type == "winrm":
        return port in (5985, 5986) or "winrm" in service_name

    return svc_type in service_name
