"""Capability selection — match gaps to capabilities and pick a batch."""

from __future__ import annotations

from basilisk.capabilities.capability import Capability
from basilisk.core.pipeline import _is_domain_only_plugin, _is_ip_or_local
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
    "forms": ["Endpoint", "Finding"],
    "vulnerability_testing": ["Finding", "Vulnerability", "Finding:sqli", "Finding:xss"],
    "host_vulnerability_testing": ["Finding", "Vulnerability"],
    "service_exploitation": ["Finding", "Vulnerability", "Credential", "Technology"],
    "credential_exploitation": ["Credential", "Finding"],
    "version": ["Vulnerability", "Finding"],
    "confirmation": [],  # any capability that targets this entity
    "attack_path": ["Finding", "Vulnerability", "Credential", "Endpoint"],
    "finding_verification": ["Finding", "Vulnerability"],
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

        # Pre-compute which host entity IDs are IPs/localhost
        ip_host_ids: set[str] = set()
        for entity in graph.query(EntityType.HOST):
            host = entity.data.get("host", "")
            if _is_ip_or_local(host):
                ip_host_ids.add(entity.id)

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

                # Skip domain-only plugins for IP/localhost targets
                if gap.entity.id in ip_host_ids and _is_domain_only_plugin(cap.plugin_name):
                    continue

                # Dedup: for Endpoint entities, use (cap, host) because
                # pentesting plugins scan ALL endpoints on a host in one run
                if gap.entity.type == EntityType.ENDPOINT:
                    host = gap.entity.data.get("host", gap.entity.id)
                    key = (cap.name, host)
                else:
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
            # For Endpoint entities, dedup by (plugin, host) not (plugin, entity)
            if sc.target_entity.type == EntityType.ENDPOINT:
                host = sc.target_entity.data.get("host", sc.target_entity.id)
                key = (sc.capability.plugin_name, host)
            else:
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
                # Check service subtype (e.g. "Service:redis" must match redis)
                if ":" in req:
                    svc_type = req.split(":", 1)[1]
                    if not _matches_service_type(entity, svc_type):
                        return False
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
                    if sub == "params" and not entity.data.get("has_params") \
                            and not entity.data.get("scan_path"):
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
                # Check subtype (e.g. "Technology:waf")
                if ":" in req:
                    sub = req.split(":", 1)[1]
                    if sub == "waf" and not entity.data.get("is_waf"):
                        return False
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
    banner = str(service_entity.data.get("banner", "")).lower()

    if svc_type == "http":
        return (
            port in (80, 443, 3000, 4280, 5000, 8000, 8080, 8180, 8280, 8443, 8888, 9090, 9200)
            or "http" in service_name
            or any(kw in banner for kw in ("http/", "apache", "nginx", "iis"))
        )
    if svc_type == "https":
        return port in (443, 8443) or protocol == "https"
    if svc_type == "ssh":
        return port == 22 or "ssh" in service_name or "ssh" in banner
    if svc_type == "ftp":
        return port == 21 or "ftp" in service_name
    if svc_type == "smb":
        return port in (445, 139) or "smb" in service_name or "samba" in banner
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
    if svc_type == "postgres":
        return port == 5432 or "postgres" in service_name
    if svc_type == "mongodb":
        return port == 27017 or "mongo" in service_name
    if svc_type == "memcached":
        return port == 11211 or "memcache" in service_name
    if svc_type == "elasticsearch":
        return port == 9200 or "elastic" in service_name

    return svc_type in service_name
