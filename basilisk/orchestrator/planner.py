"""Missing knowledge rules — identifies gaps in the knowledge graph."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.relations import RelationType

if TYPE_CHECKING:
    from basilisk.knowledge.graph import KnowledgeGraph


@dataclass
class KnowledgeGap:
    """A gap in knowledge that a capability could fill."""

    entity: Entity
    missing: str          # what's unknown: "services", "technology", "endpoints", etc.
    priority: float       # base priority (higher = more urgent)
    description: str      # human explanation


class Planner:
    """Rule-based engine that identifies what we don't know yet.

    Each rule function takes a graph, returns gaps found.
    Rules are checked in priority order.
    """

    def find_gaps(self, graph: KnowledgeGraph) -> list[KnowledgeGap]:
        """Run all rules and collect gaps."""
        gaps: list[KnowledgeGap] = []
        for rule in _RULES:
            gaps.extend(rule(graph))
        # Sort by priority descending
        gaps.sort(key=lambda g: g.priority, reverse=True)
        return gaps


def _host_without_services(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """Host exists but has no SERVICE relations → need port_scan."""
    gaps = []
    for host in graph.hosts():
        services = graph.neighbors(host.id, RelationType.EXPOSES)
        if not services and "services_checked" not in host.data:
            gaps.append(KnowledgeGap(
                entity=host,
                missing="services",
                priority=10.0,
                description=f"Host {host.data.get('host', '?')} has no known services",
            ))
    return gaps


def _host_without_dns(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """Host exists but has no DNS data → need dns_enum."""
    gaps = []
    for host in graph.hosts():
        if not host.data.get("dns_records") and host.data.get("type") != "ip":
            gaps.append(KnowledgeGap(
                entity=host,
                missing="dns",
                priority=8.0,
                description=f"Host {host.data.get('host', '?')} has no DNS data",
            ))
    return gaps


def _http_service_without_tech(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """HTTP service exists but no TECHNOLOGY detected → need tech_detect."""
    gaps = []
    for host in graph.hosts():
        services = graph.neighbors(host.id, RelationType.EXPOSES)
        has_http_service = any(
            _is_http_service(svc) for svc in services
        )
        if has_http_service:
            techs = graph.neighbors(host.id, RelationType.RUNS)
            if not techs and "tech_checked" not in host.data:
                gaps.append(KnowledgeGap(
                    entity=host,
                    missing="technology",
                    priority=7.0,
                    description=f"HTTP service on {host.data.get('host', '?')} — no tech detected",
                ))
    return gaps


def _http_service_without_endpoints(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """HTTP service exists but no ENDPOINT entities → need web_crawler/dir_brute."""
    gaps = []
    for host in graph.hosts():
        services = graph.neighbors(host.id, RelationType.EXPOSES)
        has_http = any(_is_http_service(svc) for svc in services)
        if has_http:
            endpoints = graph.neighbors(host.id, RelationType.HAS_ENDPOINT)
            if not endpoints and "endpoints_checked" not in host.data:
                gaps.append(KnowledgeGap(
                    entity=host,
                    missing="endpoints",
                    priority=6.0,
                    description=f"HTTP on {host.data.get('host', '?')} — no endpoints discovered",
                ))
    return gaps


def _endpoint_without_testing(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """Endpoints with params exist but no security findings → need vuln testing."""
    gaps = []
    for ep in graph.endpoints():
        if ep.data.get("has_params") or ep.data.get("is_api"):
            # Check if any Finding relates to this endpoint's host
            host = ep.data.get("host", "")
            if host:
                findings = graph.query(EntityType.FINDING, host=host)
                vuln_tested = any(
                    f.data.get("severity") in ("high", "critical", "medium")
                    for f in findings
                )
                if not vuln_tested and "vuln_tested" not in ep.data:
                    gaps.append(KnowledgeGap(
                        entity=ep,
                        missing="vulnerability_testing",
                        priority=5.0,
                        description=f"Endpoint {ep.data.get('path', '?')} on {host} untested",
                    ))
    return gaps


def _technology_without_version(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """Technology exists but version unknown → need version_detect."""
    gaps = []
    for tech in graph.technologies():
        if not tech.data.get("version") and "version_checked" not in tech.data:
            gaps.append(KnowledgeGap(
                entity=tech,
                missing="version",
                priority=4.0,
                description=f"Technology {tech.data.get('name', '?')} — version unknown",
            ))
    return gaps


def _low_confidence_entity(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """Any entity with confidence < 0.5 → recheck."""
    gaps = []
    for entity in graph.all_entities():
        if entity.confidence < 0.5 and entity.type in (EntityType.HOST, EntityType.SERVICE):
            gaps.append(KnowledgeGap(
                entity=entity,
                missing="confirmation",
                priority=3.0,
                description=f"Low confidence ({entity.confidence:.2f}) {entity.type}",
            ))
    return gaps


def _is_http_service(entity: Entity) -> bool:
    """Check if a Service entity is HTTP/HTTPS."""
    port = entity.data.get("port")
    protocol = entity.data.get("protocol", "")
    service_name = entity.data.get("service", "")

    if port in (80, 443, 8080, 8443):
        return True
    if protocol in ("http", "https"):
        return True
    return bool(service_name and "http" in service_name.lower())


_RULES = [
    _host_without_services,
    _host_without_dns,
    _http_service_without_tech,
    _http_service_without_endpoints,
    _endpoint_without_testing,
    _technology_without_version,
    _low_confidence_entity,
]
