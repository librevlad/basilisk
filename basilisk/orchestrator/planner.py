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


def _http_endpoints_without_forms(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """HTTP endpoints exist but no forms discovered → need form_analyzer/web_crawler.

    When scan_paths are injected, endpoints exist but forms haven't been analyzed.
    form_analyzer discovers HTML form fields (names, methods) needed by pentesting plugins.
    """
    gaps = []
    for host in graph.hosts():
        services = graph.neighbors(host.id, RelationType.EXPOSES)
        has_http = any(_is_http_service(svc) for svc in services)
        if not has_http:
            continue
        endpoints = graph.neighbors(host.id, RelationType.HAS_ENDPOINT)
        if endpoints and "forms_checked" not in host.data:
            gaps.append(KnowledgeGap(
                entity=host,
                missing="forms",
                priority=5.5,
                description=f"HTTP on {host.data.get('host', '?')} — endpoints, no forms",
            ))
    return gaps


def _endpoint_without_testing(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """Endpoints with params exist but not yet tested → need vuln testing.

    Only create ONE gap per host (pentesting plugins scan all endpoints
    on a host in a single run). Skip hosts where testing already happened.
    Waits for form analysis to complete (forms_checked) so pentesting plugins
    have full injection point data from form_analyzer.
    """
    gaps = []
    seen_hosts: set[str] = set()
    # Pre-check which hosts have forms_checked
    hosts_forms_done: set[str] = set()
    for host in graph.hosts():
        if "forms_checked" in host.data:
            hosts_forms_done.add(host.data.get("host", ""))
    for ep in graph.endpoints():
        has_injectable = (
            ep.data.get("has_params") or ep.data.get("is_api")
            or ep.data.get("scan_path") or ep.data.get("is_upload")
        )
        if not has_injectable:
            continue
        host = ep.data.get("host", "")
        if host in seen_hosts:
            continue
        # Wait for form analysis before pentesting (forms provide better injection points).
        # Only block if host has HTTP services (meaning form_analyzer can run) AND
        # scan_path endpoints exist AND forms not yet analyzed.
        if host and host not in hosts_forms_done and ep.data.get("scan_path"):
            host_id = Entity.make_id(EntityType.HOST, host=host)
            host_ent = graph.get(host_id)
            if host_ent and any(
                _is_http_service(s)
                for s in graph.neighbors(host_id, RelationType.EXPOSES)
            ):
                continue
        seen_hosts.add(host)
        gaps.append(KnowledgeGap(
            entity=ep,
            missing="vulnerability_testing",
            priority=5.0,
            description=f"Endpoint {ep.data.get('path', '?')} on {host} needs testing",
        ))
    return gaps


def _http_host_without_vuln_testing(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """HTTP service exists → host needs host-level vulnerability testing.

    Triggers plugins like git_exposure, jwt_attack, cors_exploit,
    sensitive_files, default_creds, cache_poison, http_smuggling, etc.
    The gap fires every step; the loop's was_executed fingerprint tracking
    prevents re-running the same plugin, and terminates with no_candidates
    when all matching plugins have been executed.
    """
    gaps = []
    for host in graph.hosts():
        services = graph.neighbors(host.id, RelationType.EXPOSES)
        has_http = any(_is_http_service(svc) for svc in services)
        if has_http:
            gaps.append(KnowledgeGap(
                entity=host,
                missing="host_vulnerability_testing",
                priority=4.5,
                description=f"Host {host.data.get('host', '?')} needs host-level vuln testing",
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


def _credential_without_exploitation(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """Credentials exist → need credential_reuse / credential_spray testing."""
    gaps = []
    for cred in graph.query(EntityType.CREDENTIAL):
        host = cred.data.get("host", "")
        gaps.append(KnowledgeGap(
            entity=cred,
            missing="credential_exploitation",
            priority=7.5,
            description=f"Credential '{cred.data.get('username', '?')}'"
            f" on {host} — not yet exploited",
        ))
    return gaps


def _service_without_exploitation(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """Non-HTTP service exists but hasn't been tested → need service-specific checks.

    Triggers plugins like redis_exploit, mysql_exploit, ssh_brute, ftp_anon,
    smb_enum, service_brute, port_vuln_check, etc.
    Each service gets its own gap so service-specific plugins can match.
    """
    gaps = []
    for svc in graph.services():
        if _is_http_service(svc):
            continue
        if "service_tested" in svc.data:
            continue
        port = svc.data.get("port", "?")
        host = svc.data.get("host", "?")
        service_name = svc.data.get("service", "unknown")
        gaps.append(KnowledgeGap(
            entity=svc,
            missing="service_exploitation",
            priority=6.5,
            description=f"Service {service_name}:{port} on {host} needs exploitation testing",
        ))
    return gaps


def _is_http_service(entity: Entity) -> bool:
    """Check if a Service entity is HTTP/HTTPS."""
    port = entity.data.get("port")
    protocol = entity.data.get("protocol", "")
    service_name = entity.data.get("service", "")
    banner = str(entity.data.get("banner", "")).lower()

    if port in (80, 443, 3000, 4280, 5000, 8000, 8080, 8180, 8280, 8443, 8888, 9090, 9200):
        return True
    if protocol in ("http", "https"):
        return True
    if service_name and "http" in service_name.lower():
        return True
    # Detect HTTP from banner (e.g. "HTTP/1.1", "Apache", "nginx")
    return any(kw in banner for kw in ("http/", "apache", "nginx", "iis"))


def _finding_without_verification(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """High/critical findings without verification → need verify plugin.

    Only fires for findings with severity high/critical that are not yet verified
    and have confidence below 0.95 (probabilistic merge hasn't confirmed them).
    """
    gaps = []
    for finding in graph.findings():
        severity = finding.data.get("severity", "info")
        if severity not in ("high", "critical"):
            continue
        if finding.data.get("verified"):
            continue
        if finding.confidence >= 0.95:
            continue
        title = finding.data.get("title", "?")
        host = finding.data.get("host", "?")
        gaps.append(KnowledgeGap(
            entity=finding,
            missing="finding_verification",
            priority=6.0,
            description=f"Finding '{title}' on {host} needs verification",
        ))
    return gaps


def _attack_path_gaps(graph: KnowledgeGraph) -> list[KnowledgeGap]:
    """Suggest actions from available attack paths that haven't been executed yet.

    When an attack path's preconditions are met, create gaps for host entities
    to drive execution of path actions.
    """
    from basilisk.orchestrator.attack_paths import find_available_paths

    gaps = []
    available = find_available_paths(graph)
    hosts = graph.hosts()
    if not hosts:
        return gaps

    for path in available:
        # Use first host as representative entity
        host = hosts[0]
        gaps.append(KnowledgeGap(
            entity=host,
            missing="attack_path",
            priority=min(path.risk, 8.0),
            description=f"Attack path '{path.name}' available — "
            f"actions: {', '.join(path.actions[:3])}",
        ))

    return gaps


_RULES = [
    _host_without_services,
    _host_without_dns,
    _http_service_without_tech,
    _http_service_without_endpoints,
    _http_endpoints_without_forms,
    _endpoint_without_testing,
    _http_host_without_vuln_testing,
    _service_without_exploitation,
    _credential_without_exploitation,
    _technology_without_version,
    _low_confidence_entity,
    _finding_without_verification,
    _attack_path_gaps,
]
