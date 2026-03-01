"""Shared helpers for executor and scenario_executor — eliminates duplication."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.relations import RelationType
from basilisk.utils.net import is_ip_or_local

if TYPE_CHECKING:
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.models.result import PluginResult
    from basilisk.models.target import Target


def populate_state(state: dict[str, Any], result: PluginResult) -> None:
    """Populate shared state dict with data pentesting plugins need."""
    if not result.ok:
        return
    host = result.target
    data = result.data

    # crawled_urls
    urls = data.get("crawled_urls", [])
    if urls:
        existing = state.setdefault("crawled_urls", {}).setdefault(host, [])
        existing_set = set(existing)
        for url in urls:
            if url not in existing_set:
                existing.append(url)
                existing_set.add(url)

    # forms → discovered_forms
    forms = data.get("forms", [])
    if forms:
        existing = state.setdefault("discovered_forms", {}).setdefault(host, [])
        existing.extend(forms)

    # api_paths / interesting_paths → discovered_api_paths
    api_paths = data.get("api_paths", []) + data.get("interesting_paths", [])
    if api_paths:
        existing = state.setdefault("discovered_api_paths", {}).setdefault(host, [])
        existing_set = set(existing)
        for p in api_paths:
            if p not in existing_set:
                existing.append(p)
                existing_set.add(p)

    # upload_endpoints → crawled_urls (so exploitation plugins see them)
    upload_eps = data.get("upload_endpoints", [])
    if upload_eps:
        scheme_map = state.get("http_scheme", {})
        scheme = scheme_map.get(host, "http") or "http"
        base = f"{scheme}://{host}"
        existing = state.setdefault("crawled_urls", {}).setdefault(host, [])
        existing_set = set(existing)
        for ep in upload_eps:
            url = f"{base}{ep}" if ep.startswith("/") else ep
            if url not in existing_set:
                existing.append(url)
                existing_set.add(url)

    # waf → waf_map
    waf = data.get("waf", [])
    if waf:
        state.setdefault("waf_map", {})[host] = waf

    # nosqli_tests → state (for nosqli_verify)
    nosqli = data.get("nosqli_tests", [])
    if nosqli:
        state.setdefault("nosqli_tests", []).extend(nosqli)

    # ssti_tests → state (for ssti_verify)
    ssti = data.get("ssti_tests", [])
    if ssti:
        state.setdefault("ssti_tests", []).extend(ssti)

    # technologies → detected_tech (for dir_brute tech-specific extensions)
    techs = data.get("technologies", [])
    if techs:
        names = [t.get("name", t) if isinstance(t, dict) else t for t in techs]
        existing = state.setdefault("detected_tech", {}).setdefault(host, [])
        existing_set = set(existing)
        for n in names:
            if n not in existing_set:
                existing.append(n)
                existing_set.add(n)

    # subdomains → state (for subdomain_bruteforce permutation mode)
    subs = data.get("subdomains", [])
    if subs:
        existing = state.setdefault("subdomains", {}).setdefault(host, [])
        existing_set = set(existing)
        for s in subs:
            if s not in existing_set:
                existing.append(s)
                existing_set.add(s)

    # container_runtimes → state
    runtimes = data.get("container_runtimes", [])
    if runtimes:
        existing = state.setdefault("container_runtimes", {}).setdefault(host, [])
        existing.extend(runtimes)

    # containers → state
    containers = data.get("containers", [])
    if containers:
        existing = state.setdefault("containers", {}).setdefault(host, [])
        existing.extend(containers)


def entity_to_target(entity: Entity, graph: KnowledgeGraph) -> Target:
    """Convert an entity to a Target object for plugin execution.

    Host entities → Target directly, with ports from services in the graph.
    Service/Endpoint/Technology entities → look up the parent Host.
    """
    from basilisk.models.target import Target

    if entity.type == EntityType.HOST:
        target = graph.entity_to_target(entity)
        # Populate target.ports from discovered services
        services = graph.neighbors(entity.id, RelationType.EXPOSES)
        ports = [s.data.get("port") for s in services if s.data.get("port")]
        if ports:
            target.ports = sorted(set(ports))
        return target

    # For non-Host entities, extract host from data
    host = entity.data.get("host", "")
    if host:
        target = Target.ip(host) if is_ip_or_local(host) else Target.domain(host)
        # Populate ports from graph
        host_id = Entity.make_id(EntityType.HOST, host=host)
        services = graph.neighbors(host_id, RelationType.EXPOSES)
        ports = [s.data.get("port") for s in services if s.data.get("port")]
        if ports:
            target.ports = sorted(set(ports))
        return target

    # Fallback: walk relations to find a host
    if entity.type in (
        EntityType.SERVICE, EntityType.ENDPOINT, EntityType.TECHNOLOGY,
        EntityType.CONTAINER, EntityType.IMAGE,
    ):
        parents = graph.reverse_neighbors(entity.id)
        for parent in parents:
            if parent.type == EntityType.HOST:
                return graph.entity_to_target(parent)

    return Target.domain(host or "unknown")
