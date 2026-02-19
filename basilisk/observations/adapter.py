"""Adapter: PluginResult → list[Observation].

This is the key integration layer that converts unstructured plugin output
into typed observations for the knowledge graph. Data key mapping is derived
from extraction.py analysis.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.models.result import PluginResult
from basilisk.observations.observation import Observation


def adapt_result(result: PluginResult) -> list[Observation]:
    """Convert a PluginResult into a list of Observations."""
    observations: list[Observation] = []
    host = result.target
    data = result.data
    plugin = result.plugin

    if not result.ok:
        return observations

    # Always emit the host entity
    observations.append(_host_observation(host, plugin))

    # open_ports → Service entities
    for port_info in data.get("open_ports", []):
        obs = _service_from_port(host, port_info, plugin)
        if obs:
            observations.append(obs)

    # services → Service entities
    for svc in data.get("services", []):
        obs = _service_from_dict(host, svc, plugin)
        if obs:
            observations.append(obs)

    # technologies → Technology entities
    for tech in data.get("technologies", []):
        obs = _technology_observation(host, tech, plugin)
        if obs:
            observations.append(obs)

    # cms → Technology entities
    for cms in data.get("cms", []):
        obs = _cms_observation(host, cms, plugin)
        if obs:
            observations.append(obs)

    # subdomains → Host entities with PARENT_OF relation
    for sub in data.get("subdomains", []):
        observations.append(_subdomain_observation(sub, host, plugin))

    # Endpoint sources: crawled_urls, found_paths, api_endpoints, internal_links
    for url in data.get("crawled_urls", []):
        obs = _endpoint_from_url(host, url, plugin)
        if obs:
            observations.append(obs)

    for path_entry in data.get("found_paths", []):
        obs = _endpoint_from_path(host, path_entry, plugin)
        if obs:
            observations.append(obs)

    for ep in data.get("api_endpoints", []):
        obs = _endpoint_from_api(host, ep, plugin)
        if obs:
            observations.append(obs)

    for url in data.get("internal_links", []):
        obs = _endpoint_from_url(host, url, plugin)
        if obs:
            observations.append(obs)

    # credentials → Credential entities
    for cred in data.get("credentials", []):
        obs = _credential_observation(host, cred, plugin)
        if obs:
            observations.append(obs)

    # waf → Technology entities
    for waf in data.get("waf", []):
        obs = _waf_observation(host, waf, plugin)
        if obs:
            observations.append(obs)

    # ssl_info → enrich Host/Service data
    if data.get("ssl_info"):
        observations.append(_ssl_observation(host, data["ssl_info"], plugin))

    # records (DNS) → enrich Host data
    if data.get("records"):
        observations.append(_dns_observation(host, data["records"], plugin))

    # findings → Finding entities
    for finding in result.findings:
        observations.append(_finding_observation(host, finding, plugin))

    return observations


def _host_observation(host: str, plugin: str) -> Observation:
    """Create base Host observation."""
    return Observation(
        entity_type=EntityType.HOST,
        entity_data={"host": host},
        key_fields={"host": host},
        source_plugin=plugin,
    )


def _service_from_port(host: str, port_info: Any, plugin: str) -> Observation | None:
    """Convert open_ports entry to Service observation."""
    if isinstance(port_info, dict):
        port = port_info.get("port")
        protocol = port_info.get("protocol", "tcp")
        service_name = port_info.get("service", "")
    elif isinstance(port_info, int):
        port = port_info
        protocol = "tcp"
        service_name = ""
    else:
        return None

    if not port:
        return None

    host_id = Entity.make_id(EntityType.HOST, host=host)
    service_id = Entity.make_id(EntityType.SERVICE, host=host, port=str(port), protocol=protocol)

    return Observation(
        entity_type=EntityType.SERVICE,
        entity_data={
            "host": host, "port": port, "protocol": protocol, "service": service_name,
        },
        key_fields={"host": host, "port": str(port), "protocol": protocol},
        relation=Relation(
            source_id=host_id, target_id=service_id,
            type=RelationType.EXPOSES, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _service_from_dict(host: str, svc: Any, plugin: str) -> Observation | None:
    """Convert services list entry to Service observation."""
    if not isinstance(svc, dict):
        return None
    port = svc.get("port")
    if not port:
        return None
    protocol = svc.get("protocol", "tcp")
    host_id = Entity.make_id(EntityType.HOST, host=host)
    service_id = Entity.make_id(EntityType.SERVICE, host=host, port=str(port), protocol=protocol)

    return Observation(
        entity_type=EntityType.SERVICE,
        entity_data={"host": host, "port": port, "protocol": protocol, **svc},
        key_fields={"host": host, "port": str(port), "protocol": protocol},
        relation=Relation(
            source_id=host_id, target_id=service_id,
            type=RelationType.EXPOSES, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _technology_observation(host: str, tech: Any, plugin: str) -> Observation | None:
    """Convert technology entry to Technology observation."""
    if isinstance(tech, dict):
        name = tech.get("name", "")
        version = tech.get("version", "")
    elif isinstance(tech, str):
        name = tech
        version = ""
    else:
        return None

    if not name:
        return None

    host_id = Entity.make_id(EntityType.HOST, host=host)
    tech_id = Entity.make_id(EntityType.TECHNOLOGY, host=host, name=name, version=version)

    return Observation(
        entity_type=EntityType.TECHNOLOGY,
        entity_data={"host": host, "name": name, "version": version},
        key_fields={"host": host, "name": name, "version": version},
        relation=Relation(
            source_id=host_id, target_id=tech_id,
            type=RelationType.RUNS, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _cms_observation(host: str, cms: Any, plugin: str) -> Observation | None:
    """Convert CMS detection to Technology observation."""
    if isinstance(cms, dict):
        name = cms.get("name", cms.get("cms", ""))
        version = cms.get("version", "")
    elif isinstance(cms, str):
        name = cms
        version = ""
    else:
        return None

    if not name:
        return None

    host_id = Entity.make_id(EntityType.HOST, host=host)
    tech_id = Entity.make_id(EntityType.TECHNOLOGY, host=host, name=name, version=version)

    return Observation(
        entity_type=EntityType.TECHNOLOGY,
        entity_data={"host": host, "name": name, "version": version, "is_cms": True},
        key_fields={"host": host, "name": name, "version": version},
        relation=Relation(
            source_id=host_id, target_id=tech_id,
            type=RelationType.RUNS, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _subdomain_observation(subdomain: str, parent_host: str, plugin: str) -> Observation:
    """Convert subdomain to Host observation with PARENT_OF relation."""
    parent_id = Entity.make_id(EntityType.HOST, host=parent_host)
    child_id = Entity.make_id(EntityType.HOST, host=subdomain)

    return Observation(
        entity_type=EntityType.HOST,
        entity_data={"host": subdomain, "type": "subdomain", "parent": parent_host},
        key_fields={"host": subdomain},
        relation=Relation(
            source_id=parent_id, target_id=child_id,
            type=RelationType.PARENT_OF, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _endpoint_from_url(host: str, url: str, plugin: str) -> Observation | None:
    """Convert URL to Endpoint observation."""
    if not isinstance(url, str) or not url:
        return None

    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        has_params = bool(parsed.query)
    except Exception:
        path = url
        has_params = False

    return _make_endpoint_observation(host, path, plugin, params=has_params)


def _endpoint_from_path(host: str, path_entry: Any, plugin: str) -> Observation | None:
    """Convert found_paths entry to Endpoint observation."""
    if isinstance(path_entry, dict):
        path = path_entry.get("path", "")
        status = path_entry.get("status", 0)
    elif isinstance(path_entry, str):
        path = path_entry
        status = 0
    else:
        return None

    if not path:
        return None

    return _make_endpoint_observation(host, path, plugin, status=status)


def _endpoint_from_api(host: str, ep: Any, plugin: str) -> Observation | None:
    """Convert api_endpoints entry to Endpoint observation."""
    if isinstance(ep, dict):
        path = ep.get("path", ep.get("url", ""))
    elif isinstance(ep, str):
        path = ep
    else:
        return None

    if not path:
        return None

    return _make_endpoint_observation(host, path, plugin, is_api=True)


def _make_endpoint_observation(
    host: str, path: str, plugin: str, *,
    status: int = 0, params: bool = False, is_api: bool = False,
) -> Observation:
    """Create an Endpoint observation with SERVICE → ENDPOINT relation."""
    host_id = Entity.make_id(EntityType.HOST, host=host)
    endpoint_id = Entity.make_id(EntityType.ENDPOINT, host=host, path=path)

    data: dict[str, Any] = {"host": host, "path": path}
    if status:
        data["status"] = status
    if params:
        data["has_params"] = True
    if is_api:
        data["is_api"] = True

    return Observation(
        entity_type=EntityType.ENDPOINT,
        entity_data=data,
        key_fields={"host": host, "path": path},
        relation=Relation(
            source_id=host_id, target_id=endpoint_id,
            type=RelationType.HAS_ENDPOINT, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _credential_observation(host: str, cred: Any, plugin: str) -> Observation | None:
    """Convert credential entry to Credential observation."""
    if not isinstance(cred, dict):
        return None

    username = cred.get("username", cred.get("user", ""))
    password = cred.get("password", cred.get("pass", ""))
    if not username:
        return None

    host_id = Entity.make_id(EntityType.HOST, host=host)
    cred_id = Entity.make_id(EntityType.CREDENTIAL, host=host, username=username)

    return Observation(
        entity_type=EntityType.CREDENTIAL,
        entity_data={"host": host, "username": username, "password": password},
        key_fields={"host": host, "username": username},
        relation=Relation(
            source_id=cred_id, target_id=host_id,
            type=RelationType.ACCESSES, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _waf_observation(host: str, waf: Any, plugin: str) -> Observation | None:
    """Convert WAF detection to Technology observation."""
    if isinstance(waf, dict):
        name = waf.get("name", "WAF")
    elif isinstance(waf, str):
        name = waf
    else:
        return None

    host_id = Entity.make_id(EntityType.HOST, host=host)
    tech_id = Entity.make_id(EntityType.TECHNOLOGY, host=host, name=name, version="")

    return Observation(
        entity_type=EntityType.TECHNOLOGY,
        entity_data={"host": host, "name": name, "version": "", "is_waf": True},
        key_fields={"host": host, "name": name, "version": ""},
        relation=Relation(
            source_id=host_id, target_id=tech_id,
            type=RelationType.RUNS, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _ssl_observation(host: str, ssl_info: dict, plugin: str) -> Observation:
    """Enrich Host with SSL info (stored as data on Host)."""
    return Observation(
        entity_type=EntityType.HOST,
        entity_data={"host": host, "ssl_info": ssl_info},
        key_fields={"host": host},
        source_plugin=plugin,
    )


def _dns_observation(host: str, records: list, plugin: str) -> Observation:
    """Enrich Host with DNS records."""
    return Observation(
        entity_type=EntityType.HOST,
        entity_data={"host": host, "dns_records": records},
        key_fields={"host": host},
        source_plugin=plugin,
    )


def _finding_observation(host: str, finding: Any, plugin: str) -> Observation:
    """Convert a Finding to a Finding entity observation."""
    host_id = Entity.make_id(EntityType.HOST, host=host)
    title = finding.title if hasattr(finding, "title") else str(finding)
    severity = finding.severity.name.lower() if hasattr(finding, "severity") else "info"
    evidence = finding.evidence if hasattr(finding, "evidence") else ""

    finding_id = Entity.make_id(EntityType.FINDING, host=host, title=title)

    return Observation(
        entity_type=EntityType.FINDING,
        entity_data={
            "host": host,
            "title": title,
            "severity": severity,
            "description": getattr(finding, "description", ""),
            "evidence": evidence,
        },
        key_fields={"host": host, "title": title},
        relation=Relation(
            source_id=finding_id, target_id=host_id,
            type=RelationType.RELATES_TO, source_plugin=plugin,
        ),
        evidence=evidence,
        source_plugin=plugin,
    )
