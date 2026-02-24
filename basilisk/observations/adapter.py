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

    # Helper: data.get() can return None when key exists but value is None
    def _safe_list(key: str) -> list:
        val = data.get(key)
        return val if isinstance(val, list) else []

    # open_ports → Service entities
    for port_info in _safe_list("open_ports"):
        obs = _service_from_port(host, port_info, plugin)
        if obs:
            observations.append(obs)

    # services → Service entities
    for svc in _safe_list("services"):
        obs = _service_from_dict(host, svc, plugin)
        if obs:
            observations.append(obs)

    # technologies → Technology entities
    for tech in _safe_list("technologies"):
        obs = _technology_observation(host, tech, plugin)
        if obs:
            observations.append(obs)

    # cms → Technology entities
    for cms in _safe_list("cms"):
        obs = _cms_observation(host, cms, plugin)
        if obs:
            observations.append(obs)

    # subdomains → Host entities with PARENT_OF relation
    for sub in _safe_list("subdomains"):
        observations.append(_subdomain_observation(sub, host, plugin))

    # Endpoint sources: crawled_urls, found_paths, api_endpoints, internal_links
    for url in _safe_list("crawled_urls"):
        obs = _endpoint_from_url(host, url, plugin)
        if obs:
            observations.append(obs)

    for path_entry in _safe_list("found_paths"):
        obs = _endpoint_from_path(host, path_entry, plugin)
        if obs:
            observations.append(obs)

    for ep in _safe_list("api_endpoints"):
        obs = _endpoint_from_api(host, ep, plugin)
        if obs:
            observations.append(obs)

    for url in _safe_list("internal_links"):
        obs = _endpoint_from_url(host, url, plugin)
        if obs:
            observations.append(obs)

    # urls → Endpoint entities (from sitemap_parser)
    for url in _safe_list("urls"):
        obs = _endpoint_from_url(host, url, plugin)
        if obs:
            observations.append(obs)

    # upload_endpoints → Endpoint entities (from file_upload_check)
    for path in _safe_list("upload_endpoints"):
        if isinstance(path, str) and path:
            obs = _make_endpoint_observation(host, path, plugin, is_upload=True)
            observations.append(obs)

    # forms → Endpoint entities (from form_analyzer)
    for form in _safe_list("forms"):
        if isinstance(form, dict):
            action = form.get("action", "")
            if action:
                obs = _make_endpoint_observation(host, action, plugin)
                observations.append(obs)

    # credentials → Credential entities
    for cred in _safe_list("credentials"):
        obs = _credential_observation(host, cred, plugin)
        if obs:
            observations.append(obs)

    # waf → Technology entities
    for waf in _safe_list("waf"):
        obs = _waf_observation(host, waf, plugin)
        if obs:
            observations.append(obs)

    # waf_cdn → Technology entities (from tech_detect plugin)
    for wc in _safe_list("waf_cdn"):
        obs = _waf_cdn_observation(host, wc, plugin)
        if obs:
            observations.append(obs)

    # cdn → Technology entities (from cdn_detect / waf_detect)
    for cdn in _safe_list("cdn"):
        obs = _cdn_observation(host, cdn, plugin)
        if obs:
            observations.append(obs)

    # ssl_info → enrich Host/Service data
    if data.get("ssl_info"):
        observations.append(_ssl_observation(host, data["ssl_info"], plugin))

    # records (DNS) → enrich Host data
    if data.get("records"):
        observations.append(_dns_observation(host, data["records"], plugin))

    # container_runtimes → Technology entities (is_container_runtime=True)
    for rt in _safe_list("container_runtimes"):
        obs = _container_runtime_observation(host, rt, plugin)
        if obs:
            observations.append(obs)

    # containers → Container entities + USES_IMAGE relations
    for container in _safe_list("containers"):
        obs_list = _container_observations(host, container, plugin)
        observations.extend(obs_list)

    # images → Image entities
    for img in _safe_list("images"):
        obs = _image_observation(host, img, plugin)
        if obs:
            observations.append(obs)

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
        banner = port_info.get("banner", "")
    elif isinstance(port_info, int):
        port = port_info
        protocol = "tcp"
        service_name = ""
        banner = ""
    else:
        return None

    if not port:
        return None

    # Infer service name from banner if not already set
    if not service_name and banner:
        service_name = _infer_service_from_banner(banner)

    host_id = Entity.make_id(EntityType.HOST, host=host)
    service_id = Entity.make_id(EntityType.SERVICE, host=host, port=str(port), protocol=protocol)

    entity_data: dict[str, Any] = {
        "host": host, "port": port, "protocol": protocol, "service": service_name,
    }
    if banner:
        entity_data["banner"] = banner

    return Observation(
        entity_type=EntityType.SERVICE,
        entity_data=entity_data,
        key_fields={"host": host, "port": str(port), "protocol": protocol},
        relation=Relation(
            source_id=host_id, target_id=service_id,
            type=RelationType.EXPOSES, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _infer_service_from_banner(banner: str) -> str:
    """Infer service name from banner string."""
    b = banner.lower()
    if b.startswith("ssh-"):
        return "ssh"
    if b.startswith("220") and ("ftp" in b or "vsftpd" in b or "proftpd" in b):
        return "ftp"
    if "mysql" in b or "mariadb" in b:
        return "mysql"
    if "postgresql" in b:
        return "postgresql"
    if "redis" in b:
        return "redis"
    if "mongodb" in b or "mongo" in b:
        return "mongodb"
    if "elasticsearch" in b or "elastic" in b:
        return "elasticsearch"
    if "samba" in b or "smb" in b:
        return "smb"
    if "http" in b:
        return "http"
    return ""


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

    # Normalize: if a full URL was passed, extract just the path component
    if path.startswith(("http://", "https://")):
        try:
            parsed = urlparse(path)
            path = parsed.path or "/"
        except Exception:
            pass

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

    # Normalize: if a full URL was passed, extract just the path component
    if path.startswith(("http://", "https://")):
        try:
            parsed = urlparse(path)
            path = parsed.path or "/"
            if parsed.query:
                return _make_endpoint_observation(
                    host, path, plugin, is_api=True, params=True,
                )
        except Exception:
            pass

    return _make_endpoint_observation(host, path, plugin, is_api=True)


def _make_endpoint_observation(
    host: str, path: str, plugin: str, *,
    status: int = 0, params: bool = False, is_api: bool = False,
    is_upload: bool = False,
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
    if is_upload:
        data["is_upload"] = True

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


def _waf_cdn_observation(host: str, wc: Any, plugin: str) -> Observation | None:
    """Convert WAF/CDN entry from tech_detect to Technology observation."""
    if isinstance(wc, dict):
        name = wc.get("name", "")
        version = wc.get("version", "")
        category = wc.get("category", "")
    elif isinstance(wc, str):
        name = wc
        version = ""
        category = ""
    else:
        return None

    if not name:
        return None

    host_id = Entity.make_id(EntityType.HOST, host=host)
    tech_id = Entity.make_id(EntityType.TECHNOLOGY, host=host, name=name, version=version)

    entity_data: dict[str, Any] = {"host": host, "name": name, "version": version}
    if category in ("waf",):
        entity_data["is_waf"] = True
    if category in ("cdn", "cache"):
        entity_data["is_cdn"] = True

    return Observation(
        entity_type=EntityType.TECHNOLOGY,
        entity_data=entity_data,
        key_fields={"host": host, "name": name, "version": version},
        relation=Relation(
            source_id=host_id, target_id=tech_id,
            type=RelationType.RUNS, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _cdn_observation(host: str, cdn: Any, plugin: str) -> Observation | None:
    """Convert CDN detection entry to Technology observation."""
    if isinstance(cdn, dict):
        name = cdn.get("name", cdn.get("provider", ""))
    elif isinstance(cdn, str):
        name = cdn
    else:
        return None

    if not name:
        return None

    host_id = Entity.make_id(EntityType.HOST, host=host)
    tech_id = Entity.make_id(EntityType.TECHNOLOGY, host=host, name=name, version="")

    return Observation(
        entity_type=EntityType.TECHNOLOGY,
        entity_data={"host": host, "name": name, "version": "", "is_cdn": True},
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


def _container_runtime_observation(
    host: str, rt: Any, plugin: str,
) -> Observation | None:
    """Convert container runtime entry to Technology observation with is_container_runtime."""
    if isinstance(rt, dict):
        name = rt.get("name", "docker")
        version = rt.get("version", "")
    elif isinstance(rt, str):
        name = rt
        version = ""
    else:
        return None

    if not name:
        return None

    host_id = Entity.make_id(EntityType.HOST, host=host)
    tech_id = Entity.make_id(EntityType.TECHNOLOGY, host=host, name=name, version=version)

    return Observation(
        entity_type=EntityType.TECHNOLOGY,
        entity_data={
            "host": host, "name": name, "version": version, "is_container_runtime": True,
        },
        key_fields={"host": host, "name": name, "version": version},
        relation=Relation(
            source_id=host_id, target_id=tech_id,
            type=RelationType.RUNS, source_plugin=plugin,
        ),
        source_plugin=plugin,
    )


def _parse_image_ref(ref: str) -> tuple[str, str]:
    """Parse image reference like 'nginx:1.24' → ('nginx', '1.24').

    Handles: 'nginx:1.24', 'ubuntu', 'registry.io/app:v2', 'sha256:abc...'.
    """
    if not ref or ref.startswith("sha256:"):
        return ref, ""
    # Split on last colon, but not if it's part of a registry port
    parts = ref.rsplit(":", 1)
    if len(parts) == 2:
        name, tag = parts
        # If tag looks like a port number followed by a path, it's a registry
        if "/" in tag:
            return ref, "latest"
        return name, tag
    return ref, "latest"


def _container_observations(
    host: str, container: Any, plugin: str,
) -> list[Observation]:
    """Convert container entry to Container + optional Image observations."""
    if not isinstance(container, dict):
        return []

    container_id = container.get("id", container.get("container_id", ""))
    if not container_id:
        return []

    observations: list[Observation] = []

    # Container entity
    container_entity_id = Entity.make_id(
        EntityType.CONTAINER, host=host, container_id=container_id,
    )

    # Find runtime Technology to create RUNS_CONTAINER relation
    runtime_name = container.get("runtime", "docker")
    runtime_id = Entity.make_id(
        EntityType.TECHNOLOGY, host=host, name=runtime_name, version="",
    )

    container_data: dict[str, Any] = {"host": host, "container_id": container_id}
    for key in (
        "image", "state", "names", "ports", "mounts", "network_mode",
        "privileged", "user", "pid_mode", "capabilities",
    ):
        if key in container:
            container_data[key] = container[key]

    observations.append(Observation(
        entity_type=EntityType.CONTAINER,
        entity_data=container_data,
        key_fields={"host": host, "container_id": container_id},
        relation=Relation(
            source_id=runtime_id, target_id=container_entity_id,
            type=RelationType.RUNS_CONTAINER, source_plugin=plugin,
        ),
        source_plugin=plugin,
    ))

    # Image entity from container's image field
    image_ref = container.get("image", "")
    if image_ref:
        image_name, image_tag = _parse_image_ref(image_ref)
        image_entity_id = Entity.make_id(
            EntityType.IMAGE, host=host, image_name=image_name, image_tag=image_tag,
        )
        observations.append(Observation(
            entity_type=EntityType.IMAGE,
            entity_data={
                "host": host, "image_name": image_name, "image_tag": image_tag,
            },
            key_fields={"host": host, "image_name": image_name, "image_tag": image_tag},
            relation=Relation(
                source_id=container_entity_id, target_id=image_entity_id,
                type=RelationType.USES_IMAGE, source_plugin=plugin,
            ),
            source_plugin=plugin,
        ))

    return observations


def _image_observation(host: str, img: Any, plugin: str) -> Observation | None:
    """Convert image entry to Image observation."""
    if isinstance(img, dict):
        image_name = img.get("image_name", img.get("name", ""))
        image_tag = img.get("image_tag", img.get("tag", "latest"))
    elif isinstance(img, str):
        image_name, image_tag = _parse_image_ref(img)
    else:
        return None

    if not image_name:
        return None

    return Observation(
        entity_type=EntityType.IMAGE,
        entity_data={"host": host, "image_name": image_name, "image_tag": image_tag},
        key_fields={"host": host, "image_name": image_name, "image_tag": image_tag},
        source_plugin=plugin,
    )


def _finding_observation(host: str, finding: Any, plugin: str) -> Observation:
    """Convert a Finding to a Finding entity observation."""
    host_id = Entity.make_id(EntityType.HOST, host=host)
    title = finding.title if hasattr(finding, "title") else str(finding)
    severity = finding.severity.name.lower() if hasattr(finding, "severity") else "info"
    evidence = finding.evidence if hasattr(finding, "evidence") else ""

    finding_id = Entity.make_id(EntityType.FINDING, host=host, title=title)

    finding_confidence = getattr(finding, "confidence", 1.0)
    verified = getattr(finding, "verified", False)
    false_positive_risk = getattr(finding, "false_positive_risk", "low")

    # Infer category from tags (skip generic tags like "pentesting", "analysis")
    tags = getattr(finding, "tags", []) or []
    generic_tags = {
        "pentesting", "analysis", "scanning", "recon", "exploitation",
        "crypto", "lateral", "privesc", "post_exploit", "forensics",
        "form", "header", "config",
    }
    category = next((t for t in tags if t not in generic_tags), "")

    return Observation(
        entity_type=EntityType.FINDING,
        entity_data={
            "host": host,
            "title": title,
            "severity": severity,
            "category": category,
            "description": getattr(finding, "description", ""),
            "evidence": evidence,
            "finding_confidence": finding_confidence,
            "verified": verified,
            "false_positive_risk": false_positive_risk,
        },
        key_fields={"host": host, "title": title},
        relation=Relation(
            source_id=finding_id, target_id=host_id,
            type=RelationType.RELATES_TO, source_plugin=plugin,
        ),
        evidence=evidence,
        confidence=finding_confidence,
        source_plugin=plugin,
    )
