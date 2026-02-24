"""Orchestrator executor — wraps core AsyncExecutor for autonomous mode."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.relations import RelationType
from basilisk.models.result import PluginResult
from basilisk.models.target import Target
from basilisk.observations.adapter import adapt_result
from basilisk.orchestrator.selector import _is_ip_or_local

if TYPE_CHECKING:
    from basilisk.capabilities.capability import Capability
    from basilisk.core.executor import AsyncExecutor, PluginContext
    from basilisk.core.registry import PluginRegistry
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.observations.observation import Observation

logger = logging.getLogger(__name__)


class OrchestratorExecutor:
    """Run a plugin via the core executor and convert output to observations."""

    def __init__(
        self,
        registry: PluginRegistry,
        core_executor: AsyncExecutor,
        ctx: PluginContext,
    ) -> None:
        self.registry = registry
        self.core_executor = core_executor
        self.ctx = ctx

    async def execute(
        self,
        capability: Capability,
        target_entity: Entity,
        graph: KnowledgeGraph,
    ) -> list[Observation]:
        """Run a plugin and convert its output to observations."""
        plugin_cls = self.registry.get(capability.plugin_name)
        if not plugin_cls:
            logger.warning("Plugin %s not found in registry", capability.plugin_name)
            return []

        target = self._entity_to_target(target_entity, graph)
        plugin = plugin_cls()

        # Pass service port info through ctx.state for service-targeted plugins
        if target_entity.type == EntityType.SERVICE:
            port = target_entity.data.get("port")
            svc_name = target_entity.data.get("service", "")
            if port:
                self.ctx.state["target_service_port"] = port
                self.ctx.state["target_service_name"] = svc_name

        try:
            await plugin.setup(self.ctx)
            result = await self.core_executor.run_one(plugin, target, self.ctx)
            await plugin.teardown()
        except Exception:
            logger.exception("Failed to execute %s on %s", capability.plugin_name, target.host)
            return []

        # Store in pipeline context for backward compatibility
        key = f"{result.plugin}:{result.target}"
        self.ctx.pipeline[key] = result

        # Populate ctx.state with data that pentesting plugins need
        self._populate_state(result)

        # Emit findings via existing callback
        for finding in result.findings:
            self.ctx.emit(finding, result.target)

        return adapt_result(result)

    def _populate_state(self, result: PluginResult) -> None:
        """Populate ctx.state with data pentesting plugins need."""
        if not result.ok:
            return
        host = result.target
        data = result.data

        # crawled_urls
        urls = data.get("crawled_urls", [])
        if urls:
            existing = self.ctx.state.setdefault("crawled_urls", {}).setdefault(host, [])
            existing_set = set(existing)
            for url in urls:
                if url not in existing_set:
                    existing.append(url)
                    existing_set.add(url)

        # forms → discovered_forms
        forms = data.get("forms", [])
        if forms:
            existing = self.ctx.state.setdefault("discovered_forms", {}).setdefault(host, [])
            existing.extend(forms)

        # api_paths / interesting_paths → discovered_api_paths
        api_paths = data.get("api_paths", []) + data.get("interesting_paths", [])
        if api_paths:
            existing = self.ctx.state.setdefault("discovered_api_paths", {}).setdefault(host, [])
            existing_set = set(existing)
            for p in api_paths:
                if p not in existing_set:
                    existing.append(p)
                    existing_set.add(p)

        # upload_endpoints → crawled_urls (so exploitation plugins see them)
        upload_eps = data.get("upload_endpoints", [])
        if upload_eps:
            scheme_map = self.ctx.state.get("http_scheme", {})
            scheme = scheme_map.get(host, "http") or "http"
            base = f"{scheme}://{host}"
            existing = self.ctx.state.setdefault("crawled_urls", {}).setdefault(host, [])
            existing_set = set(existing)
            for ep in upload_eps:
                url = f"{base}{ep}" if ep.startswith("/") else ep
                if url not in existing_set:
                    existing.append(url)
                    existing_set.add(url)

        # waf → waf_map
        waf = data.get("waf", [])
        if waf:
            self.ctx.state.setdefault("waf_map", {})[host] = waf

        # nosqli_tests → ctx.state (for nosqli_verify)
        nosqli = data.get("nosqli_tests", [])
        if nosqli:
            self.ctx.state.setdefault("nosqli_tests", []).extend(nosqli)

        # ssti_tests → ctx.state (for ssti_verify)
        ssti = data.get("ssti_tests", [])
        if ssti:
            self.ctx.state.setdefault("ssti_tests", []).extend(ssti)

        # technologies → detected_tech (for dir_brute tech-specific extensions)
        techs = data.get("technologies", [])
        if techs:
            names = [t.get("name", t) if isinstance(t, dict) else t for t in techs]
            existing = self.ctx.state.setdefault("detected_tech", {}).setdefault(host, [])
            existing_set = set(existing)
            for n in names:
                if n not in existing_set:
                    existing.append(n)
                    existing_set.add(n)

        # subdomains → ctx.state (for subdomain_bruteforce permutation mode)
        subs = data.get("subdomains", [])
        if subs:
            existing = self.ctx.state.setdefault("subdomains", {}).setdefault(host, [])
            existing_set = set(existing)
            for s in subs:
                if s not in existing_set:
                    existing.append(s)
                    existing_set.add(s)

        # container_runtimes → ctx.state
        runtimes = data.get("container_runtimes", [])
        if runtimes:
            existing = self.ctx.state.setdefault(
                "container_runtimes", {},
            ).setdefault(host, [])
            existing.extend(runtimes)

        # containers → ctx.state
        containers = data.get("containers", [])
        if containers:
            existing = self.ctx.state.setdefault("containers", {}).setdefault(host, [])
            existing.extend(containers)

    @staticmethod
    def _entity_to_target(entity: Entity, graph: KnowledgeGraph) -> Target:
        """Convert an entity to a Target object for plugin execution.

        Host entities → Target directly, with ports from services in the graph.
        Service/Endpoint/Technology entities → look up the parent Host.
        """
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
            target = Target.ip(host) if _is_ip_or_local(host) else Target.domain(host)
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
