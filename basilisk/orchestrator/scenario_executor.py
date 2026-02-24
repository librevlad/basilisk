"""Scenario executor — dispatches to v4 scenarios instead of v3 plugins."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from basilisk.bridge.result_adapter import ResultAdapter
from basilisk.domain.target import LiveTarget
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.relations import RelationType
from basilisk.models.result import Finding, PluginResult
from basilisk.observations.adapter import adapt_result
from basilisk.orchestrator.selector import _is_ip_or_local

if TYPE_CHECKING:
    from basilisk.capabilities.capability import Capability
    from basilisk.config import Settings
    from basilisk.engine.scenario_registry import ScenarioRegistry
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.observations.observation import Observation

logger = logging.getLogger(__name__)


def _noop_emit(_finding: Finding, _target: str = "") -> None:
    pass


@dataclass
class _CtxShim:
    """Minimal shim satisfying the loop's executor.ctx.pipeline/state access."""

    pipeline: dict[str, PluginResult] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)
    emit: Any = _noop_emit


class ScenarioExecutor:
    """Run scenarios (native v4 + legacy-wrapped) and convert to observations.

    Drop-in replacement for OrchestratorExecutor — the AutonomousLoop only
    interacts through execute() and ctx.pipeline/ctx.state.
    """

    def __init__(
        self,
        registry: ScenarioRegistry,
        actor: Any,
        settings: Settings,
        tools: dict[str, Any] | None = None,
        state: dict[str, Any] | None = None,
    ) -> None:
        self.registry = registry
        self._actor = actor
        self._settings = settings
        self._tools = tools or {}
        self.ctx = _CtxShim(state=state if state is not None else {})

    async def execute(
        self,
        capability: Capability,
        target_entity: Entity,
        graph: KnowledgeGraph,
    ) -> list[Observation]:
        """Run a scenario and convert its output to observations."""
        scenario = self.registry.get(capability.plugin_name)
        if scenario is None:
            logger.warning("Scenario %s not found in registry", capability.plugin_name)
            return []

        v3_target = self._entity_to_target(target_entity, graph)
        v4_target = LiveTarget(
            host=v3_target.host,
            ports=v3_target.ports,
            meta=v3_target.meta,
        )

        # Pass service port info through state for service-targeted plugins
        if target_entity.type == EntityType.SERVICE:
            port = target_entity.data.get("port")
            svc_name = target_entity.data.get("service", "")
            if port:
                self.ctx.state["target_service_port"] = port
                self.ctx.state["target_service_name"] = svc_name

        tools = {
            **self._tools,
            "settings": self._settings,
            "config": self._settings,
            "pipeline": self.ctx.pipeline,
            "state": self.ctx.state,
        }

        try:
            scenario_result = await scenario.run(v4_target, self._actor, [], tools)
        except Exception:
            logger.exception(
                "Failed to execute %s on %s", capability.plugin_name, v3_target.host,
            )
            return []

        # Convert ScenarioResult → PluginResult for pipeline compat
        result = ResultAdapter.to_v3_result(scenario_result)
        key = f"{result.plugin}:{result.target}"
        self.ctx.pipeline[key] = result

        # Populate ctx.state with data that pentesting plugins need
        self._populate_state(result)

        # Emit findings
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
            existing = self.ctx.state.setdefault(
                "discovered_api_paths", {},
            ).setdefault(host, [])
            existing_set = set(existing)
            for p in api_paths:
                if p not in existing_set:
                    existing.append(p)
                    existing_set.add(p)

        # upload_endpoints → crawled_urls
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

        # nosqli_tests
        nosqli = data.get("nosqli_tests", [])
        if nosqli:
            self.ctx.state.setdefault("nosqli_tests", []).extend(nosqli)

        # ssti_tests
        ssti = data.get("ssti_tests", [])
        if ssti:
            self.ctx.state.setdefault("ssti_tests", []).extend(ssti)

        # technologies → detected_tech
        techs = data.get("technologies", [])
        if techs:
            names = [t.get("name", t) if isinstance(t, dict) else t for t in techs]
            existing = self.ctx.state.setdefault("detected_tech", {}).setdefault(host, [])
            existing_set = set(existing)
            for n in names:
                if n not in existing_set:
                    existing.append(n)
                    existing_set.add(n)

        # subdomains
        subs = data.get("subdomains", [])
        if subs:
            existing = self.ctx.state.setdefault("subdomains", {}).setdefault(host, [])
            existing_set = set(existing)
            for s in subs:
                if s not in existing_set:
                    existing.append(s)
                    existing_set.add(s)

        # container_runtimes
        runtimes = data.get("container_runtimes", [])
        if runtimes:
            existing = self.ctx.state.setdefault(
                "container_runtimes", {},
            ).setdefault(host, [])
            existing.extend(runtimes)

        # containers
        containers = data.get("containers", [])
        if containers:
            existing = self.ctx.state.setdefault("containers", {}).setdefault(host, [])
            existing.extend(containers)

    @staticmethod
    def _entity_to_target(entity: Entity, graph: KnowledgeGraph) -> Any:
        """Convert an entity to a v3 Target for scenario execution."""
        from basilisk.models.target import Target

        if entity.type == EntityType.HOST:
            target = graph.entity_to_target(entity)
            services = graph.neighbors(entity.id, RelationType.EXPOSES)
            ports = [s.data.get("port") for s in services if s.data.get("port")]
            if ports:
                target.ports = sorted(set(ports))
            return target

        host = entity.data.get("host", "")
        if host:
            target = Target.ip(host) if _is_ip_or_local(host) else Target.domain(host)
            host_id = Entity.make_id(EntityType.HOST, host=host)
            services = graph.neighbors(host_id, RelationType.EXPOSES)
            ports = [s.data.get("port") for s in services if s.data.get("port")]
            if ports:
                target.ports = sorted(set(ports))
            return target

        if entity.type in (
            EntityType.SERVICE, EntityType.ENDPOINT, EntityType.TECHNOLOGY,
            EntityType.CONTAINER, EntityType.IMAGE,
        ):
            parents = graph.reverse_neighbors(entity.id)
            for parent in parents:
                if parent.type == EntityType.HOST:
                    return graph.entity_to_target(parent)

        return Target.domain(host or "unknown")
