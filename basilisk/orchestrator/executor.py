"""Orchestrator executor — wraps core AsyncExecutor for autonomous mode."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.models.target import Target
from basilisk.observations.adapter import adapt_result

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

        # Emit findings via existing callback
        for finding in result.findings:
            self.ctx.emit(finding, result.target)

        return adapt_result(result)

    @staticmethod
    def _entity_to_target(entity: Entity, graph: KnowledgeGraph) -> Target:
        """Convert an entity to a Target object for plugin execution.

        Host entities → Target directly.
        Service/Endpoint/Technology entities → look up the parent Host.
        """
        if entity.type == EntityType.HOST:
            return graph.entity_to_target(entity)

        # For non-Host entities, extract host from data
        host = entity.data.get("host", "")
        if host:
            return Target.domain(host)

        # Fallback: walk relations to find a host
        if entity.type in (EntityType.SERVICE, EntityType.ENDPOINT, EntityType.TECHNOLOGY):
            parents = graph.reverse_neighbors(entity.id)
            for parent in parents:
                if parent.type == EntityType.HOST:
                    return graph.entity_to_target(parent)

        return Target.domain(host or "unknown")
