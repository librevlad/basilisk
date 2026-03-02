"""Scenario executor — dispatches to v4 scenarios instead of v3 plugins."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from basilisk.bridge.result_adapter import ResultAdapter
from basilisk.domain.target import LiveTarget
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.models.result import Finding, PluginResult
from basilisk.observations.adapter import adapt_result
from basilisk.orchestrator.executor_utils import entity_to_target, populate_state

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

        v3_target = entity_to_target(target_entity, graph)
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
        populate_state(self.ctx.state, result)

