"""Protocol types for executor implementations — used by loop.py for typing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from basilisk.knowledge.entities import Entity

if TYPE_CHECKING:
    from basilisk.capabilities.capability import Capability
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.observations.observation import Observation


class ExecutorContext(Protocol):
    """Minimal interface for executor.ctx accessed by the loop."""

    pipeline: dict[str, Any]
    state: dict[str, Any]


class ExecutorProtocol(Protocol):
    """Protocol satisfied by both OrchestratorExecutor and ScenarioExecutor."""

    ctx: ExecutorContext

    async def execute(
        self,
        capability: Capability,
        target_entity: Entity,
        graph: KnowledgeGraph,
    ) -> list[Observation]: ...
