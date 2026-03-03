"""Shared execution fingerprint for (capability, entity) deduplication."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from basilisk.knowledge.entities import Entity

from basilisk.knowledge.entities import EntityType


def make_execution_fingerprint(plugin_name: str, entity: Entity) -> str:
    """Create a unique fingerprint for a (plugin, entity) pair.

    For Endpoint-targeted plugins (pentesting, exploitation), use plugin:host
    because these plugins scan ALL injection points on the host in a single run.
    For other entity types, use the full entity ID.
    """
    if entity.type == EntityType.ENDPOINT:
        host = entity.data.get("host", entity.id)
        return f"{plugin_name}:{host}"
    return f"{plugin_name}:{entity.id}"
