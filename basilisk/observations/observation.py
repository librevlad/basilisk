"""Observation model — structured output from plugin execution."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from basilisk.knowledge.entities import EntityType
from basilisk.knowledge.relations import Relation


class Observation(BaseModel):
    """A single piece of knowledge extracted from a PluginResult.

    Observations are the bridge between the plugin world (PluginResult) and
    the knowledge graph (Entity + Relation). The adapter converts
    PluginResult → list[Observation], and the loop applies each observation
    to the graph.
    """

    entity_type: EntityType
    entity_data: dict[str, Any] = Field(default_factory=dict)
    key_fields: dict[str, str] = Field(default_factory=dict)
    relation: Relation | None = None
    evidence: str = ""
    confidence: float = 1.0
    source_plugin: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
