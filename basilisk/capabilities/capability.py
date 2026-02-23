"""Capability model — what a plugin can do in the knowledge graph context."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Capability(BaseModel):
    """Describes what a plugin can do: what knowledge it needs and produces."""

    name: str
    plugin_name: str
    category: str
    requires_knowledge: list[str] = Field(default_factory=list)
    produces_knowledge: list[str] = Field(default_factory=list)
    cost_score: float = 1.0       # relative execution cost (1-10)
    noise_score: float = 1.0      # detectability (1-10)
    execution_time_estimate: float = 10.0  # seconds
