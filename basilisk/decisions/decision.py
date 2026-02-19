"""Decision model — structured record of every autonomous action choice."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from pydantic import BaseModel, Field


class ContextSnapshot(BaseModel):
    """Graph state at the moment a decision was made."""

    entity_count: int = 0
    relation_count: int = 0
    host_count: int = 0
    service_count: int = 0
    finding_count: int = 0
    gap_count: int = 0
    elapsed_seconds: float = 0.0
    step: int = 0


class EvaluatedOption(BaseModel):
    """A single candidate considered during decision-making."""

    capability_name: str
    plugin_name: str
    target_entity_id: str
    target_host: str
    score: float
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    reason: str = ""
    was_chosen: bool = False


class Decision(BaseModel):
    """Complete record of an autonomous decision with pre/post execution data.

    Created BEFORE execution (intent), updated AFTER execution (outcome).
    Deterministic ID derived from step + timestamp + plugin + target.
    """

    id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    step: int = 0
    goal: str = ""                       # gap.missing (e.g. "services")
    goal_description: str = ""           # gap.description
    goal_priority: float = 0.0           # gap.priority
    triggering_entity_id: str = ""
    context: ContextSnapshot = Field(default_factory=ContextSnapshot)
    evaluated_options: list[EvaluatedOption] = Field(default_factory=list)
    chosen_capability: str = ""
    chosen_plugin: str = ""
    chosen_target: str = ""
    chosen_score: float = 0.0
    reasoning_trace: str = ""

    # Filled after execution
    outcome_observations: int = 0
    outcome_new_entities: int = 0
    outcome_confidence_delta: float = 0.0
    outcome_duration: float = 0.0
    was_productive: bool = False

    @staticmethod
    def make_id(step: int, timestamp: datetime, plugin: str, target: str) -> str:
        """Deterministic ID from step + timestamp + plugin + target."""
        raw = f"{step}:{timestamp.isoformat()}:{plugin}:{target}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
