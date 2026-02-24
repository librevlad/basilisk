"""Capability model — what a plugin can do in the knowledge graph context."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ActionType(StrEnum):
    """Classification of what a capability does."""

    ENUMERATION = "enumeration"     # recon, scanning — discover new entities
    EXPERIMENT = "experiment"       # analysis, pentesting — test hypotheses
    EXPLOIT = "exploit"             # exploitation — needs confirmed vulnerability
    VERIFICATION = "verification"   # re-test to confirm/reject findings


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
    reduces_uncertainty: list[str] = Field(default_factory=list)  # knowledge confirmed
    risk_domain: str = "general"  # recon|web|network|auth|crypto|forensics|general
    action_type: ActionType = ActionType.ENUMERATION
    expected_state_delta: dict[str, Any] = Field(default_factory=dict)
    detects: list[str] = Field(default_factory=list)  # vuln categories this plugin detects
