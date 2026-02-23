"""Goal Engine — strategic objectives that guide gap prioritization."""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.orchestrator.planner import KnowledgeGap

logger = logging.getLogger(__name__)


class GoalType(StrEnum):
    """Strategic objectives for the autonomous engine."""

    RECON = "recon"
    SURFACE_MAPPING = "surface_mapping"
    EXPLOIT = "exploit"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    VERIFICATION = "verification"


class Goal(BaseModel):
    """A strategic objective that boosts matching gap priorities."""

    type: GoalType
    name: str
    priority: float = 1.0
    relevant_gap_types: list[str] = Field(default_factory=list)
    relevant_risk_domains: list[str] = Field(default_factory=list)
    completion_condition: str = ""

    def matches_gap(self, gap: KnowledgeGap) -> bool:
        """True if the gap's missing type is covered by this goal."""
        return gap.missing in self.relevant_gap_types

    def matches_risk_domain(self, domain: str) -> bool:
        """True if the risk domain aligns with this goal."""
        return domain in self.relevant_risk_domains


# Default goal progression — executed in order
DEFAULT_GOAL_PROGRESSION: list[Goal] = [
    Goal(
        type=GoalType.RECON,
        name="Reconnaissance",
        priority=1.5,
        relevant_gap_types=["services", "dns", "confirmation"],
        relevant_risk_domains=["recon", "network"],
        completion_condition="All hosts have services discovered",
    ),
    Goal(
        type=GoalType.SURFACE_MAPPING,
        name="Surface Mapping",
        priority=1.3,
        relevant_gap_types=["technology", "endpoints", "forms", "version", "container_runtime"],
        relevant_risk_domains=["web", "network", "container"],
        completion_condition="All HTTP services have endpoints and tech detected",
    ),
    Goal(
        type=GoalType.EXPLOIT,
        name="Exploitation",
        priority=1.2,
        relevant_gap_types=[
            "vulnerability_testing", "host_vulnerability_testing",
            "service_exploitation", "credential_exploitation", "attack_path",
            "container_enumeration", "container_config_audit", "image_analysis",
        ],
        relevant_risk_domains=["web", "auth", "network", "container"],
        completion_condition="Vulnerability testing complete on all endpoints",
    ),
    Goal(
        type=GoalType.PRIVILEGE_ESCALATION,
        name="Privilege Escalation",
        priority=1.1,
        relevant_gap_types=["credential_exploitation", "service_exploitation"],
        relevant_risk_domains=["auth"],
        completion_condition="Credential and service exploitation attempted",
    ),
    Goal(
        type=GoalType.VERIFICATION,
        name="Verification",
        priority=1.4,
        relevant_gap_types=["finding_verification", "confirmation"],
        relevant_risk_domains=["web", "network", "auth"],
        completion_condition="All high/critical findings verified",
    ),
]


class GoalEngine:
    """Manages strategic goal progression and gap prioritization.

    When constructed with goals, it boosts matching gap priorities by the
    active goal's priority multiplier. When constructed without goals
    (or goals=None), it is fully transparent — prioritize_gaps() returns
    gaps unchanged.
    """

    def __init__(self, goals: list[Goal] | None = None) -> None:
        self._goals = goals or []
        self._index = 0

    @property
    def active_goal(self) -> Goal | None:
        """Current strategic objective, or None if no goals or all exhausted."""
        if not self._goals or self._index >= len(self._goals):
            return None
        return self._goals[self._index]

    def advance(self) -> Goal | None:
        """Move to the next goal. Returns the new active goal or None."""
        self._index += 1
        goal = self.active_goal
        if goal:
            logger.info("Goal advanced to: %s", goal.name)
        else:
            logger.info("All goals exhausted")
        return goal

    def should_advance(self, gaps: list[KnowledgeGap]) -> bool:
        """True if no remaining gaps match the active goal."""
        goal = self.active_goal
        if goal is None:
            return False
        return not any(goal.matches_gap(g) for g in gaps)

    def prioritize_gaps(self, gaps: list[KnowledgeGap]) -> list[KnowledgeGap]:
        """Boost priorities of gaps matching the active goal.

        Non-matching gaps keep their original priority. Returns a new
        sorted list (original gaps are mutated in-place for priority).
        """
        goal = self.active_goal
        if goal is None:
            return gaps

        for gap in gaps:
            if goal.matches_gap(gap):
                gap.priority *= goal.priority

        gaps.sort(key=lambda g: g.priority, reverse=True)
        return gaps

    def select_for_graph(self, graph: KnowledgeGraph) -> Goal | None:
        """Auto-select goal based on current graph state.

        Heuristic:
        - hosts > 0, services == 0 → RECON
        - services > 0, endpoints == 0 → SURFACE_MAPPING
        - endpoints > 0, findings < 3 → EXPLOIT
        - findings >= 3 → VERIFICATION
        """
        hosts = len(graph.hosts())
        services = len(graph.services())
        endpoints = len(graph.endpoints())
        findings = len(graph.findings())

        if hosts > 0 and services == 0:
            target_type = GoalType.RECON
        elif services > 0 and endpoints == 0:
            target_type = GoalType.SURFACE_MAPPING
        elif endpoints > 0 and findings < 3:
            target_type = GoalType.EXPLOIT
        else:
            target_type = GoalType.VERIFICATION

        for i, goal in enumerate(self._goals):
            if goal.type == target_type:
                self._index = i
                logger.info("Auto-selected goal: %s", goal.name)
                return goal

        return self.active_goal

    def goal_progress_delta(
        self, before_snapshot: dict[str, int], after_snapshot: dict[str, int],
    ) -> float:
        """Compute progress toward the active goal between two snapshots.

        Maps GoalType to relevant metrics and returns normalized delta [0.0, 1.0].
        Snapshots should have keys: host_count, service_count, endpoint_count,
        technology_count, finding_count, vulnerability_count.
        """
        goal = self.active_goal
        if goal is None:
            return 0.0

        # Map goal types to relevant metrics
        goal_metrics: dict[GoalType, list[str]] = {
            GoalType.RECON: ["host_count", "service_count"],
            GoalType.SURFACE_MAPPING: ["endpoint_count", "technology_count"],
            GoalType.EXPLOIT: ["finding_count"],
            GoalType.PRIVILEGE_ESCALATION: ["finding_count"],
            GoalType.VERIFICATION: ["finding_count"],
        }

        metrics = goal_metrics.get(goal.type, [])
        if not metrics:
            return 0.0

        total_delta = 0.0
        for metric in metrics:
            before = before_snapshot.get(metric, 0)
            after = after_snapshot.get(metric, 0)
            if after > before:
                total_delta += (after - before)

        # Normalize: each new entity contributes ~0.05, cap at 1.0
        return min(total_delta * 0.05, 1.0)
