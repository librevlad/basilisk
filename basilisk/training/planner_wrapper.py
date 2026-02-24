"""Training planner wrapper — injects gaps for undiscovered expected findings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from basilisk.orchestrator.planner import KnowledgeGap

if TYPE_CHECKING:
    from basilisk.knowledge.entities import Entity
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.orchestrator.planner import Planner
    from basilisk.training.profile import ExpectedFinding, TrainingProfile
    from basilisk.training.validator import FindingTracker

# Map finding category to gap types that trigger relevant plugins.
_CATEGORY_GAP_MAP: dict[str, list[str]] = {
    "sqli": ["vulnerability_testing", "host_vulnerability_testing"],
    "xss": ["vulnerability_testing", "host_vulnerability_testing"],
    "auth": ["credential_exploitation", "host_vulnerability_testing"],
    "config": ["host_vulnerability_testing"],
    "injection": ["vulnerability_testing", "host_vulnerability_testing"],
    "lfi": ["vulnerability_testing", "host_vulnerability_testing"],
    "csrf": ["host_vulnerability_testing"],
    "upload": ["vulnerability_testing", "host_vulnerability_testing"],
    "crypto": ["host_vulnerability_testing"],
    "dos": ["host_vulnerability_testing"],
    "logic": ["host_vulnerability_testing"],
}


class TrainingPlanner:
    """Wraps Planner: adds synthetic gaps for undiscovered expected findings.

    Duck-type compatible — injected into AutonomousLoop in place of the real Planner.
    """

    def __init__(
        self,
        planner: Planner,
        tracker: FindingTracker,
        profile: TrainingProfile,
    ) -> None:
        self._planner = planner
        self._tracker = tracker
        self._profile = profile

    def find_gaps(self, graph: KnowledgeGraph) -> list[KnowledgeGap]:
        """Run real planner, then inject/boost gaps for undiscovered findings."""
        # 1. Sync tracker with current graph findings
        for finding in graph.findings():
            self._tracker.check_discovery(finding, step=0)

        # 2. Check verification status via 'verified' flag in entity data
        for tf in self._tracker.tracked:
            if tf.discovered and not tf.verified:
                entity = graph.get(tf.matched_entity_id)
                if entity and entity.data.get("verified"):
                    self._tracker.check_verification(tf.matched_entity_id, step=0)

        # 3. Get real gaps from underlying planner
        gaps = self._planner.find_gaps(graph)

        # 4. Boost verification gaps for discovered-but-unverified findings
        for gap in gaps:
            if gap.missing == "finding_verification":
                for tf in self._tracker.tracked:
                    if (
                        tf.discovered
                        and not tf.verified
                        and tf.matched_entity_id == gap.entity.id
                    ):
                        gap.priority = max(gap.priority, 15.0)
                        break

        # 5. Inject hint gaps for undiscovered findings
        host_entity = self._find_host_entity(graph)
        if host_entity:
            for tf in self._tracker.tracked:
                if not tf.discovered:
                    for gap_type in self._infer_gap_types(tf.expected):
                        gaps.append(KnowledgeGap(
                            entity=host_entity,
                            missing=gap_type,
                            priority=12.0,
                            description=f"Training: find '{tf.expected.title}'",
                        ))

        gaps.sort(key=lambda g: g.priority, reverse=True)
        return gaps

    @staticmethod
    def _infer_gap_types(ef: ExpectedFinding) -> list[str]:
        """Infer gap types from expected finding category."""
        return _CATEGORY_GAP_MAP.get(ef.category, ["host_vulnerability_testing"])

    @staticmethod
    def _find_host_entity(graph: KnowledgeGraph) -> Entity | None:
        """Return first host entity from the graph."""
        hosts = graph.hosts()
        return hosts[0] if hosts else None
