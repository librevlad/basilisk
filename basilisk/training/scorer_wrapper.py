"""Training scorer wrapper — boosts hint-matched and verification plugins."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from basilisk.capabilities.capability import Capability
    from basilisk.knowledge.entities import Entity
    from basilisk.scoring.scorer import ScoredCapability, Scorer
    from basilisk.training.profile import TrainingProfile
    from basilisk.training.validator import FindingTracker


class TrainingScorer:
    """Wraps Scorer: boosts plugins matching expected finding hints.

    Duck-type compatible — injected into AutonomousLoop in place of the real Scorer.
    """

    def __init__(
        self,
        scorer: Scorer,
        tracker: FindingTracker,
        profile: TrainingProfile,
    ) -> None:
        self._scorer = scorer
        self._tracker = tracker
        self._profile = profile
        self._hint_plugins = self._collect_hint_plugins()

    def _collect_hint_plugins(self) -> set[str]:
        """Collect all plugin names mentioned as hints in the profile."""
        plugins: set[str] = set()
        for ef in self._profile.expected_findings:
            plugins.update(ef.plugin_hints)
        return plugins

    def rank(
        self, candidates: list[tuple[Capability, Entity]],
    ) -> list[ScoredCapability]:
        """Score using real scorer, then apply training boosts."""
        scored = self._scorer.rank(candidates)

        for sc in scored:
            # Boost plugins that are hint-matched
            if sc.capability.plugin_name in self._hint_plugins:
                sc.score *= 2.0
                sc.score_breakdown["training_boost"] = 2.0

            # Boost verification plugins for discovered-but-unverified findings
            if sc.capability.reduces_uncertainty:
                for tf in self._tracker.tracked:
                    if (
                        tf.discovered
                        and not tf.verified
                        and tf.matched_entity_id == sc.target_entity.id
                    ):
                        sc.score *= 3.0
                        sc.score_breakdown["verification_boost"] = 3.0
                        break

        scored.sort(key=lambda s: s.score, reverse=True)
        return scored
