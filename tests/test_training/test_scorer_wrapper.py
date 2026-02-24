"""Tests for TrainingScorer wrapper."""

from __future__ import annotations

from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.scoring.scorer import Scorer
from basilisk.training.profile import ExpectedFinding, TrainingProfile
from basilisk.training.scorer_wrapper import TrainingScorer
from basilisk.training.validator import FindingTracker


def _make_profile() -> TrainingProfile:
    return TrainingProfile(
        name="test",
        target="localhost",
        expected_findings=[
            ExpectedFinding(
                title="SQL Injection",
                severity="critical",
                category="sqli",
                plugin_hints=["sqli_basic"],
            ),
        ],
    )


def _make_capability(name: str, reduces_uncertainty: list[str] | None = None) -> Capability:
    return Capability(
        name=name,
        plugin_name=name,
        category="pentesting",
        requires_knowledge=["Host"],
        produces_knowledge=["Finding"],
        cost_score=2.0,
        noise_score=1.0,
        reduces_uncertainty=reduces_uncertainty or [],
    )


class TestTrainingScorer:
    def test_delegates_to_real_scorer(self):
        profile = _make_profile()
        tracker = FindingTracker(profile)
        graph = KnowledgeGraph()
        scorer = Scorer(graph)

        host = Entity.host("localhost")
        cap = _make_capability("other_plugin")
        candidates = [(cap, host)]

        wrapper = TrainingScorer(scorer, tracker, profile)
        scored = wrapper.rank(candidates)
        assert len(scored) == 1
        assert scored[0].capability.plugin_name == "other_plugin"

    def test_boosts_hint_plugins(self):
        profile = _make_profile()
        tracker = FindingTracker(profile)
        graph = KnowledgeGraph()
        scorer = Scorer(graph)

        host = Entity.host("localhost")
        hint_cap = _make_capability("sqli_basic")
        other_cap = _make_capability("other_plugin")
        candidates = [(other_cap, host), (hint_cap, host)]

        wrapper = TrainingScorer(scorer, tracker, profile)
        scored = wrapper.rank(candidates)

        hint_scored = [s for s in scored if s.capability.plugin_name == "sqli_basic"][0]
        other_scored = [s for s in scored if s.capability.plugin_name == "other_plugin"][0]

        assert hint_scored.score_breakdown.get("training_boost") == 2.0
        assert "training_boost" not in other_scored.score_breakdown

    def test_boosts_verification_for_unverified(self):
        profile = _make_profile()
        tracker = FindingTracker(profile)

        # Mark finding as discovered but not verified
        finding = Entity(
            id="f1", type=EntityType.FINDING,
            data={"title": "SQL Injection found", "severity": "critical"},
        )
        tracker.check_discovery(finding, step=1)

        graph = KnowledgeGraph()
        scorer = Scorer(graph)

        verify_cap = _make_capability("verify_plugin", reduces_uncertainty=["Finding"])
        candidates = [(verify_cap, finding)]

        wrapper = TrainingScorer(scorer, tracker, profile)
        scored = wrapper.rank(candidates)
        assert scored[0].score_breakdown.get("verification_boost") == 3.0

    def test_sorted_after_boosts(self):
        profile = _make_profile()
        tracker = FindingTracker(profile)
        graph = KnowledgeGraph()
        scorer = Scorer(graph)

        host = Entity.host("localhost")
        hint_cap = _make_capability("sqli_basic")
        other_cap = _make_capability("other_plugin")
        candidates = [(other_cap, host), (hint_cap, host)]

        wrapper = TrainingScorer(scorer, tracker, profile)
        scored = wrapper.rank(candidates)

        # Hint plugin should be first (higher score)
        assert scored[0].capability.plugin_name == "sqli_basic"
