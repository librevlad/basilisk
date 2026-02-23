"""Tests for the priority scoring engine."""

from __future__ import annotations

from datetime import UTC, datetime

from basilisk.capabilities.capability import Capability
from basilisk.decisions.decision import Decision
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.memory.history import History
from basilisk.scoring.scorer import Scorer


def _cap(
    name: str = "test", cost: float = 2.0, noise: float = 2.0, produces: int = 2,
) -> Capability:
    return Capability(
        name=name,
        plugin_name=name,
        category="recon",
        requires_knowledge=["Host"],
        produces_knowledge=[f"prod_{i}" for i in range(produces)],
        cost_score=cost,
        noise_score=noise,
    )


def _host(name: str = "example.com") -> Entity:
    return Entity.host(name)


class TestScorer:
    def test_rank_returns_sorted(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)

        cap1 = _cap("cheap", cost=1, noise=1, produces=3)
        cap2 = _cap("expensive", cost=8, noise=8, produces=1)

        scored = scorer.rank([(cap1, host), (cap2, host)])
        assert len(scored) == 2
        # Cheap + more produces should score higher
        assert scored[0].capability.name == "cheap"
        assert scored[0].score > scored[1].score

    def test_repetition_penalty(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        g.record_execution(f"test:{host.id}")
        scorer = Scorer(g)

        cap = _cap("test")
        scored = scorer.rank([(cap, host)])
        # Score should be low due to repetition
        assert scored[0].score < 0.5

    def test_novelty_decays_with_observations(self):
        g = KnowledgeGraph()
        fresh = _host("fresh.com")
        g.add_entity(fresh)

        stale = _host("stale.com")
        stale.observation_count = 10
        g.add_entity(stale)

        scorer = Scorer(g)
        cap = _cap()

        scored = scorer.rank([(cap, fresh), (cap, stale)])
        # Fresh entity should score higher
        fresh_score = next(s for s in scored if s.target_entity.data["host"] == "fresh.com")
        stale_score = next(s for s in scored if s.target_entity.data["host"] == "stale.com")
        assert fresh_score.score > stale_score.score

    def test_high_confidence_low_gain(self):
        g = KnowledgeGraph()
        certain = _host("certain.com")
        certain.confidence = 0.99
        g.add_entity(certain)

        uncertain = _host("uncertain.com")
        uncertain.confidence = 0.1
        g.add_entity(uncertain)

        scorer = Scorer(g)
        cap = _cap()

        scored = scorer.rank([(cap, certain), (cap, uncertain)])
        uncertain_sc = next(s for s in scored if s.target_entity.data["host"] == "uncertain.com")
        certain_sc = next(s for s in scored if s.target_entity.data["host"] == "certain.com")
        assert uncertain_sc.score > certain_sc.score

    def test_reason_string(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)
        scored = scorer.rank([(_cap(), host)])
        assert "score=" in scored[0].reason
        assert "cost=" in scored[0].reason

    def test_empty_candidates(self):
        g = KnowledgeGraph()
        scorer = Scorer(g)
        scored = scorer.rank([])
        assert scored == []

    def test_score_is_positive(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)
        scored = scorer.rank([(_cap(), host)])
        assert scored[0].score > 0

    def test_lower_cost_higher_score(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)

        cheap = _cap("cheap", cost=1, noise=1, produces=2)
        pricey = _cap("pricey", cost=9, noise=1, produces=2)

        scored = scorer.rank([(cheap, host), (pricey, host)])
        assert scored[0].capability.name == "cheap"

    def test_lower_noise_higher_score(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)

        quiet = _cap("quiet", cost=1, noise=1, produces=2)
        loud = _cap("loud", cost=1, noise=9, produces=2)

        scored = scorer.rank([(quiet, host), (loud, host)])
        assert scored[0].capability.name == "quiet"


class TestScorerBreakdown:
    def test_breakdown_has_all_keys(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)
        scored = scorer.rank([(_cap(), host)])
        bd = scored[0].score_breakdown
        assert "novelty" in bd
        assert "knowledge_gain" in bd
        assert "cost" in bd
        assert "noise" in bd
        assert "repetition_penalty" in bd
        assert "success_probability" in bd
        assert "raw_score" in bd

    def test_breakdown_raw_score_matches(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)
        scored = scorer.rank([(_cap(), host)])
        assert abs(scored[0].score - scored[0].score_breakdown["raw_score"]) < 1e-9

    def test_backward_compat_without_history(self):
        """Scorer without history should work identically to v3.0."""
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)
        scored = scorer.rank([(_cap(), host)])
        assert scored[0].score > 0
        assert scored[0].score_breakdown["repetition_penalty"] == 0.0


class TestScorerWithHistory:
    def test_history_repetition_penalty(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)

        history = History()
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        d = Decision(
            id=Decision.make_id(1, ts, "test", "example.com"),
            step=1, chosen_plugin="test", chosen_capability="test",
            chosen_target="example.com",
            triggering_entity_id=host.id,
        )
        history.record(d)

        scorer = Scorer(g, history=history)
        scored = scorer.rank([(_cap("test"), host)])
        assert scored[0].score_breakdown["repetition_penalty"] > 0

    def test_history_no_penalty_different_plugin(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)

        history = History()
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        d = Decision(
            id=Decision.make_id(1, ts, "other", "example.com"),
            step=1, chosen_plugin="other", chosen_capability="other",
            chosen_target="example.com",
            triggering_entity_id=host.id,
        )
        history.record(d)

        scorer = Scorer(g, history=history)
        scored = scorer.rank([(_cap("test"), host)])
        assert scored[0].score_breakdown["repetition_penalty"] == 0.0


class TestSuccessProbability:
    """Tests for _compute_success_probability and its effect on scoring."""

    def test_default_probability_is_half(self):
        """Without tracker or campaign, probability defaults to 0.5."""
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)
        scored = scorer.rank([(_cap(), host)])
        assert scored[0].score_breakdown["success_probability"] == 0.5

    def test_tracker_provides_probability(self):
        """CostTracker with >= 2 runs provides success_rate as probability."""
        from basilisk.orchestrator.cost_tracker import CostTracker

        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)

        tracker = CostTracker()
        tracker.record("test", new_entities=3, findings=1, runtime=5.0)
        tracker.record("test", new_entities=0, findings=0, runtime=4.0)
        tracker.record("test", new_entities=2, findings=0, runtime=3.0)
        # 2 out of 3 runs successful -> 0.667

        scorer = Scorer(g, cost_tracker=tracker)
        scored = scorer.rank([(_cap("test"), host)])
        prob = scored[0].score_breakdown["success_probability"]
        assert abs(prob - 2.0 / 3.0) < 1e-6

    def test_campaign_provides_probability(self):
        """CampaignMemory provides probability when no tracker available."""
        from unittest.mock import MagicMock

        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)

        campaign = MagicMock()
        campaign.plugin_success_rate.return_value = 0.8
        campaign.adjusted_cost.return_value = 2.0
        campaign.is_known_infrastructure.return_value = False
        campaign.known_technologies.return_value = []

        scorer = Scorer(g, campaign_memory=campaign)
        scored = scorer.rank([(_cap("test"), host)])
        assert scored[0].score_breakdown["success_probability"] == 0.8

    def test_tracker_priority_over_campaign(self):
        """When both tracker and campaign are available, tracker wins."""
        from unittest.mock import MagicMock

        from basilisk.orchestrator.cost_tracker import CostTracker

        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)

        tracker = CostTracker()
        tracker.record("test", new_entities=1, findings=0, runtime=2.0)
        tracker.record("test", new_entities=1, findings=0, runtime=2.0)
        # 100% success rate

        campaign = MagicMock()
        campaign.plugin_success_rate.return_value = 0.3
        campaign.adjusted_cost.return_value = 2.0
        campaign.is_known_infrastructure.return_value = False
        campaign.known_technologies.return_value = []

        scorer = Scorer(g, cost_tracker=tracker, campaign_memory=campaign)
        scored = scorer.rank([(_cap("test"), host)])
        # Should use tracker's 1.0, not campaign's 0.3
        assert scored[0].score_breakdown["success_probability"] == 1.0

    def test_floor_at_five_percent(self):
        """Success probability never drops below 0.05."""
        from basilisk.orchestrator.cost_tracker import CostTracker

        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)

        tracker = CostTracker()
        # 0% success rate (10 runs, no results)
        for _ in range(10):
            tracker.record("test", new_entities=0, findings=0, runtime=1.0)

        scorer = Scorer(g, cost_tracker=tracker)
        scored = scorer.rank([(_cap("test"), host)])
        assert scored[0].score_breakdown["success_probability"] == 0.05

    def test_tracker_ignored_with_few_runs(self):
        """Tracker with < 2 runs falls back to campaign or default."""
        from basilisk.orchestrator.cost_tracker import CostTracker

        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)

        tracker = CostTracker()
        tracker.record("test", new_entities=0, findings=0, runtime=1.0)
        # Only 1 run — not enough data

        scorer = Scorer(g, cost_tracker=tracker)
        scored = scorer.rank([(_cap("test"), host)])
        assert scored[0].score_breakdown["success_probability"] == 0.5

    def test_high_probability_boosts_score(self):
        """Higher success probability should result in higher scores."""
        from basilisk.orchestrator.cost_tracker import CostTracker

        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)

        # High success tracker
        high_tracker = CostTracker()
        high_tracker.record("test", new_entities=5, findings=2, runtime=1.0)
        high_tracker.record("test", new_entities=3, findings=1, runtime=1.0)

        scorer_high = Scorer(g, cost_tracker=high_tracker)
        scored_high = scorer_high.rank([(_cap("test"), host)])

        # Low success tracker
        low_tracker = CostTracker()
        low_tracker.record("test", new_entities=0, findings=0, runtime=1.0)
        low_tracker.record("test", new_entities=0, findings=0, runtime=1.0)

        scorer_low = Scorer(g, cost_tracker=low_tracker)
        scored_low = scorer_low.rank([(_cap("test"), host)])

        assert scored_high[0].score > scored_low[0].score
