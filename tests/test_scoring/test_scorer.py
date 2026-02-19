"""Tests for the priority scoring engine."""

from __future__ import annotations

from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.scoring.scorer import Scorer


def _cap(name: str = "test", cost: float = 2.0, noise: float = 2.0, produces: int = 2) -> Capability:
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
