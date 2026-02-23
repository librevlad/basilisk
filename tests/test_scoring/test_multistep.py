"""Tests for multi-step scoring and cost learning integration."""

from __future__ import annotations

from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.orchestrator.cost_tracker import CostTracker
from basilisk.scoring.scorer import Scorer


def _cap(
    name: str = "test", cost: float = 2.0, noise: float = 2.0, produces: list[str] | None = None,
) -> Capability:
    return Capability(
        name=name,
        plugin_name=name,
        category="recon",
        requires_knowledge=["Host"],
        produces_knowledge=produces or ["Service"],
        cost_score=cost,
        noise_score=noise,
    )


def _host(name: str = "example.com") -> Entity:
    return Entity.host(name)


class TestUnlockValue:
    def test_breakdown_includes_unlock_value(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)
        scored = scorer.rank([(_cap(), host)])
        assert "unlock_value" in scored[0].score_breakdown

    def test_service_producer_has_unlock_on_empty_graph(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)

        # Producing Service should unlock HTTP-dependent paths
        cap = _cap("port_scan", produces=["Service"])
        scored = scorer.rank([(cap, host)])
        assert scored[0].score_breakdown["unlock_value"] > 0

    def test_endpoint_producer_has_unlock(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        svc = Entity.service("example.com", 80, "tcp")
        svc.data["service"] = "http"
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))

        scorer = Scorer(g)
        # Producing Endpoint should unlock injection/credential paths
        cap = _cap("web_crawler", produces=["Endpoint"])
        scored = scorer.rank([(cap, host)])
        assert scored[0].score_breakdown["unlock_value"] > 0


class TestCostTrackerIntegration:
    def test_scorer_uses_adjusted_cost(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)

        tracker = CostTracker()
        # Plugin always fails
        for _ in range(5):
            tracker.record("bad_cap", new_entities=0, findings=0, runtime=1.0)

        scorer = Scorer(g, cost_tracker=tracker)
        cap = _cap("bad_cap", cost=2.0)
        scored = scorer.rank([(cap, host)])
        # Cost should be penalized → lower score
        assert scored[0].score_breakdown["cost"] > 2.0

    def test_scorer_without_tracker_uses_base_cost(self):
        g = KnowledgeGraph()
        host = _host()
        g.add_entity(host)
        scorer = Scorer(g)
        cap = _cap("test", cost=3.0)
        scored = scorer.rank([(cap, host)])
        assert scored[0].score_breakdown["cost"] == 3.0
