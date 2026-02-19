"""Tests for capability selector."""

from __future__ import annotations

from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.orchestrator.planner import KnowledgeGap
from basilisk.orchestrator.selector import Selector
from basilisk.scoring.scorer import ScoredCapability


def _cap(
    name: str = "test",
    requires: list[str] | None = None,
    produces: list[str] | None = None,
) -> Capability:
    return Capability(
        name=name,
        plugin_name=name,
        category="recon",
        requires_knowledge=requires or ["Host"],
        produces_knowledge=produces or ["Finding"],
        cost_score=2.0,
        noise_score=2.0,
    )


def _gap(entity: Entity, missing: str = "services") -> KnowledgeGap:
    return KnowledgeGap(entity=entity, missing=missing, priority=5.0, description="test gap")


class TestSelectorMatch:
    def test_matches_service_producing_cap_to_service_gap(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        g.add_entity(host)

        selector = Selector({"port_scan": _cap("port_scan", produces=["Service"])})
        gaps = [_gap(host, "services")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 1
        assert candidates[0][0].name == "port_scan"

    def test_no_match_when_produces_mismatch(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        g.add_entity(host)

        selector = Selector({"xss": _cap("xss", produces=["Finding:xss"])})
        gaps = [_gap(host, "services")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 0

    def test_match_requires_http_service(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        svc = Entity.service("test.com", 80)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))

        selector = Selector({
            "tech": _cap("tech", requires=["Host", "Service:http"], produces=["Technology"]),
        })
        gaps = [_gap(host, "technology")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 1

    def test_no_match_when_requirements_unmet(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        g.add_entity(host)

        selector = Selector({
            "tech": _cap("tech", requires=["Host", "Service:http"], produces=["Technology"]),
        })
        gaps = [_gap(host, "technology")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 0

    def test_dedup_candidates(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        g.add_entity(host)

        selector = Selector({"scan": _cap("scan", produces=["Service"])})
        gaps = [_gap(host, "services"), _gap(host, "services")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 1


class TestSelectorPick:
    def test_pick_respects_budget(self):
        host = Entity.host("test.com")
        scored = [
            ScoredCapability(capability=_cap(f"c{i}"), target_entity=host, score=10 - i, reason="")
            for i in range(10)
        ]
        chosen = Selector.pick(scored, budget=3)
        assert len(chosen) == 3

    def test_pick_dedup_plugin_entity(self):
        host = Entity.host("test.com")
        cap = _cap("scan")
        scored = [
            ScoredCapability(capability=cap, target_entity=host, score=10, reason=""),
            ScoredCapability(capability=cap, target_entity=host, score=8, reason=""),
        ]
        chosen = Selector.pick(scored, budget=5)
        assert len(chosen) == 1

    def test_pick_allows_different_targets(self):
        h1 = Entity.host("a.com")
        h2 = Entity.host("b.com")
        cap = _cap("scan")
        scored = [
            ScoredCapability(capability=cap, target_entity=h1, score=10, reason=""),
            ScoredCapability(capability=cap, target_entity=h2, score=8, reason=""),
        ]
        chosen = Selector.pick(scored, budget=5)
        assert len(chosen) == 2

    def test_pick_empty(self):
        chosen = Selector.pick([], budget=5)
        assert chosen == []
