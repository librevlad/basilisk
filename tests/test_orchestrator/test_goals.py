"""Tests for the Goal Engine."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.orchestrator.goals import (
    DEFAULT_GOAL_PROGRESSION,
    Goal,
    GoalEngine,
    GoalType,
)
from basilisk.orchestrator.planner import KnowledgeGap


def _gap(entity: Entity, missing: str, priority: float = 5.0) -> KnowledgeGap:
    return KnowledgeGap(
        entity=entity, missing=missing, priority=priority,
        description=f"Test gap: {missing}",
    )


def _host(name: str = "example.com") -> Entity:
    return Entity.host(name)


class TestGoal:
    def test_matches_gap(self):
        goal = Goal(
            type=GoalType.RECON, name="Recon", priority=1.5,
            relevant_gap_types=["services", "dns"],
            relevant_risk_domains=["recon"],
        )
        host = _host()
        assert goal.matches_gap(_gap(host, "services"))
        assert goal.matches_gap(_gap(host, "dns"))
        assert not goal.matches_gap(_gap(host, "technology"))

    def test_matches_risk_domain(self):
        goal = Goal(
            type=GoalType.EXPLOIT, name="Exploit", priority=1.2,
            relevant_gap_types=["vulnerability_testing"],
            relevant_risk_domains=["web", "auth"],
        )
        assert goal.matches_risk_domain("web")
        assert goal.matches_risk_domain("auth")
        assert not goal.matches_risk_domain("recon")


class TestGoalEngine:
    def test_active_goal_starts_at_first(self):
        engine = GoalEngine(goals=list(DEFAULT_GOAL_PROGRESSION))
        assert engine.active_goal is not None
        assert engine.active_goal.type == GoalType.RECON

    def test_advance(self):
        engine = GoalEngine(goals=list(DEFAULT_GOAL_PROGRESSION))
        engine.advance()
        assert engine.active_goal.type == GoalType.SURFACE_MAPPING
        engine.advance()
        assert engine.active_goal.type == GoalType.EXPLOIT

    def test_advance_past_end_returns_none(self):
        goals = [Goal(
            type=GoalType.RECON, name="Only", priority=1.0,
            relevant_gap_types=["services"], relevant_risk_domains=["recon"],
        )]
        engine = GoalEngine(goals=goals)
        result = engine.advance()
        assert result is None
        assert engine.active_goal is None

    def test_transparent_when_no_goals(self):
        """GoalEngine without goals does not modify gaps."""
        engine = GoalEngine()
        assert engine.active_goal is None

        host = _host()
        gaps = [
            _gap(host, "services", priority=10.0),
            _gap(host, "technology", priority=7.0),
        ]
        result = engine.prioritize_gaps(gaps)
        assert result[0].priority == 10.0
        assert result[1].priority == 7.0

    def test_prioritize_gaps_boosts_matching(self):
        engine = GoalEngine(goals=[Goal(
            type=GoalType.RECON, name="Recon", priority=2.0,
            relevant_gap_types=["services"],
            relevant_risk_domains=["recon"],
        )])
        host = _host()
        gaps = [
            _gap(host, "technology", priority=7.0),
            _gap(host, "services", priority=5.0),
        ]
        result = engine.prioritize_gaps(gaps)
        # "services" should be boosted: 5.0 * 2.0 = 10.0 → now first
        assert result[0].missing == "services"
        assert result[0].priority == 10.0
        # "technology" unchanged
        assert result[1].missing == "technology"
        assert result[1].priority == 7.0

    def test_should_advance_when_no_matching_gaps(self):
        engine = GoalEngine(goals=[Goal(
            type=GoalType.RECON, name="Recon", priority=1.5,
            relevant_gap_types=["services", "dns"],
            relevant_risk_domains=["recon"],
        )])
        host = _host()
        # No recon gaps remain
        gaps = [_gap(host, "technology")]
        assert engine.should_advance(gaps)

    def test_should_not_advance_when_matching_gaps_exist(self):
        engine = GoalEngine(goals=[Goal(
            type=GoalType.RECON, name="Recon", priority=1.5,
            relevant_gap_types=["services", "dns"],
            relevant_risk_domains=["recon"],
        )])
        host = _host()
        gaps = [_gap(host, "services"), _gap(host, "technology")]
        assert not engine.should_advance(gaps)

    def test_should_advance_returns_false_when_no_active_goal(self):
        engine = GoalEngine()
        host = _host()
        assert not engine.should_advance([_gap(host, "services")])


class TestGoalEngineSelectForGraph:
    def test_recon_when_no_services(self):
        engine = GoalEngine(goals=list(DEFAULT_GOAL_PROGRESSION))
        graph = KnowledgeGraph()
        graph.add_entity(_host())
        result = engine.select_for_graph(graph)
        assert result.type == GoalType.RECON

    def test_surface_mapping_when_services_no_endpoints(self):
        engine = GoalEngine(goals=list(DEFAULT_GOAL_PROGRESSION))
        graph = KnowledgeGraph()
        host = _host()
        graph.add_entity(host)
        svc = Entity.service("example.com", 443, "tcp")
        graph.add_entity(svc)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        result = engine.select_for_graph(graph)
        assert result.type == GoalType.SURFACE_MAPPING

    def test_exploit_when_endpoints_few_findings(self):
        engine = GoalEngine(goals=list(DEFAULT_GOAL_PROGRESSION))
        graph = KnowledgeGraph()
        host = _host()
        graph.add_entity(host)
        svc = Entity.service("example.com", 443, "tcp")
        graph.add_entity(svc)
        ep = Entity.endpoint("example.com", "/api")
        graph.add_entity(ep)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        graph.add_relation(Relation(
            source_id=svc.id, target_id=ep.id, type=RelationType.HAS_ENDPOINT,
        ))
        result = engine.select_for_graph(graph)
        assert result.type == GoalType.EXPLOIT

    def test_verification_when_many_findings(self):
        engine = GoalEngine(goals=list(DEFAULT_GOAL_PROGRESSION))
        graph = KnowledgeGraph()
        host = _host()
        graph.add_entity(host)
        svc = Entity.service("example.com", 443, "tcp")
        graph.add_entity(svc)
        ep = Entity.endpoint("example.com", "/api")
        graph.add_entity(ep)
        for i in range(3):
            f = Entity.finding("example.com", f"XSS-{i}")
            graph.add_entity(f)
        result = engine.select_for_graph(graph)
        assert result.type == GoalType.VERIFICATION


class TestDefaultGoalProgression:
    def test_has_five_goals(self):
        assert len(DEFAULT_GOAL_PROGRESSION) == 5

    def test_order(self):
        types = [g.type for g in DEFAULT_GOAL_PROGRESSION]
        assert types == [
            GoalType.RECON,
            GoalType.SURFACE_MAPPING,
            GoalType.EXPLOIT,
            GoalType.PRIVILEGE_ESCALATION,
            GoalType.VERIFICATION,
        ]

    def test_all_have_relevant_gap_types(self):
        for goal in DEFAULT_GOAL_PROGRESSION:
            assert len(goal.relevant_gap_types) > 0
            assert len(goal.relevant_risk_domains) > 0
