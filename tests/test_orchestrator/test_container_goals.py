"""Tests for container goal and attack path integration."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.orchestrator.attack_paths import ATTACK_PATHS, _precondition_met
from basilisk.orchestrator.goals import DEFAULT_GOAL_PROGRESSION, GoalType
from basilisk.orchestrator.planner import KnowledgeGap


class TestContainerGoalIntegration:
    def test_surface_mapping_includes_container_runtime(self):
        surface = next(g for g in DEFAULT_GOAL_PROGRESSION if g.type == GoalType.SURFACE_MAPPING)
        assert "container_runtime" in surface.relevant_gap_types
        assert "container" in surface.relevant_risk_domains

    def test_exploit_includes_container_gaps(self):
        exploit = next(g for g in DEFAULT_GOAL_PROGRESSION if g.type == GoalType.EXPLOIT)
        assert "container_enumeration" in exploit.relevant_gap_types
        assert "container_config_audit" in exploit.relevant_gap_types
        assert "image_analysis" in exploit.relevant_gap_types
        assert "container" in exploit.relevant_risk_domains

    def test_surface_mapping_matches_container_gap(self):
        surface = next(g for g in DEFAULT_GOAL_PROGRESSION if g.type == GoalType.SURFACE_MAPPING)
        host = Entity.host("example.com")
        gap = KnowledgeGap(
            entity=host, missing="container_runtime",
            priority=6.0, description="test",
        )
        assert surface.matches_gap(gap) is True

    def test_exploit_matches_container_enum_gap(self):
        exploit = next(g for g in DEFAULT_GOAL_PROGRESSION if g.type == GoalType.EXPLOIT)
        host = Entity.host("example.com")
        gap = KnowledgeGap(
            entity=host, missing="container_enumeration",
            priority=7.0, description="test",
        )
        assert exploit.matches_gap(gap) is True


class TestContainerAttackPath:
    def test_container_exploitation_path_exists(self):
        names = [p.name for p in ATTACK_PATHS]
        assert "container_exploitation" in names

    def test_container_path_preconditions(self):
        path = next(p for p in ATTACK_PATHS if p.name == "container_exploitation")
        assert "Technology:docker" in path.preconditions

    def test_container_path_actions(self):
        path = next(p for p in ATTACK_PATHS if p.name == "container_exploitation")
        assert "container_enumeration" in path.actions
        assert "container_config_audit" in path.actions
        assert "container_escape_probe" in path.actions
        assert "image_fingerprint" in path.actions

    def test_docker_precondition_met(self):
        graph = KnowledgeGraph()
        tech = Entity.technology("example.com", "docker", "24.0")
        tech.data["is_container_runtime"] = True
        graph.add_entity(tech)

        assert _precondition_met("Technology:docker", graph) is True

    def test_docker_precondition_by_name(self):
        graph = KnowledgeGraph()
        tech = Entity.technology("example.com", "Docker Engine", "24.0")
        graph.add_entity(tech)

        assert _precondition_met("Technology:docker", graph) is True

    def test_docker_precondition_not_met(self):
        graph = KnowledgeGraph()
        tech = Entity.technology("example.com", "nginx", "1.24")
        graph.add_entity(tech)

        assert _precondition_met("Technology:docker", graph) is False
