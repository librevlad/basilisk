"""Tests for container planner rules."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.orchestrator.planner import (
    Planner,
    _container_runtime_without_enumeration,
    _container_without_config_audit,
    _container_without_image_analysis,
    _host_without_container_check,
)


class TestHostWithoutContainerCheck:
    def test_docker_port_triggers_gap(self):
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        svc = Entity.service("example.com", 2375, "tcp")
        graph.add_entity(host)
        graph.add_entity(svc)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))

        gaps = _host_without_container_check(graph)
        assert len(gaps) == 1
        assert gaps[0].missing == "container_runtime"
        assert gaps[0].priority == 6.0

    def test_container_runtime_tech_triggers_gap(self):
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        tech = Entity.technology("example.com", "docker", "24.0")
        tech.data["is_container_runtime"] = True
        graph.add_entity(host)
        graph.add_entity(tech)
        graph.add_relation(Relation(
            source_id=host.id, target_id=tech.id, type=RelationType.RUNS,
        ))

        gaps = _host_without_container_check(graph)
        assert len(gaps) == 1

    def test_no_gap_when_checked(self):
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        host.data["container_runtime_checked"] = True
        svc = Entity.service("example.com", 2375, "tcp")
        graph.add_entity(host)
        graph.add_entity(svc)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))

        gaps = _host_without_container_check(graph)
        assert len(gaps) == 0

    def test_no_gap_without_docker_ports(self):
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        svc = Entity.service("example.com", 80, "tcp")
        graph.add_entity(host)
        graph.add_entity(svc)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))

        gaps = _host_without_container_check(graph)
        assert len(gaps) == 0

    def test_k8s_port_triggers_gap(self):
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        svc = Entity.service("example.com", 10250, "tcp")
        graph.add_entity(host)
        graph.add_entity(svc)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))

        gaps = _host_without_container_check(graph)
        assert len(gaps) == 1


class TestRuntimeWithoutEnumeration:
    def test_runtime_triggers_enumeration_gap(self):
        graph = KnowledgeGraph()
        tech = Entity.technology("example.com", "docker", "24.0")
        tech.data["is_container_runtime"] = True
        graph.add_entity(tech)

        gaps = _container_runtime_without_enumeration(graph)
        assert len(gaps) == 1
        assert gaps[0].missing == "container_enumeration"
        assert gaps[0].priority == 7.0

    def test_no_gap_when_enumerated(self):
        graph = KnowledgeGraph()
        tech = Entity.technology("example.com", "docker")
        tech.data["is_container_runtime"] = True
        tech.data["containers_enumerated"] = True
        graph.add_entity(tech)

        gaps = _container_runtime_without_enumeration(graph)
        assert len(gaps) == 0

    def test_non_runtime_tech_ignored(self):
        graph = KnowledgeGraph()
        tech = Entity.technology("example.com", "nginx")
        graph.add_entity(tech)

        gaps = _container_runtime_without_enumeration(graph)
        assert len(gaps) == 0


class TestContainerWithoutConfigAudit:
    def test_container_triggers_audit_gap(self):
        graph = KnowledgeGraph()
        container = Entity.container("example.com", "abc123")
        graph.add_entity(container)

        gaps = _container_without_config_audit(graph)
        assert len(gaps) == 1
        assert gaps[0].missing == "container_config_audit"
        assert gaps[0].priority == 5.5

    def test_no_gap_when_audited(self):
        graph = KnowledgeGraph()
        container = Entity.container("example.com", "abc123")
        container.data["config_audited"] = True
        graph.add_entity(container)

        gaps = _container_without_config_audit(graph)
        assert len(gaps) == 0

    def test_dedup_per_host(self):
        """Only one gap per host even with multiple containers."""
        graph = KnowledgeGraph()
        graph.add_entity(Entity.container("example.com", "abc"))
        graph.add_entity(Entity.container("example.com", "def"))

        gaps = _container_without_config_audit(graph)
        assert len(gaps) == 1

    def test_different_hosts_separate_gaps(self):
        graph = KnowledgeGraph()
        graph.add_entity(Entity.container("a.com", "abc"))
        graph.add_entity(Entity.container("b.com", "def"))

        gaps = _container_without_config_audit(graph)
        assert len(gaps) == 2


class TestContainerWithoutImageAnalysis:
    def test_image_triggers_analysis_gap(self):
        graph = KnowledgeGraph()
        image = Entity.image("example.com", "nginx", "1.24")
        graph.add_entity(image)

        gaps = _container_without_image_analysis(graph)
        assert len(gaps) == 1
        assert gaps[0].missing == "image_analysis"
        assert gaps[0].priority == 5.0

    def test_no_gap_when_checked(self):
        graph = KnowledgeGraph()
        image = Entity.image("example.com", "nginx")
        image.data["vulnerabilities_checked"] = True
        graph.add_entity(image)

        gaps = _container_without_image_analysis(graph)
        assert len(gaps) == 0


class TestPlannerIncludesContainerRules:
    def test_container_rules_in_planner(self):
        """Planner includes all container gap rules."""
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        svc = Entity.service("example.com", 2375, "tcp")
        tech = Entity.technology("example.com", "docker")
        tech.data["is_container_runtime"] = True
        container = Entity.container("example.com", "abc123")
        image = Entity.image("example.com", "nginx")

        graph.add_entity(host)
        graph.add_entity(svc)
        graph.add_entity(tech)
        graph.add_entity(container)
        graph.add_entity(image)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        graph.add_relation(Relation(
            source_id=host.id, target_id=tech.id, type=RelationType.RUNS,
        ))

        planner = Planner()
        gaps = planner.find_gaps(graph)
        missing_types = {g.missing for g in gaps}

        assert "container_runtime" in missing_types
        assert "container_enumeration" in missing_types
        assert "container_config_audit" in missing_types
        assert "image_analysis" in missing_types
