"""Tests for container selector matching."""

from __future__ import annotations

from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.orchestrator.selector import (
    _GAP_TO_PRODUCES,
    _matches_service_type,
    _requirements_met,
)


class TestContainerGapToProduces:
    def test_container_runtime_mapping(self):
        patterns = _GAP_TO_PRODUCES["container_runtime"]
        assert "Technology:container_runtime" in patterns
        assert "Container" in patterns

    def test_container_enumeration_mapping(self):
        patterns = _GAP_TO_PRODUCES["container_enumeration"]
        assert "Container" in patterns
        assert "Image" in patterns

    def test_container_config_audit_mapping(self):
        patterns = _GAP_TO_PRODUCES["container_config_audit"]
        assert "Finding" in patterns

    def test_image_analysis_mapping(self):
        patterns = _GAP_TO_PRODUCES["image_analysis"]
        assert "Finding" in patterns
        assert "Vulnerability" in patterns


class TestContainerRequirementsMet:
    def test_container_requirement_with_container_entity(self):
        cap = Capability(
            name="test", plugin_name="test", category="analysis",
            requires_knowledge=["Container"],
            produces_knowledge=["Finding"],
        )
        container = Entity.container("example.com", "abc123")
        graph = KnowledgeGraph()
        graph.add_entity(container)

        assert _requirements_met(cap, container, graph) is True

    def test_container_requirement_with_host_and_containers(self):
        cap = Capability(
            name="test", plugin_name="test", category="analysis",
            requires_knowledge=["Container"],
            produces_knowledge=["Finding"],
        )
        host = Entity.host("example.com")
        container = Entity.container("example.com", "abc123")
        graph = KnowledgeGraph()
        graph.add_entity(host)
        graph.add_entity(container)

        assert _requirements_met(cap, host, graph) is True

    def test_container_requirement_fails_without_containers(self):
        cap = Capability(
            name="test", plugin_name="test", category="analysis",
            requires_knowledge=["Container"],
            produces_knowledge=["Finding"],
        )
        host = Entity.host("example.com")
        graph = KnowledgeGraph()
        graph.add_entity(host)

        assert _requirements_met(cap, host, graph) is False

    def test_image_requirement_with_image_entity(self):
        cap = Capability(
            name="test", plugin_name="test", category="analysis",
            requires_knowledge=["Image"],
            produces_knowledge=["Finding"],
        )
        image = Entity.image("example.com", "nginx")
        graph = KnowledgeGraph()
        graph.add_entity(image)

        assert _requirements_met(cap, image, graph) is True

    def test_image_requirement_fails_with_host(self):
        cap = Capability(
            name="test", plugin_name="test", category="analysis",
            requires_knowledge=["Image"],
            produces_knowledge=["Finding"],
        )
        host = Entity.host("example.com")
        graph = KnowledgeGraph()
        graph.add_entity(host)

        assert _requirements_met(cap, host, graph) is False


class TestDockerServiceType:
    def test_docker_port_2375(self):
        svc = Entity.service("example.com", 2375, "tcp")
        assert _matches_service_type(svc, "docker") is True

    def test_docker_port_2376(self):
        svc = Entity.service("example.com", 2376, "tcp")
        assert _matches_service_type(svc, "docker") is True

    def test_docker_service_name(self):
        svc = Entity.service("example.com", 9999, "tcp")
        svc.data["service"] = "docker"
        assert _matches_service_type(svc, "docker") is True

    def test_non_docker_port(self):
        svc = Entity.service("example.com", 80, "tcp")
        assert _matches_service_type(svc, "docker") is False
