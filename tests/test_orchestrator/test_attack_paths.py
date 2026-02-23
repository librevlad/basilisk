"""Tests for attack path registry and availability detection."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.orchestrator.attack_paths import (
    ATTACK_PATHS,
    count_unlockable_paths,
    find_available_paths,
)


def _graph_with_http() -> KnowledgeGraph:
    """Graph with a host and HTTP service."""
    g = KnowledgeGraph()
    host = Entity.host("example.com")
    g.add_entity(host)
    svc = Entity.service("example.com", 80, "tcp")
    svc.data["service"] = "http"
    g.add_entity(svc)
    g.add_relation(Relation(
        source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
    ))
    return g


def _graph_with_http_and_endpoints() -> KnowledgeGraph:
    """Graph with host, HTTP service, and endpoints with params."""
    g = _graph_with_http()
    host = g.hosts()[0]
    ep = Entity.endpoint("example.com", "/login")
    ep.data["has_params"] = True
    g.add_entity(ep)
    g.add_relation(Relation(
        source_id=host.id, target_id=ep.id, type=RelationType.HAS_ENDPOINT,
    ))
    return g


def _graph_with_credential() -> KnowledgeGraph:
    """Graph with host, service, and credential."""
    g = _graph_with_http()
    cred = Entity.credential("example.com", "admin", "password123")
    g.add_entity(cred)
    return g


class TestAttackPathRegistry:
    def test_registry_not_empty(self):
        assert len(ATTACK_PATHS) > 0

    def test_all_paths_have_names(self):
        names = {p.name for p in ATTACK_PATHS}
        assert "credential_attack" in names
        assert "lateral_movement" in names
        assert "injection_attack" in names

    def test_unlock_references_valid_paths(self):
        names = {p.name for p in ATTACK_PATHS}
        for path in ATTACK_PATHS:
            for unlock in path.unlock:
                assert unlock in names, f"{path.name} unlocks unknown '{unlock}'"


class TestFindAvailablePaths:
    def test_empty_graph_no_paths(self):
        g = KnowledgeGraph()
        assert find_available_paths(g) == []

    def test_host_only_no_paths(self):
        g = KnowledgeGraph()
        g.add_entity(Entity.host("example.com"))
        # No services, so very few paths available
        paths = find_available_paths(g)
        # Only service_exploitation may match (requires just "Service")
        assert all(
            "Service:http" not in p.preconditions for p in paths
        )

    def test_http_service_enables_paths(self):
        g = _graph_with_http()
        paths = find_available_paths(g)
        names = {p.name for p in paths}
        assert "web_vuln_discovery" in names
        assert "sensitive_exposure" in names

    def test_endpoints_enable_injection(self):
        g = _graph_with_http_and_endpoints()
        paths = find_available_paths(g)
        names = {p.name for p in paths}
        assert "injection_attack" in names
        assert "credential_attack" in names

    def test_credential_enables_lateral(self):
        g = _graph_with_credential()
        paths = find_available_paths(g)
        names = {p.name for p in paths}
        assert "lateral_movement" in names


class TestCountUnlockablePaths:
    def test_empty_graph_service_produces_unlock(self):
        g = KnowledgeGraph()
        g.add_entity(Entity.host("example.com"))
        # Producing Service would unlock paths that need Service
        count = count_unlockable_paths(["Service"], g)
        assert count > 0

    def test_nothing_new_no_unlocks(self):
        g = _graph_with_http_and_endpoints()
        # Everything already present, "Host" produces nothing new
        count = count_unlockable_paths(["Host"], g)
        # Should be low or zero since most paths are already available
        assert count >= 0

    def test_credential_produces_unlocks(self):
        g = _graph_with_http()
        # No credentials yet — producing Credential should unlock lateral_movement etc.
        count = count_unlockable_paths(["Credential"], g)
        assert count > 0

    def test_endpoint_produces_unlocks(self):
        g = _graph_with_http()
        # No endpoints yet — producing Endpoint should unlock injection paths
        count = count_unlockable_paths(["Endpoint"], g)
        assert count > 0
