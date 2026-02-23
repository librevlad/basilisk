"""Tests for campaign data extraction from KnowledgeGraph."""

from __future__ import annotations

from basilisk.campaign.extractor import (
    _extract_base_domain,
    extract_plugin_efficacy,
    extract_target_profiles,
    extract_tech_fingerprints,
)
from basilisk.decisions.decision import Decision
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.memory.history import History


def _build_graph() -> KnowledgeGraph:
    """Build a small test graph."""
    g = KnowledgeGraph()

    host = Entity.host("example.com")
    g.add_entity(host)

    svc = Entity.service("example.com", 443, "tcp", service="https")
    g.add_entity(svc)
    g.add_relation(Relation(
        source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
    ))

    tech = Entity.technology("example.com", "nginx", "1.24")
    g.add_entity(tech)
    g.add_relation(Relation(
        source_id=host.id, target_id=tech.id, type=RelationType.RUNS,
    ))

    finding = Entity.finding("example.com", "XSS in /search", severity="HIGH")
    g.add_entity(finding)
    g.add_relation(Relation(
        source_id=finding.id, target_id=host.id, type=RelationType.RELATES_TO,
    ))

    ep = Entity.endpoint("example.com", "/api/v1")
    g.add_entity(ep)
    g.add_relation(Relation(
        source_id=host.id, target_id=ep.id, type=RelationType.HAS_ENDPOINT,
    ))

    return g


class TestExtractTargetProfiles:
    def test_extracts_host(self):
        g = _build_graph()
        profiles = extract_target_profiles(g)
        assert len(profiles) == 1
        p = profiles[0]
        assert p.host == "example.com"

    def test_extracts_services(self):
        g = _build_graph()
        p = extract_target_profiles(g)[0]
        assert len(p.known_services) == 1
        assert p.known_services[0].port == 443

    def test_extracts_technologies(self):
        g = _build_graph()
        p = extract_target_profiles(g)[0]
        assert len(p.known_technologies) == 1
        assert p.known_technologies[0].name == "nginx"
        assert p.known_technologies[0].version == "1.24"

    def test_extracts_endpoints_count(self):
        g = _build_graph()
        p = extract_target_profiles(g)[0]
        assert p.known_endpoints_count == 1

    def test_extracts_findings(self):
        g = _build_graph()
        p = extract_target_profiles(g)[0]
        assert p.known_findings_count == 1
        assert p.finding_severities.get("HIGH", 0) == 1

    def test_empty_graph(self):
        g = KnowledgeGraph()
        assert extract_target_profiles(g) == []


class TestExtractPluginEfficacy:
    def test_from_history(self):
        history = History()
        d = Decision(
            id="abc123",
            chosen_plugin="port_scan",
            outcome_new_entities=5,
            outcome_observations=3,
            outcome_confidence_delta=0.5,
            outcome_duration=2.1,
        )
        history.record(d)

        efficacies = extract_plugin_efficacy(history)
        assert len(efficacies) == 1
        eff = efficacies[0]
        assert eff.plugin_name == "port_scan"
        assert eff.total_runs == 1
        assert eff.total_successes == 1  # new_entities > 0
        assert eff.total_new_entities == 5
        assert eff.total_runtime == 2.1

    def test_empty_history(self):
        history = History()
        assert extract_plugin_efficacy(history) == []

    def test_unproductive_decision(self):
        history = History()
        d = Decision(
            id="abc123",
            chosen_plugin="port_scan",
            outcome_new_entities=0,
            outcome_confidence_delta=0.0,
            outcome_duration=1.0,
        )
        history.record(d)

        efficacies = extract_plugin_efficacy(history)
        assert efficacies[0].total_successes == 0


class TestExtractTechFingerprints:
    def test_groups_by_domain(self):
        g = KnowledgeGraph()
        g.add_entity(Entity.technology("sub.example.com", "nginx"))
        g.add_entity(Entity.technology("sub.example.com", "php"))
        g.add_entity(Entity.technology("other.com", "apache"))

        fps = extract_tech_fingerprints(g)
        by_domain = {fp.base_domain: fp for fp in fps}

        assert "example.com" in by_domain
        assert sorted(by_domain["example.com"].technologies) == ["nginx", "php"]
        assert "other.com" in by_domain
        assert by_domain["other.com"].technologies == ["apache"]


class TestExtractBaseDomain:
    def test_subdomain(self):
        assert _extract_base_domain("sub.example.com") == "example.com"

    def test_plain_domain(self):
        assert _extract_base_domain("example.com") == "example.com"

    def test_deep_subdomain(self):
        assert _extract_base_domain("a.b.c.example.com") == "example.com"

    def test_single_label(self):
        assert _extract_base_domain("localhost") == "localhost"
