"""Tests for the evidence aggregator and belief revision."""

from __future__ import annotations

from datetime import UTC, datetime

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.reasoning.belief import SOURCE_FAMILIES, EvidenceAggregator, get_source_family

# ---------------------------------------------------------------------------
# Source family tests
# ---------------------------------------------------------------------------


class TestSourceFamilies:
    def test_known_plugins(self):
        assert get_source_family("dns_enum") == "dns"
        assert get_source_family("port_scan") == "network_scan"
        assert get_source_family("tech_detect") == "http_probe"
        assert get_source_family("sqli_basic") == "exploit"
        assert get_source_family("git_exposure") == "config_leak"
        assert get_source_family("ssti_verify") == "verification"

    def test_unknown_plugin(self):
        assert get_source_family("unknown_plugin_xyz") == "general"

    def test_families_are_strings(self):
        for plugin, family in SOURCE_FAMILIES.items():
            assert isinstance(plugin, str)
            assert isinstance(family, str)


# ---------------------------------------------------------------------------
# EvidenceAggregator tests
# ---------------------------------------------------------------------------


def _make_graph_with_entity(
    host: str = "example.com", confidence: float = 0.5,
) -> tuple[KnowledgeGraph, str]:
    """Create graph with one host entity, return (graph, entity_id)."""
    graph = KnowledgeGraph()
    now = datetime.now(UTC)
    entity = Entity(
        id=Entity.make_id(EntityType.HOST, host=host),
        type=EntityType.HOST,
        data={"host": host},
        confidence=confidence,
        first_seen=now, last_seen=now,
    )
    graph.add_entity(entity)
    return graph, entity.id


class TestEvidenceAggregator:
    def test_no_revision_single_family(self):
        graph, eid = _make_graph_with_entity()
        agg = EvidenceAggregator(graph)
        agg.record_evidence(eid, "dns_enum", 0.1)
        agg.record_evidence(eid, "whois", 0.05)  # same dns family
        revisions = agg.revise_beliefs()
        # Both plugins are in "dns" family → only 1 family, no revision
        assert len(revisions) == 0

    def test_independence_bonus(self):
        graph, eid = _make_graph_with_entity(confidence=0.5)
        agg = EvidenceAggregator(graph)
        agg.record_evidence(eid, "dns_enum", 0.1)        # dns family
        agg.record_evidence(eid, "port_scan", 0.1)       # network_scan family
        revisions = agg.revise_beliefs()
        assert len(revisions) == 1
        entity_id, old_conf, new_conf = revisions[0]
        assert entity_id == eid
        assert new_conf > old_conf
        # Independence bonus: +0.05 for 2 families
        assert abs(new_conf - old_conf - 0.05) < 0.001

    def test_three_families_bonus(self):
        graph, eid = _make_graph_with_entity(confidence=0.5)
        agg = EvidenceAggregator(graph)
        agg.record_evidence(eid, "dns_enum", 0.1)        # dns
        agg.record_evidence(eid, "port_scan", 0.1)       # network_scan
        agg.record_evidence(eid, "tech_detect", 0.1)     # http_probe
        revisions = agg.revise_beliefs()
        assert len(revisions) == 1
        _, old_conf, new_conf = revisions[0]
        # 3 families → +0.10 bonus
        assert abs(new_conf - old_conf - 0.10) < 0.001

    def test_max_independence_bonus(self):
        graph, eid = _make_graph_with_entity(confidence=0.5)
        agg = EvidenceAggregator(graph)
        agg.record_evidence(eid, "dns_enum", 0.1)        # dns
        agg.record_evidence(eid, "port_scan", 0.1)       # network_scan
        agg.record_evidence(eid, "tech_detect", 0.1)     # http_probe
        agg.record_evidence(eid, "sqli_basic", 0.1)      # exploit
        agg.record_evidence(eid, "git_exposure", 0.1)    # config_leak
        revisions = agg.revise_beliefs()
        assert len(revisions) == 1
        _, old_conf, new_conf = revisions[0]
        # 5 families → min((5-1)*0.05, 0.15) = 0.15 (capped)
        assert abs(new_conf - old_conf - 0.15) < 0.001

    def test_contradiction_penalty(self):
        graph, eid = _make_graph_with_entity(confidence=0.5)
        agg = EvidenceAggregator(graph)
        agg.record_evidence(eid, "dns_enum", 0.1)        # positive from dns
        agg.record_evidence(eid, "port_scan", -0.1)      # negative from network_scan
        revisions = agg.revise_beliefs()
        assert len(revisions) == 1
        _, old_conf, new_conf = revisions[0]
        # Independence bonus +0.05, contradiction penalty -0.1 = net -0.05
        assert new_conf < old_conf

    def test_reset_step(self):
        graph, eid = _make_graph_with_entity()
        agg = EvidenceAggregator(graph)
        agg.record_evidence(eid, "dns_enum", 0.1)
        agg.reset_step()
        # After reset, no evidence to process
        revisions = agg.revise_beliefs()
        assert len(revisions) == 0

    def test_confidence_floor(self):
        graph, eid = _make_graph_with_entity(confidence=0.12)
        agg = EvidenceAggregator(graph)
        agg.record_evidence(eid, "dns_enum", 0.1)
        agg.record_evidence(eid, "port_scan", -0.2)
        revisions = agg.revise_beliefs()
        if revisions:
            _, _, new_conf = revisions[0]
            assert new_conf >= 0.1  # floor

    def test_confidence_ceiling(self):
        graph, eid = _make_graph_with_entity(confidence=0.95)
        agg = EvidenceAggregator(graph)
        agg.record_evidence(eid, "dns_enum", 0.1)
        agg.record_evidence(eid, "port_scan", 0.1)
        agg.record_evidence(eid, "tech_detect", 0.1)
        agg.record_evidence(eid, "sqli_basic", 0.1)
        revisions = agg.revise_beliefs()
        if revisions:
            _, _, new_conf = revisions[0]
            assert new_conf <= 1.0  # ceiling

    def test_nonexistent_entity_skipped(self):
        graph = KnowledgeGraph()
        agg = EvidenceAggregator(graph)
        agg.record_evidence("nonexistent_id", "dns_enum", 0.1)
        agg.record_evidence("nonexistent_id", "port_scan", 0.1)
        revisions = agg.revise_beliefs()
        assert len(revisions) == 0

    def test_multiple_entities(self):
        graph = KnowledgeGraph()
        now = datetime.now(UTC)
        ids = []
        for host in ["a.com", "b.com"]:
            entity = Entity(
                id=Entity.make_id(EntityType.HOST, host=host),
                type=EntityType.HOST,
                data={"host": host},
                confidence=0.5,
                first_seen=now, last_seen=now,
            )
            graph.add_entity(entity)
            ids.append(entity.id)

        agg = EvidenceAggregator(graph)
        # a.com: 2 families
        agg.record_evidence(ids[0], "dns_enum", 0.1)
        agg.record_evidence(ids[0], "port_scan", 0.1)
        # b.com: 1 family (no revision)
        agg.record_evidence(ids[1], "dns_enum", 0.1)

        revisions = agg.revise_beliefs()
        assert len(revisions) == 1
        assert revisions[0][0] == ids[0]

    def test_with_hypothesis_engine(self):
        """EvidenceAggregator accepts optional hypothesis engine without error."""
        from basilisk.reasoning.hypothesis import HypothesisEngine

        graph, eid = _make_graph_with_entity()
        engine = HypothesisEngine()
        agg = EvidenceAggregator(graph, hypothesis_engine=engine)
        agg.record_evidence(eid, "dns_enum", 0.1)
        agg.record_evidence(eid, "port_scan", 0.1)
        revisions = agg.revise_beliefs()
        assert len(revisions) == 1
