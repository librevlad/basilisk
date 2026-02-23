"""Tests for the hypothesis engine and pattern detectors."""

from __future__ import annotations

from datetime import UTC, datetime

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.reasoning.hypothesis import (
    EvidenceItem,
    Hypothesis,
    HypothesisEngine,
    HypothesisStatus,
    HypothesisType,
    _detect_framework_pattern,
    _detect_service_identity,
    _detect_shared_stack,
    _detect_systematic_vuln,
    _detect_unverified_findings,
)

# ---------------------------------------------------------------------------
# Hypothesis model tests
# ---------------------------------------------------------------------------


class TestHypothesis:
    def test_make_id_deterministic(self):
        id1 = Hypothesis.make_id(HypothesisType.SHARED_STACK, tech="nginx")
        id2 = Hypothesis.make_id(HypothesisType.SHARED_STACK, tech="nginx")
        assert id1 == id2
        assert len(id1) == 16

    def test_make_id_different_types(self):
        id1 = Hypothesis.make_id(HypothesisType.SHARED_STACK, tech="nginx")
        id2 = Hypothesis.make_id(HypothesisType.SERVICE_IDENTITY, tech="nginx")
        assert id1 != id2

    def test_initial_confidence(self):
        hyp = Hypothesis(
            id="test",
            type=HypothesisType.SHARED_STACK,
            statement="test hypothesis",
        )
        assert hyp.confidence == 0.5
        assert hyp.status == HypothesisStatus.ACTIVE

    def test_add_supporting_evidence(self):
        hyp = Hypothesis(
            id="test",
            type=HypothesisType.SHARED_STACK,
            statement="test",
        )
        hyp.add_supporting(EvidenceItem(
            entity_id="e1", source_plugin="tech_detect",
            description="found nginx", source_family="http_probe",
        ))
        assert hyp.confidence > 0.5
        assert len(hyp.supporting_evidence) == 1

    def test_add_contradicting_evidence(self):
        hyp = Hypothesis(
            id="test",
            type=HypothesisType.SHARED_STACK,
            statement="test",
        )
        hyp.add_supporting(EvidenceItem(
            entity_id="e1", source_plugin="tech_detect",
            description="found nginx", source_family="http_probe",
        ))
        initial = hyp.confidence
        hyp.add_contradicting(EvidenceItem(
            entity_id="e2", source_plugin="waf_detect",
            description="not nginx", source_family="http_probe",
        ))
        assert hyp.confidence < initial

    def test_confirmation_threshold(self):
        hyp = Hypothesis(
            id="test",
            type=HypothesisType.SHARED_STACK,
            statement="test",
        )
        # Add many supporting evidence items from different families
        for i, family in enumerate(["dns", "http_probe", "network_scan", "exploit"]):
            hyp.add_supporting(EvidenceItem(
                entity_id=f"e{i}", source_plugin=f"plugin_{i}",
                description="evidence", source_family=family,
                weight=1.0,
            ))
        assert hyp.status == HypothesisStatus.CONFIRMED
        assert hyp.resolved_at is not None

    def test_rejection_threshold(self):
        hyp = Hypothesis(
            id="test",
            type=HypothesisType.SHARED_STACK,
            statement="test",
        )
        # Add many contradicting evidence items
        for i, family in enumerate(["dns", "http_probe", "network_scan", "exploit"]):
            hyp.add_contradicting(EvidenceItem(
                entity_id=f"e{i}", source_plugin=f"plugin_{i}",
                description="counter evidence", source_family=family,
                weight=1.0,
            ))
        assert hyp.status == HypothesisStatus.REJECTED

    def test_source_family_diminishing_returns(self):
        hyp = Hypothesis(
            id="test",
            type=HypothesisType.SHARED_STACK,
            statement="test",
        )
        # Two items from same family
        hyp.add_supporting(EvidenceItem(
            entity_id="e1", source_plugin="p1",
            description="ev1", source_family="http_probe",
        ))
        conf_one_family = hyp.confidence

        hyp2 = Hypothesis(
            id="test2",
            type=HypothesisType.SHARED_STACK,
            statement="test",
        )
        # Two items from different families
        hyp2.add_supporting(EvidenceItem(
            entity_id="e1", source_plugin="p1",
            description="ev1", source_family="http_probe",
        ))
        hyp2.add_supporting(EvidenceItem(
            entity_id="e2", source_plugin="p2",
            description="ev2", source_family="network_scan",
        ))
        # Different families should give higher confidence
        assert hyp2.confidence >= conf_one_family

    def test_confidence_bounds(self):
        hyp = Hypothesis(
            id="test",
            type=HypothesisType.SHARED_STACK,
            statement="test",
        )
        # Many supporting items shouldn't exceed 1.0
        for i in range(20):
            hyp.add_supporting(EvidenceItem(
                entity_id=f"e{i}", source_plugin=f"p{i}",
                description="ev", source_family=f"family_{i}",
                weight=1.0,
            ))
        assert hyp.confidence <= 1.0


# ---------------------------------------------------------------------------
# Pattern detector tests
# ---------------------------------------------------------------------------


def _make_graph_with_hosts(hosts: list[str]) -> KnowledgeGraph:
    """Helper: create graph with host entities."""
    graph = KnowledgeGraph()
    now = datetime.now(UTC)
    for h in hosts:
        entity = Entity(
            id=Entity.make_id(EntityType.HOST, host=h),
            type=EntityType.HOST,
            data={"host": h, "type": "domain"},
            first_seen=now, last_seen=now,
        )
        graph.add_entity(entity)
    return graph


def _add_tech(graph: KnowledgeGraph, host: str, tech_name: str, version: str = "") -> None:
    """Helper: add technology to host."""
    now = datetime.now(UTC)
    host_id = Entity.make_id(EntityType.HOST, host=host)
    tech = Entity(
        id=Entity.make_id(EntityType.TECHNOLOGY, host=host, name=tech_name, version=version),
        type=EntityType.TECHNOLOGY,
        data={"host": host, "name": tech_name, "version": version},
        first_seen=now, last_seen=now,
    )
    graph.add_entity(tech)
    graph.add_relation(Relation(source_id=host_id, target_id=tech.id, type=RelationType.RUNS))


def _add_service(
    graph: KnowledgeGraph, host: str, port: int,
    protocol: str = "tcp", service: str = "",
) -> None:
    """Helper: add service to host."""
    now = datetime.now(UTC)
    host_id = Entity.make_id(EntityType.HOST, host=host)
    svc = Entity(
        id=Entity.make_id(EntityType.SERVICE, host=host, port=str(port), protocol=protocol),
        type=EntityType.SERVICE,
        data={"host": host, "port": port, "protocol": protocol, "service": service},
        first_seen=now, last_seen=now,
    )
    graph.add_entity(svc)
    graph.add_relation(Relation(
        source_id=host_id, target_id=svc.id, type=RelationType.EXPOSES,
    ))


class TestDetectSharedStack:
    def test_no_shared_tech(self):
        graph = _make_graph_with_hosts(["a.com"])
        _add_tech(graph, "a.com", "nginx")
        result = _detect_shared_stack(graph)
        assert len(result) == 0

    def test_shared_tech_detected(self):
        graph = _make_graph_with_hosts(["a.com", "b.com"])
        _add_tech(graph, "a.com", "nginx")
        _add_tech(graph, "b.com", "nginx")
        result = _detect_shared_stack(graph)
        assert len(result) == 1
        assert result[0].type == HypothesisType.SHARED_STACK
        assert "nginx" in result[0].statement


class TestDetectServiceIdentity:
    def test_known_port_unknown_service(self):
        graph = _make_graph_with_hosts(["a.com"])
        _add_service(graph, "a.com", 6379)  # redis port, no service name
        result = _detect_service_identity(graph)
        assert len(result) == 1
        assert "redis" in result[0].statement

    def test_known_service_skipped(self):
        graph = _make_graph_with_hosts(["a.com"])
        _add_service(graph, "a.com", 6379, service="redis")
        result = _detect_service_identity(graph)
        assert len(result) == 0


class TestDetectSystematicVuln:
    def test_recurring_findings(self):
        graph = _make_graph_with_hosts(["a.com", "b.com", "c.com"])
        now = datetime.now(UTC)
        for host in ["a.com", "b.com", "c.com"]:
            finding = Entity(
                id=Entity.make_id(EntityType.FINDING, host=host, title=f"XSS in /search on {host}"),
                type=EntityType.FINDING,
                data={"host": host, "title": f"XSS in /search on {host}", "severity": "high"},
                first_seen=now, last_seen=now,
            )
            graph.add_entity(finding)
        result = _detect_systematic_vuln(graph)
        assert len(result) == 1
        assert "XSS" in result[0].statement

    def test_no_recurring_findings(self):
        graph = _make_graph_with_hosts(["a.com"])
        now = datetime.now(UTC)
        finding = Entity(
            id=Entity.make_id(EntityType.FINDING, host="a.com", title="XSS in /search"),
            type=EntityType.FINDING,
            data={"host": "a.com", "title": "XSS in /search", "severity": "high"},
            first_seen=now, last_seen=now,
        )
        graph.add_entity(finding)
        result = _detect_systematic_vuln(graph)
        assert len(result) == 0


class TestDetectUnverifiedFindings:
    def test_high_severity_low_confidence(self):
        graph = KnowledgeGraph()
        now = datetime.now(UTC)
        finding = Entity(
            id=Entity.make_id(EntityType.FINDING, host="a.com", title="SQLi"),
            type=EntityType.FINDING,
            data={"host": "a.com", "title": "SQLi", "severity": "critical"},
            confidence=0.4,
            first_seen=now, last_seen=now,
        )
        graph.add_entity(finding)
        result = _detect_unverified_findings(graph)
        assert len(result) == 1
        assert result[0].type == HypothesisType.UNVERIFIED_FINDING

    def test_high_confidence_skipped(self):
        graph = KnowledgeGraph()
        now = datetime.now(UTC)
        finding = Entity(
            id=Entity.make_id(EntityType.FINDING, host="a.com", title="SQLi"),
            type=EntityType.FINDING,
            data={"host": "a.com", "title": "SQLi", "severity": "critical"},
            confidence=0.9,
            first_seen=now, last_seen=now,
        )
        graph.add_entity(finding)
        result = _detect_unverified_findings(graph)
        assert len(result) == 0

    def test_low_severity_skipped(self):
        graph = KnowledgeGraph()
        now = datetime.now(UTC)
        finding = Entity(
            id=Entity.make_id(EntityType.FINDING, host="a.com", title="Info"),
            type=EntityType.FINDING,
            data={"host": "a.com", "title": "Info", "severity": "info"},
            confidence=0.3,
            first_seen=now, last_seen=now,
        )
        graph.add_entity(finding)
        result = _detect_unverified_findings(graph)
        assert len(result) == 0


class TestDetectFrameworkPattern:
    def test_wordpress_pattern(self):
        graph = _make_graph_with_hosts(["a.com"])
        _add_service(graph, "a.com", 443, service="https")
        now = datetime.now(UTC)
        host_id = Entity.make_id(EntityType.HOST, host="a.com")
        for path in ["/wp-content/themes", "/wp-admin/login.php", "/wp-includes/js"]:
            ep = Entity(
                id=Entity.make_id(EntityType.ENDPOINT, host="a.com", path=path),
                type=EntityType.ENDPOINT,
                data={"host": "a.com", "path": path},
                first_seen=now, last_seen=now,
            )
            graph.add_entity(ep)
            graph.add_relation(Relation(
                source_id=host_id, target_id=ep.id, type=RelationType.HAS_ENDPOINT,
            ))
        result = _detect_framework_pattern(graph)
        assert len(result) >= 1
        assert any("wordpress" in h.statement for h in result)

    def test_no_pattern(self):
        graph = _make_graph_with_hosts(["a.com"])
        now = datetime.now(UTC)
        host_id = Entity.make_id(EntityType.HOST, host="a.com")
        ep = Entity(
            id=Entity.make_id(EntityType.ENDPOINT, host="a.com", path="/about"),
            type=EntityType.ENDPOINT,
            data={"host": "a.com", "path": "/about"},
            first_seen=now, last_seen=now,
        )
        graph.add_entity(ep)
        graph.add_relation(Relation(
            source_id=host_id, target_id=ep.id, type=RelationType.HAS_ENDPOINT,
        ))
        result = _detect_framework_pattern(graph)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# HypothesisEngine tests
# ---------------------------------------------------------------------------


class TestHypothesisEngine:
    def test_generate_empty_graph(self):
        engine = HypothesisEngine()
        graph = KnowledgeGraph()
        result = engine.generate_hypotheses(graph)
        assert result == []

    def test_generate_dedup(self):
        engine = HypothesisEngine()
        graph = _make_graph_with_hosts(["a.com", "b.com"])
        _add_tech(graph, "a.com", "nginx")
        _add_tech(graph, "b.com", "nginx")
        result1 = engine.generate_hypotheses(graph)
        result2 = engine.generate_hypotheses(graph)
        assert len(result1) >= 1
        assert len(result2) == 0  # already generated

    def test_max_active_limit(self):
        engine = HypothesisEngine()
        engine.MAX_ACTIVE = 3
        graph = KnowledgeGraph()
        now = datetime.now(UTC)
        # Create enough unverified findings to exceed limit
        for i in range(10):
            finding = Entity(
                id=Entity.make_id(EntityType.FINDING, host=f"h{i}.com", title=f"SQLi_{i}"),
                type=EntityType.FINDING,
                data={"host": f"h{i}.com", "title": f"SQLi_{i}", "severity": "critical"},
                confidence=0.3,
                first_seen=now, last_seen=now,
            )
            graph.add_entity(finding)
        engine.generate_hypotheses(graph)
        active = engine.active_hypotheses
        assert len(active) <= 3

    def test_update_from_observation(self):
        engine = HypothesisEngine()
        graph = _make_graph_with_hosts(["a.com", "b.com"])
        _add_tech(graph, "a.com", "nginx")
        _add_tech(graph, "b.com", "nginx")
        engine.generate_hypotheses(graph)

        host_id = Entity.make_id(EntityType.HOST, host="a.com")
        changed = engine.update_from_observation(
            entity_id=host_id,
            source_plugin="tech_detect",
            source_family="http_probe",
            was_new=True,
            confidence_delta=0.2,
        )
        # May or may not have changed status depending on threshold
        assert isinstance(changed, list)

    def test_resolution_gain(self):
        engine = HypothesisEngine()
        graph = _make_graph_with_hosts(["a.com", "b.com"])
        _add_tech(graph, "a.com", "nginx")
        _add_tech(graph, "b.com", "nginx")
        engine.generate_hypotheses(graph)

        host_id = Entity.make_id(EntityType.HOST, host="a.com")
        gain = engine.resolution_gain("tech_detect", host_id)
        assert gain >= 0.0
        assert gain <= 1.0

    def test_resolution_gain_no_match(self):
        engine = HypothesisEngine()
        gain = engine.resolution_gain("unknown_plugin", "unknown_entity")
        assert gain == 0.0

    def test_hypotheses_for_entity(self):
        engine = HypothesisEngine()
        graph = _make_graph_with_hosts(["a.com", "b.com"])
        _add_tech(graph, "a.com", "nginx")
        _add_tech(graph, "b.com", "nginx")
        engine.generate_hypotheses(graph)

        host_id = Entity.make_id(EntityType.HOST, host="a.com")
        related = engine.hypotheses_for_entity(host_id)
        assert len(related) >= 1

    def test_all_hypotheses(self):
        engine = HypothesisEngine()
        graph = _make_graph_with_hosts(["a.com", "b.com"])
        _add_tech(graph, "a.com", "nginx")
        _add_tech(graph, "b.com", "nginx")
        engine.generate_hypotheses(graph)
        assert len(engine.all_hypotheses) >= 1
