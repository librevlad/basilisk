"""Tests for the KnowledgeGraph."""

from __future__ import annotations

from datetime import UTC, datetime

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType


def _make_host(name: str = "example.com") -> Entity:
    return Entity.host(name)


def _make_service(host: str = "example.com", port: int = 443) -> Entity:
    return Entity.service(host, port, "https")


class TestGraphAddEntity:
    def test_add_and_retrieve(self):
        g = KnowledgeGraph()
        host = _make_host()
        g.add_entity(host)
        assert g.get(host.id) is not None
        assert g.entity_count == 1

    def test_add_duplicate_merges(self):
        g = KnowledgeGraph()
        h1 = _make_host()
        h2 = _make_host()
        g.add_entity(h1)
        g.add_entity(h2)
        assert g.entity_count == 1
        assert g.get(h1.id).observation_count == 2

    def test_get_nonexistent_returns_none(self):
        g = KnowledgeGraph()
        assert g.get("nonexistent") is None


class TestGraphMerge:
    def test_confidence_merge(self):
        g = KnowledgeGraph()
        h1 = Entity.host("merge.com")
        h1.confidence = 0.5
        g.add_entity(h1)

        h2 = Entity.host("merge.com")
        h2.confidence = 0.5
        g.merge_entity(h2)

        merged = g.get(h1.id)
        # 1 - (1-0.5) * (1-0.5) = 1 - 0.25 = 0.75
        assert abs(merged.confidence - 0.75) < 0.01

    def test_data_merge_new_keys(self):
        g = KnowledgeGraph()
        h1 = Entity.host("data.com")
        h1.data["a"] = 1
        g.add_entity(h1)

        h2 = Entity.host("data.com")
        h2.data["b"] = 2
        g.merge_entity(h2)

        merged = g.get(h1.id)
        assert merged.data["a"] == 1
        assert merged.data["b"] == 2

    def test_data_merge_override(self):
        g = KnowledgeGraph()
        h1 = Entity.host("override.com")
        h1.data["x"] = "old"
        g.add_entity(h1)

        h2 = Entity.host("override.com")
        h2.data["x"] = "new"
        g.merge_entity(h2)

        assert g.get(h1.id).data["x"] == "new"

    def test_evidence_merge_no_duplicates(self):
        g = KnowledgeGraph()
        h1 = Entity.host("ev.com")
        h1.evidence = ["source_a"]
        g.add_entity(h1)

        h2 = Entity.host("ev.com")
        h2.evidence = ["source_a", "source_b"]
        g.merge_entity(h2)

        merged = g.get(h1.id)
        assert sorted(merged.evidence) == ["source_a", "source_b"]

    def test_last_seen_uses_max(self):
        g = KnowledgeGraph()
        h1 = Entity.host("time.com")
        early = datetime(2024, 1, 1, tzinfo=UTC)
        late = datetime(2025, 1, 1, tzinfo=UTC)
        h1.last_seen = early
        g.add_entity(h1)

        h2 = Entity.host("time.com")
        h2.last_seen = late
        g.merge_entity(h2)

        assert g.get(h1.id).last_seen == late


class TestGraphRelations:
    def test_add_relation(self):
        g = KnowledgeGraph()
        host = _make_host()
        svc = _make_service()
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id,
            type=RelationType.EXPOSES,
        ))
        assert g.relation_count == 1

    def test_dedup_relations(self):
        g = KnowledgeGraph()
        host = _make_host()
        svc = _make_service()
        g.add_entity(host)
        g.add_entity(svc)
        rel = Relation(source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES)
        g.add_relation(rel)
        g.add_relation(rel)  # duplicate
        assert g.relation_count == 1

    def test_neighbors(self):
        g = KnowledgeGraph()
        host = _make_host()
        svc = _make_service()
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        neighbors = g.neighbors(host.id, RelationType.EXPOSES)
        assert len(neighbors) == 1
        assert neighbors[0].id == svc.id

    def test_neighbors_filter_by_type(self):
        g = KnowledgeGraph()
        host = _make_host()
        svc = _make_service()
        tech = Entity.technology("example.com", "nginx")
        g.add_entity(host)
        g.add_entity(svc)
        g.add_entity(tech)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        g.add_relation(Relation(
            source_id=host.id, target_id=tech.id, type=RelationType.RUNS,
        ))
        # Only EXPOSES
        exposes = g.neighbors(host.id, RelationType.EXPOSES)
        assert len(exposes) == 1
        # All
        all_neighbors = g.neighbors(host.id, None)
        assert len(all_neighbors) == 2

    def test_reverse_neighbors(self):
        g = KnowledgeGraph()
        host = _make_host()
        svc = _make_service()
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        rev = g.reverse_neighbors(svc.id, RelationType.EXPOSES)
        assert len(rev) == 1
        assert rev[0].id == host.id


class TestGraphQuery:
    def test_query_by_type(self):
        g = KnowledgeGraph()
        g.add_entity(_make_host("a.com"))
        g.add_entity(_make_host("b.com"))
        g.add_entity(_make_service("a.com", 80))
        hosts = g.query(EntityType.HOST)
        assert len(hosts) == 2

    def test_query_with_filters(self):
        g = KnowledgeGraph()
        g.add_entity(_make_host("a.com"))
        g.add_entity(_make_host("b.com"))
        result = g.query(EntityType.HOST, host="a.com")
        assert len(result) == 1
        assert result[0].data["host"] == "a.com"

    def test_hosts_convenience(self):
        g = KnowledgeGraph()
        g.add_entity(_make_host())
        g.add_entity(_make_service())
        assert len(g.hosts()) == 1

    def test_services_convenience(self):
        g = KnowledgeGraph()
        g.add_entity(_make_host())
        g.add_entity(_make_service())
        assert len(g.services()) == 1


class TestGraphExecutionLog:
    def test_record_and_check(self):
        g = KnowledgeGraph()
        assert not g.was_executed("fp1")
        g.record_execution("fp1")
        assert g.was_executed("fp1")

    def test_different_fingerprints(self):
        g = KnowledgeGraph()
        g.record_execution("fp1")
        assert not g.was_executed("fp2")


class TestGraphToTargets:
    def test_converts_hosts_to_targets(self):
        g = KnowledgeGraph()
        h = Entity.host("test.com")
        g.add_entity(h)
        targets = g.to_targets()
        assert len(targets) == 1
        assert targets[0].host == "test.com"

    def test_converts_subdomain(self):
        g = KnowledgeGraph()
        h = Entity.host("sub.test.com")
        h.data["type"] = "subdomain"
        h.data["parent"] = "test.com"
        g.add_entity(h)
        targets = g.to_targets()
        assert len(targets) == 1
        assert targets[0].parent == "test.com"


class TestGraphClear:
    def test_clear_empties_graph(self):
        g = KnowledgeGraph()
        g.add_entity(_make_host())
        g.add_relation(Relation(
            source_id="a", target_id="b", type=RelationType.EXPOSES,
        ))
        g.record_execution("fp")
        g.clear()
        assert g.entity_count == 0
        assert g.relation_count == 0
        assert not g.was_executed("fp")
