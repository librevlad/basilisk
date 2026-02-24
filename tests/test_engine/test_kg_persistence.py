"""Tests for KG persistence roundtrip."""

from __future__ import annotations

import aiosqlite

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.knowledge.store import KnowledgeStore


class TestKgRoundtrip:
    async def test_kg_save_load_roundtrip(self, tmp_path):
        """Create graph, save, load — entity/relation counts match."""
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        svc = Entity.service("example.com", 443, "tcp")
        graph.add_entity(host)
        graph.add_entity(svc)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id,
            type=RelationType.EXPOSES, source_plugin="port_scan",
        ))

        db_path = tmp_path / "knowledge.db"
        async with aiosqlite.connect(str(db_path)) as db:
            store = KnowledgeStore(db)
            await store.init_schema()
            await store.save(graph)

        # Load into fresh graph
        async with aiosqlite.connect(str(db_path)) as db:
            store = KnowledgeStore(db)
            loaded = await store.load()

        assert loaded.entity_count == graph.entity_count
        assert loaded.relation_count == graph.relation_count
        assert loaded.get(host.id) is not None
        assert loaded.get(svc.id) is not None

    async def test_kg_creates_file(self, tmp_path):
        """Verify DB file is created on disk."""
        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("test.com"))

        db_path = tmp_path / "kg_test.db"
        async with aiosqlite.connect(str(db_path)) as db:
            store = KnowledgeStore(db)
            await store.init_schema()
            await store.save(graph)

        assert db_path.exists()
        assert db_path.stat().st_size > 0

    async def test_kg_execution_log_persisted(self, tmp_path):
        """Verify execution fingerprints survive roundtrip."""
        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("test.com"))
        graph.record_execution("port_scan:test.com:step1")
        graph.record_execution("dns_enum:test.com:step2")

        db_path = tmp_path / "knowledge.db"
        async with aiosqlite.connect(str(db_path)) as db:
            store = KnowledgeStore(db)
            await store.init_schema()
            await store.save(graph)

        async with aiosqlite.connect(str(db_path)) as db:
            store = KnowledgeStore(db)
            loaded = await store.load()

        assert loaded.was_executed("port_scan:test.com:step1")
        assert loaded.was_executed("dns_enum:test.com:step2")
        assert not loaded.was_executed("nonexistent:fp")
