"""Tests for KnowledgeStore — SQLite persistence for the knowledge graph."""

from __future__ import annotations

import aiosqlite

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.knowledge.store import KnowledgeStore


async def _make_store() -> tuple[KnowledgeStore, aiosqlite.Connection]:
    db = await aiosqlite.connect(":memory:")
    store = KnowledgeStore(db)
    await store.init_schema()
    return store, db


class TestStoreSchema:
    async def test_init_schema_creates_tables(self):
        store, db = await _make_store()
        try:
            cursor = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'kg_%'"
            )
            tables = {row[0] for row in await cursor.fetchall()}
            assert "kg_entities" in tables
            assert "kg_relations" in tables
        finally:
            await db.close()

    async def test_init_schema_idempotent(self):
        store, db = await _make_store()
        try:
            await store.init_schema()  # second call should not raise
        finally:
            await db.close()


class TestStoreSaveEntity:
    async def test_save_single_entity(self):
        store, db = await _make_store()
        try:
            entity = Entity.host("test.com")
            await store.save_entity(entity)
            await db.commit()
            cursor = await db.execute("SELECT COUNT(*) FROM kg_entities")
            row = await cursor.fetchone()
            assert row[0] == 1
        finally:
            await db.close()

    async def test_upsert_updates_existing(self):
        store, db = await _make_store()
        try:
            entity = Entity.host("test.com")
            await store.save_entity(entity)
            await db.commit()

            entity.confidence = 0.9
            entity.observation_count = 5
            await store.save_entity(entity)
            await db.commit()

            cursor = await db.execute("SELECT confidence, observation_count FROM kg_entities")
            row = await cursor.fetchone()
            assert abs(row[0] - 0.9) < 0.01
            assert row[1] == 5
        finally:
            await db.close()


class TestStoreSaveRelation:
    async def test_save_single_relation(self):
        store, db = await _make_store()
        try:
            host = Entity.host("test.com")
            svc = Entity.service("test.com", 443, "https")
            await store.save_entity(host)
            await store.save_entity(svc)
            rel = Relation(
                source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
            )
            await store.save_relation(rel)
            await db.commit()

            cursor = await db.execute("SELECT COUNT(*) FROM kg_relations")
            row = await cursor.fetchone()
            assert row[0] == 1
        finally:
            await db.close()


class TestStoreRoundTrip:
    async def test_save_and_load_entities(self):
        store, db = await _make_store()
        try:
            graph = KnowledgeGraph()
            graph.add_entity(Entity.host("a.com"))
            graph.add_entity(Entity.host("b.com"))
            graph.add_entity(Entity.service("a.com", 80, "tcp"))
            await store.save(graph)

            loaded = await store.load()
            assert loaded.entity_count == 3
            assert len(loaded.hosts()) == 2
            assert len(loaded.services()) == 1
        finally:
            await db.close()

    async def test_save_and_load_relations(self):
        store, db = await _make_store()
        try:
            graph = KnowledgeGraph()
            host = Entity.host("rel.com")
            svc = Entity.service("rel.com", 443, "https")
            graph.add_entity(host)
            graph.add_entity(svc)
            graph.add_relation(Relation(
                source_id=host.id, target_id=svc.id,
                type=RelationType.EXPOSES,
            ))
            await store.save(graph)

            loaded = await store.load()
            assert loaded.relation_count == 1
            neighbors = loaded.neighbors(host.id, RelationType.EXPOSES)
            assert len(neighbors) == 1
            assert neighbors[0].id == svc.id
        finally:
            await db.close()

    async def test_entity_data_preserved(self):
        store, db = await _make_store()
        try:
            graph = KnowledgeGraph()
            entity = Entity.host("data.com")
            entity.confidence = 0.85
            entity.evidence = ["source_a", "source_b"]
            entity.observation_count = 3
            graph.add_entity(entity)
            await store.save(graph)

            loaded = await store.load()
            loaded_entity = loaded.get(entity.id)
            assert loaded_entity is not None
            assert loaded_entity.data["host"] == "data.com"
            assert abs(loaded_entity.confidence - 0.85) < 0.01
            assert loaded_entity.evidence == ["source_a", "source_b"]
            assert loaded_entity.observation_count == 3
        finally:
            await db.close()

    async def test_full_graph_round_trip(self):
        store, db = await _make_store()
        try:
            graph = KnowledgeGraph()
            host = Entity.host("full.com")
            svc = Entity.service("full.com", 80, "tcp")
            tech = Entity.technology("full.com", "nginx", "1.24")
            graph.add_entity(host)
            graph.add_entity(svc)
            graph.add_entity(tech)
            graph.add_relation(Relation(
                source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
            ))
            graph.add_relation(Relation(
                source_id=svc.id, target_id=tech.id, type=RelationType.RUNS,
            ))
            await store.save(graph)

            loaded = await store.load()
            assert loaded.entity_count == 3
            assert loaded.relation_count == 2
            assert len(loaded.hosts()) == 1
            assert len(loaded.services()) == 1
            assert len(loaded.technologies()) == 1
        finally:
            await db.close()
