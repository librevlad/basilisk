"""Tests for KnowledgeGraph invariants — self-loop rejection, validate(), SQL dedup."""

from __future__ import annotations

import pytest

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType


def _make_graph() -> tuple[KnowledgeGraph, Entity, Entity]:
    """Build a small graph with two hosts."""
    g = KnowledgeGraph()
    h1 = Entity.host("a.com")
    h2 = Entity.host("b.com")
    g.add_entity(h1)
    g.add_entity(h2)
    return g, h1, h2


class TestSelfLoopRejected:
    """add_relation with same source/target is silently dropped."""

    def test_self_loop_rejected(self):
        g, h1, _ = _make_graph()
        g.add_relation(Relation(
            source_id=h1.id, target_id=h1.id, type=RelationType.RELATES_TO,
        ))
        assert g.relation_count == 0

    def test_normal_relation_accepted(self):
        g, h1, h2 = _make_graph()
        g.add_relation(Relation(
            source_id=h1.id, target_id=h2.id, type=RelationType.PARENT_OF,
        ))
        assert g.relation_count == 1


class TestValidate:
    """validate() detects graph violations."""

    def test_validate_clean_graph(self):
        g, h1, h2 = _make_graph()
        g.add_relation(Relation(
            source_id=h1.id, target_id=h2.id, type=RelationType.PARENT_OF,
        ))
        errors = g.validate()
        assert errors == []

    def test_validate_dangling_source(self):
        g, _, h2 = _make_graph()
        # Manually insert a relation with a non-existent source
        bad_rel = Relation(
            source_id="nonexistent_src", target_id=h2.id, type=RelationType.RELATES_TO,
        )
        g._relations.append(bad_rel)
        errors = g.validate()
        assert any("Dangling source" in e for e in errors)

    def test_validate_dangling_target(self):
        g, h1, _ = _make_graph()
        bad_rel = Relation(
            source_id=h1.id, target_id="nonexistent_tgt", type=RelationType.RELATES_TO,
        )
        g._relations.append(bad_rel)
        errors = g.validate()
        assert any("Dangling target" in e for e in errors)

    def test_validate_self_loop_detected(self):
        """Manually injected self-loop is caught by validate()."""
        g, h1, _ = _make_graph()
        bad_rel = Relation(
            source_id=h1.id, target_id=h1.id, type=RelationType.RELATES_TO,
        )
        g._relations.append(bad_rel)
        errors = g.validate()
        assert any("Self-loop" in e for e in errors)


class TestUniqueRelationIndex:
    """SQL unique index preserves dedup on save/load roundtrip."""

    @pytest.mark.asyncio
    async def test_unique_relation_index(self):
        import aiosqlite

        from basilisk.knowledge.store import KnowledgeStore

        db = await aiosqlite.connect(":memory:")
        store = KnowledgeStore(db)
        await store.init_schema()

        g, h1, h2 = _make_graph()
        rel = Relation(
            source_id=h1.id, target_id=h2.id, type=RelationType.PARENT_OF,
        )
        g.add_relation(rel)
        await store.save(g)

        # Save duplicate relation directly via SQL (bypasses app-level dedup)
        await store.save_relation(rel)
        await db.commit()

        loaded = await store.load()
        # Unique index ensures only one relation survives
        assert loaded.relation_count == 1
        await db.close()
