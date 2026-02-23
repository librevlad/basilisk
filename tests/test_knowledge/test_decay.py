"""Tests for knowledge decay in the graph."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph


class TestApplyDecay:
    def test_no_decay_for_fresh_entities(self):
        g = KnowledgeGraph()
        host = Entity.host("fresh.com")
        host.confidence = 1.0
        g.add_entity(host)
        affected = g.apply_decay()
        # Entity just created — age < 1 hour, no decay
        assert affected == 0
        assert g.hosts()[0].confidence == 1.0

    def test_decay_for_old_entity(self):
        g = KnowledgeGraph()
        host = Entity.host("old.com")
        host.confidence = 1.0
        host.last_seen = datetime.now(UTC) - timedelta(hours=5)
        g.add_entity(host)
        affected = g.apply_decay()
        assert affected == 1
        assert g.hosts()[0].confidence < 1.0

    def test_decay_floor(self):
        g = KnowledgeGraph()
        host = Entity.host("ancient.com")
        host.confidence = 0.15
        host.last_seen = datetime.now(UTC) - timedelta(hours=100)
        g.add_entity(host)
        g.apply_decay()
        # Should not go below 0.1
        assert g.hosts()[0].confidence >= 0.1

    def test_decay_proportional_to_age(self):
        g = KnowledgeGraph()
        young = Entity.host("young.com")
        young.confidence = 1.0
        young.last_seen = datetime.now(UTC) - timedelta(hours=2)
        g.add_entity(young)

        old = Entity.host("old.com")
        old.confidence = 1.0
        old.last_seen = datetime.now(UTC) - timedelta(hours=10)
        g.add_entity(old)

        g.apply_decay()
        hosts = {h.data["host"]: h for h in g.hosts()}
        assert hosts["young.com"].confidence > hosts["old.com"].confidence

    def test_custom_decay_rate(self):
        g = KnowledgeGraph()
        host = Entity.host("decay.com")
        host.confidence = 1.0
        host.last_seen = datetime.now(UTC) - timedelta(hours=5)
        g.add_entity(host)

        # High decay rate
        g.apply_decay(decay_rate=0.1)
        conf = g.hosts()[0].confidence
        assert conf < 0.6  # significant decay with high rate

    def test_returns_affected_count(self):
        g = KnowledgeGraph()
        for name in ["a.com", "b.com", "c.com"]:
            e = Entity.host(name)
            e.last_seen = datetime.now(UTC) - timedelta(hours=3)
            g.add_entity(e)
        # One fresh entity
        g.add_entity(Entity.host("fresh.com"))
        affected = g.apply_decay()
        assert affected == 3  # only the 3 old entities
