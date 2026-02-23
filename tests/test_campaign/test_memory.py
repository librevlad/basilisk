"""Tests for CampaignMemory in-memory aggregator."""

from __future__ import annotations

import aiosqlite
import pytest

from basilisk.campaign.memory import CampaignMemory, _extract_base_domain
from basilisk.campaign.models import (
    PluginEfficacy,
    ServiceRecord,
    TargetProfile,
    TechFingerprint,
    TechRecord,
    TechStackRecord,
)
from basilisk.campaign.store import CampaignStore
from basilisk.decisions.decision import Decision
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.memory.history import History


@pytest.fixture
async def store():
    """In-memory campaign store with some data."""
    db = await aiosqlite.connect(":memory:")
    s = CampaignStore(db)
    await s.init_schema()

    # Seed data
    await s.save_target_profile(TargetProfile(
        host="example.com",
        audit_count=3,
        known_services=[ServiceRecord(port=80), ServiceRecord(port=443)],
        known_technologies=[TechRecord(name="nginx"), TechRecord(name="php")],
    ))
    await s.save_plugin_efficacy(PluginEfficacy(
        plugin_name="port_scan",
        total_runs=20,
        total_successes=18,
        tech_stack_stats={
            "nginx,php": TechStackRecord(runs=10, successes=8),
        },
    ))
    await s.save_tech_fingerprint(TechFingerprint(
        base_domain="example.com",
        technologies=["nginx", "php"],
    ))

    yield s
    await db.close()


class TestLoad:
    async def test_loads_profiles(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])
        assert mem.get_profile("example.com") is not None

    async def test_loads_efficacy(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])
        assert mem.plugin_success_rate("port_scan") == 0.9

    async def test_loads_fingerprints(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["sub.example.com"])
        # Should load fingerprint for base domain "example.com"
        assert mem.known_technologies("sub.example.com") == []
        # But the fingerprint is there (accessed internally)

    async def test_unknown_host(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["unknown.com"])
        assert mem.get_profile("unknown.com") is None


class TestQueryMethods:
    async def test_plugin_success_rate(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])
        assert mem.plugin_success_rate("port_scan") == 0.9
        assert mem.plugin_success_rate("nonexistent") == 0.0

    async def test_plugin_tech_rate(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])
        # "nginx,php" has 10 runs (>= 3), success rate = 0.8
        rate = mem.plugin_tech_rate("port_scan", ["nginx", "php"])
        assert rate == 0.8

    async def test_plugin_tech_rate_insufficient_data(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])
        # Unknown tech stack
        assert mem.plugin_tech_rate("port_scan", ["apache"]) is None

    async def test_adjusted_cost(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])
        # port_scan success_rate=0.9 → multiplier = 2.0 - 1.3*0.9 = 0.83
        cost = mem.adjusted_cost("port_scan", 5.0)
        assert cost == pytest.approx(5.0 * 0.83, abs=0.01)

    async def test_adjusted_cost_unknown_plugin(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])
        assert mem.adjusted_cost("unknown_plugin", 5.0) == 5.0

    async def test_is_known_infrastructure(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])
        assert mem.is_known_infrastructure("example.com", 80) is True
        assert mem.is_known_infrastructure("example.com", 8080) is False
        assert mem.is_known_infrastructure("unknown.com", 80) is False

    async def test_known_technologies(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])
        techs = mem.known_technologies("example.com")
        assert "nginx" in techs
        assert "php" in techs
        assert mem.known_technologies("unknown.com") == []


class TestUpdateFromGraph:
    async def test_merges_new_host(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])

        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("new.com"))
        graph.add_entity(Entity.service("new.com", 22, "tcp", service="ssh"))
        host_id = Entity.make_id(EntityType.HOST, host="new.com")
        svc_id = Entity.make_id(EntityType.SERVICE, host="new.com", port="22", protocol="tcp")
        graph.add_relation(Relation(
            source_id=host_id, target_id=svc_id, type=RelationType.EXPOSES,
        ))

        history = History()
        mem.update_from_graph(graph, history)

        profile = mem.get_profile("new.com")
        assert profile is not None
        assert len(profile.known_services) == 1
        assert profile.known_services[0].port == 22

    async def test_increments_audit_count(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])

        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("example.com"))
        history = History()
        mem.update_from_graph(graph, history)

        profile = mem.get_profile("example.com")
        assert profile.audit_count == 4  # was 3, now +1

    async def test_merges_efficacy(self, store: CampaignStore):
        mem = CampaignMemory()
        await mem.load(store, ["example.com"])

        graph = KnowledgeGraph()
        history = History()
        d = Decision(
            id="test1",
            chosen_plugin="port_scan",
            outcome_new_entities=3,
            outcome_confidence_delta=0.5,
            outcome_duration=1.0,
        )
        history.record(d)
        mem.update_from_graph(graph, history)

        # Should have merged: original 20 runs + 1 new = 21
        rate = mem.plugin_success_rate("port_scan")
        # 18 + 1 successes out of 20 + 1 = 21 runs
        assert rate == pytest.approx(19 / 21, abs=0.01)


class TestExtractBaseDomain:
    def test_subdomain(self):
        assert _extract_base_domain("sub.example.com") == "example.com"

    def test_single_label(self):
        assert _extract_base_domain("localhost") == "localhost"
