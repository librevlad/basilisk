"""Integration test: Scorer + CampaignMemory end-to-end."""

from __future__ import annotations

import aiosqlite
import pytest

from basilisk.campaign.memory import CampaignMemory
from basilisk.campaign.models import (
    PluginEfficacy,
    ServiceRecord,
    TargetProfile,
    TechRecord,
    TechStackRecord,
)
from basilisk.campaign.store import CampaignStore
from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.scoring.scorer import Scorer


@pytest.fixture
async def campaign_memory():
    """CampaignMemory loaded with seed data."""
    db = await aiosqlite.connect(":memory:")
    store = CampaignStore(db)
    await store.init_schema()

    await store.save_target_profile(TargetProfile(
        host="example.com",
        known_services=[ServiceRecord(port=80), ServiceRecord(port=443)],
        known_technologies=[TechRecord(name="nginx"), TechRecord(name="php")],
    ))
    await store.save_plugin_efficacy(PluginEfficacy(
        plugin_name="tech_detect",
        total_runs=30,
        total_successes=25,
        tech_stack_stats={
            "nginx,php": TechStackRecord(runs=15, successes=14),
        },
    ))
    await store.save_plugin_efficacy(PluginEfficacy(
        plugin_name="bad_plugin",
        total_runs=20,
        total_successes=2,
    ))

    mem = CampaignMemory()
    await mem.load(store, ["example.com"])
    yield mem
    await db.close()


class TestScorerWithCampaign:
    async def test_campaign_adjusts_cost(self, campaign_memory: CampaignMemory):
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        graph.add_entity(host)

        scorer = Scorer(graph, campaign_memory=campaign_memory)

        cap = Capability(
            name="Tech Detect",
            plugin_name="tech_detect",
            category="analysis",
            cost_score=5.0,
            noise_score=1.0,
            produces_knowledge=["Technology"],
        )

        scored = scorer.rank([(cap, host)])
        assert len(scored) == 1
        # Cost should be adjusted by campaign memory
        breakdown = scored[0].score_breakdown
        assert breakdown["cost"] != 5.0  # Should be adjusted
        assert breakdown["cost"] < 5.0   # tech_detect has high success rate → discount

    async def test_prior_bonus_for_known_host(self, campaign_memory: CampaignMemory):
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        graph.add_entity(host)

        scorer = Scorer(graph, campaign_memory=campaign_memory)

        cap = Capability(
            name="Tech Detect",
            plugin_name="tech_detect",
            category="analysis",
            cost_score=5.0,
            noise_score=1.0,
            produces_knowledge=["Technology"],
        )

        scored = scorer.rank([(cap, host)])
        breakdown = scored[0].score_breakdown
        # Known host with known techs and tech_rate > 0.5 → prior_bonus > 0
        assert breakdown["prior_bonus"] > 0.0

    async def test_no_campaign_no_bonus(self):
        """Without campaign memory, prior_bonus should be 0."""
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        graph.add_entity(host)

        scorer = Scorer(graph)  # No campaign

        cap = Capability(
            name="Tech Detect",
            plugin_name="tech_detect",
            category="analysis",
            cost_score=5.0,
            noise_score=1.0,
            produces_knowledge=["Technology"],
        )

        scored = scorer.rank([(cap, host)])
        breakdown = scored[0].score_breakdown
        assert breakdown["prior_bonus"] == 0.0

    async def test_known_service_bonus(self, campaign_memory: CampaignMemory):
        graph = KnowledgeGraph()
        svc = Entity.service("example.com", 443, "tcp")
        graph.add_entity(svc)

        scorer = Scorer(graph, campaign_memory=campaign_memory)

        cap = Capability(
            name="SSL Check",
            plugin_name="ssl_check",
            category="scanning",
            cost_score=3.0,
            noise_score=1.0,
            produces_knowledge=["Finding"],
        )

        scored = scorer.rank([(cap, svc)])
        breakdown = scored[0].score_breakdown
        # Port 443 is known infrastructure → prior_bonus = 0.15
        assert breakdown["prior_bonus"] == 0.15

    async def test_unknown_service_no_bonus(self, campaign_memory: CampaignMemory):
        graph = KnowledgeGraph()
        svc = Entity.service("example.com", 8080, "tcp")
        graph.add_entity(svc)

        scorer = Scorer(graph, campaign_memory=campaign_memory)

        cap = Capability(
            name="SSL Check",
            plugin_name="ssl_check",
            category="scanning",
            cost_score=3.0,
            noise_score=1.0,
            produces_knowledge=["Finding"],
        )

        scored = scorer.rank([(cap, svc)])
        breakdown = scored[0].score_breakdown
        assert breakdown["prior_bonus"] == 0.0
