"""Tests for campaign SQLite store."""

from __future__ import annotations

from datetime import UTC, datetime

import aiosqlite
import pytest

from basilisk.campaign.models import (
    PluginEfficacy,
    ServiceRecord,
    TargetProfile,
    TechFingerprint,
    TechRecord,
    TechStackRecord,
)
from basilisk.campaign.store import CampaignStore


@pytest.fixture
async def store():
    """In-memory campaign store."""
    db = await aiosqlite.connect(":memory:")
    s = CampaignStore(db)
    await s.init_schema()
    yield s
    await db.close()


class TestSchemaInit:
    async def test_tables_created(self, store: CampaignStore):
        async with store.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
        ) as cursor:
            tables = [row[0] for row in await cursor.fetchall()]
        assert "target_profiles" in tables
        assert "plugin_efficacy" in tables
        assert "tech_fingerprints" in tables

    async def test_idempotent(self, store: CampaignStore):
        # Second init should not raise
        await store.init_schema()


class TestTargetProfilePersistence:
    async def test_save_and_load(self, store: CampaignStore):
        profile = TargetProfile(
            host="example.com",
            last_audited=datetime(2025, 6, 1, tzinfo=UTC),
            audit_count=2,
            known_services=[ServiceRecord(port=80), ServiceRecord(port=443, service="https")],
            known_technologies=[TechRecord(name="nginx", version="1.24")],
            known_endpoints_count=15,
            known_findings_count=3,
            finding_severities={"HIGH": 2, "MEDIUM": 1},
        )
        await store.save_target_profile(profile)
        loaded = await store.load_target_profile("example.com")

        assert loaded is not None
        assert loaded.host == "example.com"
        assert loaded.audit_count == 2
        assert len(loaded.known_services) == 2
        assert loaded.known_services[1].service == "https"
        assert len(loaded.known_technologies) == 1
        assert loaded.known_technologies[0].name == "nginx"
        assert loaded.known_endpoints_count == 15
        assert loaded.known_findings_count == 3
        assert loaded.finding_severities["HIGH"] == 2

    async def test_load_nonexistent(self, store: CampaignStore):
        assert await store.load_target_profile("nope.com") is None

    async def test_upsert(self, store: CampaignStore):
        p1 = TargetProfile(host="example.com", audit_count=1)
        await store.save_target_profile(p1)
        p2 = TargetProfile(host="example.com", audit_count=5)
        await store.save_target_profile(p2)

        loaded = await store.load_target_profile("example.com")
        assert loaded.audit_count == 5

    async def test_load_all(self, store: CampaignStore):
        await store.save_target_profile(TargetProfile(host="a.com"))
        await store.save_target_profile(TargetProfile(host="b.com"))
        all_profiles = await store.load_all_target_profiles()
        assert len(all_profiles) == 2


class TestPluginEfficacyPersistence:
    async def test_save_and_load(self, store: CampaignStore):
        eff = PluginEfficacy(
            plugin_name="port_scan",
            total_runs=50,
            total_successes=40,
            total_new_entities=200,
            total_findings=10,
            total_runtime=125.5,
            tech_stack_stats={
                "nginx,php": TechStackRecord(runs=10, successes=8, new_entities=30, findings=2),
            },
        )
        await store.save_plugin_efficacy(eff)
        loaded = await store.load_all_plugin_efficacy()

        assert len(loaded) == 1
        assert loaded[0].plugin_name == "port_scan"
        assert loaded[0].total_runs == 50
        assert loaded[0].total_successes == 40
        assert "nginx,php" in loaded[0].tech_stack_stats
        ts = loaded[0].tech_stack_stats["nginx,php"]
        assert ts.runs == 10
        assert ts.successes == 8

    async def test_upsert(self, store: CampaignStore):
        await store.save_plugin_efficacy(
            PluginEfficacy(plugin_name="ssl_check", total_runs=5),
        )
        await store.save_plugin_efficacy(
            PluginEfficacy(plugin_name="ssl_check", total_runs=15),
        )
        loaded = await store.load_all_plugin_efficacy()
        assert len(loaded) == 1
        assert loaded[0].total_runs == 15


class TestTechFingerprintPersistence:
    async def test_save_and_load(self, store: CampaignStore):
        fp = TechFingerprint(
            base_domain="example.com",
            technologies=["nginx", "php", "wordpress"],
            observation_count=3,
            last_seen=datetime(2025, 6, 1, tzinfo=UTC),
        )
        await store.save_tech_fingerprint(fp)
        loaded = await store.load_tech_fingerprint("example.com")

        assert loaded is not None
        assert loaded.base_domain == "example.com"
        assert loaded.technologies == ["nginx", "php", "wordpress"]
        assert loaded.observation_count == 3

    async def test_load_nonexistent(self, store: CampaignStore):
        assert await store.load_tech_fingerprint("nope.com") is None

    async def test_upsert(self, store: CampaignStore):
        fp1 = TechFingerprint(
            base_domain="test.com", technologies=["nginx"], observation_count=1,
        )
        await store.save_tech_fingerprint(fp1)
        fp2 = TechFingerprint(
            base_domain="test.com", technologies=["nginx", "php"], observation_count=2,
        )
        await store.save_tech_fingerprint(fp2)

        loaded = await store.load_tech_fingerprint("test.com")
        assert loaded.technologies == ["nginx", "php"]
        assert loaded.observation_count == 2
