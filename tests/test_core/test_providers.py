"""Tests for ProviderPool — multi-provider aggregation."""

import asyncio

import pytest

from basilisk.config import Settings
from basilisk.core.executor import PluginContext
from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.core.providers import ProviderPool
from basilisk.core.registry import PluginRegistry
from basilisk.models.result import PluginResult
from basilisk.models.target import Target


class SubCrtsh(BasePlugin):
    meta = PluginMeta(
        name="sub_crtsh", display_name="crt.sh",
        category=PluginCategory.RECON, provides="subdomains",
    )

    async def run(self, target, ctx):
        return PluginResult.success(
            "sub_crtsh", target.host,
            data={"subdomains": ["a.example.com", "b.example.com"]},
        )


class SubHT(BasePlugin):
    meta = PluginMeta(
        name="sub_ht", display_name="HackerTarget",
        category=PluginCategory.RECON, provides="subdomains",
    )

    async def run(self, target, ctx):
        return PluginResult.success(
            "sub_ht", target.host,
            data={"subdomains": ["b.example.com", "c.example.com"]},
        )


class SubFailing(BasePlugin):
    meta = PluginMeta(
        name="sub_failing", display_name="Failing Provider",
        category=PluginCategory.RECON, provides="subdomains",
    )

    async def run(self, target, ctx):
        msg = "Provider down"
        raise ConnectionError(msg)


class SubSlow(BasePlugin):
    meta = PluginMeta(
        name="sub_slow", display_name="Slow Provider",
        category=PluginCategory.RECON, provides="subdomains",
    )

    async def run(self, target, ctx):
        await asyncio.sleep(5)
        return PluginResult.success(
            "sub_slow", target.host,
            data={"subdomains": ["slow.example.com"]},
        )


@pytest.fixture
def registry():
    reg = PluginRegistry()
    reg.register(SubCrtsh)
    reg.register(SubHT)
    return reg


@pytest.fixture
def ctx():
    return PluginContext(config=Settings())


@pytest.fixture
def pool(registry):
    return ProviderPool(registry)


class TestProviderPool:
    def test_get_providers(self, pool):
        providers = pool.get_providers("subdomains")
        assert len(providers) == 2

    def test_no_providers(self, pool):
        providers = pool.get_providers("nonexistent")
        assert len(providers) == 0

    async def test_gather_all(self, pool, ctx):
        target = Target.domain("example.com")
        result = await pool.gather("subdomains", target, ctx, strategy="all")
        assert result.ok
        subs = result.data.get("subdomains", [])
        assert "a.example.com" in subs
        assert "b.example.com" in subs
        assert "c.example.com" in subs
        # b.example.com should be deduplicated
        assert subs.count("b.example.com") == 1

    async def test_gather_first(self, pool, ctx):
        target = Target.domain("example.com")
        result = await pool.gather("subdomains", target, ctx, strategy="first")
        assert result.ok
        # Should return the first successful result
        assert "subdomains" in result.data

    async def test_gather_no_providers(self, pool, ctx):
        target = Target.domain("example.com")
        result = await pool.gather("nonexistent", target, ctx)
        assert not result.ok
        assert "No providers" in result.error

    async def test_gather_all_with_failures(self, ctx):
        reg = PluginRegistry()
        reg.register(SubCrtsh)
        reg.register(SubFailing)
        pool = ProviderPool(reg)

        target = Target.domain("example.com")
        result = await pool.gather("subdomains", target, ctx, strategy="all")
        # Should still succeed with partial results
        assert result.ok or result.status == "partial"
        subs = result.data.get("subdomains", [])
        assert "a.example.com" in subs

    async def test_gather_fastest(self, ctx):
        reg = PluginRegistry()
        reg.register(SubCrtsh)  # fast
        reg.register(SubSlow)   # slow
        pool = ProviderPool(reg)

        target = Target.domain("example.com")
        result = await pool.gather("subdomains", target, ctx, strategy="fastest")
        assert result.ok
        # Should be the fast one
        assert result.plugin == "sub_crtsh"
