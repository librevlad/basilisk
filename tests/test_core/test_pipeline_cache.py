"""Tests for pipeline cache integration — skip cached, write new, force phases."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from basilisk.config import Settings
from basilisk.core.executor import AsyncExecutor, PluginContext
from basilisk.core.pipeline import Pipeline, PipelineState
from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.core.registry import PluginRegistry
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target, TargetScope
from basilisk.storage.cache import ResultCache
from basilisk.storage.db import close_db, open_db


class ReconPlugin(BasePlugin):
    meta = PluginMeta(
        name="recon_cache_test", display_name="Recon Cache Test",
        category=PluginCategory.RECON,
    )

    async def run(self, target, ctx):
        return PluginResult.success(
            "recon_cache_test", target.host,
            findings=[Finding.info(f"Recon {target.host}")],
            data={"subdomains": ["sub1.example.com"]},
        )


class ScanPlugin(BasePlugin):
    meta = PluginMeta(
        name="scan_cache_test", display_name="Scan Cache Test",
        category=PluginCategory.SCANNING,
    )
    run_count = 0

    async def run(self, target, ctx):
        ScanPlugin.run_count += 1
        return PluginResult.success(
            "scan_cache_test", target.host,
            findings=[Finding.medium(f"Port open on {target.host}")],
        )


@pytest.fixture
def registry():
    reg = PluginRegistry()
    reg.register(ReconPlugin)
    reg.register(ScanPlugin)
    return reg


@pytest.fixture
def ctx():
    return PluginContext(config=Settings())


@pytest.fixture
async def cache(tmp_path):
    db = await open_db(tmp_path / "test_pipeline_cache.db")
    c = ResultCache(db)
    yield c
    await close_db(db)


class TestPipelineCacheSkip:
    async def test_skips_cached_plugin(self, registry, ctx, cache):
        """Pipeline should skip execution when a fresh cache entry exists."""
        # Pre-populate cache
        cached_result = PluginResult.success(
            "scan_cache_test", "example.com",
            findings=[Finding.medium("Cached port 80 open")],
            data={"ports": [80]},
        )
        await cache.put("example.com", cached_result)

        executor = AsyncExecutor(max_concurrency=10)
        ScanPlugin.run_count = 0
        pipeline = Pipeline(
            registry, executor, ctx,
            cache=cache,
            cache_ttl={"scanning": 1.0},
        )

        scope = TargetScope()
        scope.add(Target.domain("example.com"))

        state = await pipeline.run(scope, phases=["scanning"])

        assert state.status == "completed"
        # The plugin should NOT have been called
        assert ScanPlugin.run_count == 0
        # But the cached result should appear in results
        assert len(state.results) == 1
        assert state.results[0].plugin == "scan_cache_test"
        assert state.results[0].findings[0].title == "Cached port 80 open"

    async def test_cached_result_in_pipeline_ctx(self, registry, ctx, cache):
        """Cached results should be available in ctx.pipeline for downstream plugins."""
        cached_result = PluginResult.success(
            "recon_cache_test", "example.com",
            data={"subdomains": ["sub1.example.com"]},
        )
        await cache.put("example.com", cached_result)

        executor = AsyncExecutor(max_concurrency=10)
        pipeline = Pipeline(
            registry, executor, ctx,
            cache=cache,
            cache_ttl={"recon": 1.0},
        )

        scope = TargetScope()
        scope.add(Target.domain("example.com"))
        await pipeline.run(scope, phases=["recon"])

        assert "recon_cache_test:example.com" in ctx.pipeline

    async def test_cached_recon_expands_scope(self, registry, ctx, cache):
        """Cached recon results should still expand scope with subdomains."""
        cached_result = PluginResult.success(
            "recon_cache_test", "example.com",
            data={"subdomains": ["cached-sub.example.com"]},
        )
        await cache.put("example.com", cached_result)

        executor = AsyncExecutor(max_concurrency=10)
        pipeline = Pipeline(
            registry, executor, ctx,
            cache=cache,
            cache_ttl={"recon": 1.0},
        )

        scope = TargetScope()
        scope.add(Target.domain("example.com"))
        await pipeline.run(scope, phases=["recon"])

        assert "cached-sub.example.com" in scope.hosts


class TestPipelineCacheWrite:
    async def test_writes_new_results_to_cache(self, registry, ctx, cache):
        """After executing a plugin, results should be written to cache."""
        executor = AsyncExecutor(max_concurrency=10)
        ScanPlugin.run_count = 0
        pipeline = Pipeline(
            registry, executor, ctx,
            cache=cache,
        )

        scope = TargetScope()
        scope.add(Target.domain("example.com"))
        await pipeline.run(scope, phases=["scanning"])

        # Now check the cache has the result
        cached = await cache.get_cached("scan_cache_test", "example.com", max_age_hours=1.0)
        assert cached is not None
        assert cached.plugin == "scan_cache_test"
        assert len(cached.findings) == 1


class TestPipelineNoCache:
    async def test_no_cache_runs_everything(self, registry, ctx):
        """Without cache, all plugins should execute normally."""
        executor = AsyncExecutor(max_concurrency=10)
        ScanPlugin.run_count = 0
        pipeline = Pipeline(registry, executor, ctx, cache=None)

        scope = TargetScope()
        scope.add(Target.domain("example.com"))
        state = await pipeline.run(scope, phases=["scanning"])

        assert ScanPlugin.run_count == 1
        assert len(state.results) == 1


class TestPipelineForcePhase:
    async def test_force_phase_ignores_cache(self, registry, ctx, cache):
        """Forced phases should ignore cache and re-execute plugins."""
        cached_result = PluginResult.success(
            "scan_cache_test", "example.com",
            findings=[Finding.medium("Old cached result")],
        )
        await cache.put("example.com", cached_result)

        executor = AsyncExecutor(max_concurrency=10)
        ScanPlugin.run_count = 0
        pipeline = Pipeline(
            registry, executor, ctx,
            cache=cache,
            cache_ttl={"scanning": 1.0},
            force_phases={"scanning"},
        )

        scope = TargetScope()
        scope.add(Target.domain("example.com"))
        state = await pipeline.run(scope, phases=["scanning"])

        # Plugin SHOULD have been called despite cache
        assert ScanPlugin.run_count == 1
        # New result, not cached one
        assert state.results[0].findings[0].title != "Old cached result"


class TestPipelineCacheTTL:
    async def test_expired_cache_runs_plugin(self, registry, ctx, cache):
        """Expired cache entries should result in plugin execution."""
        cached_result = PluginResult.success(
            "scan_cache_test", "example.com",
            findings=[Finding.medium("Old result")],
        )
        await cache.put("example.com", cached_result)

        # Manually expire the entry
        await cache.db.execute(
            "UPDATE plugin_data SET created_at = datetime('now', '-25 hours')"
        )
        await cache.db.commit()

        executor = AsyncExecutor(max_concurrency=10)
        ScanPlugin.run_count = 0
        pipeline = Pipeline(
            registry, executor, ctx,
            cache=cache,
            cache_ttl={"scanning": 12.0},
        )

        scope = TargetScope()
        scope.add(Target.domain("example.com"))
        await pipeline.run(scope, phases=["scanning"])

        # Plugin should have been called (cache expired)
        assert ScanPlugin.run_count == 1


class TestPipelineCacheProgress:
    async def test_progress_reaches_100_with_cache(self, registry, ctx, cache):
        """Phase progress must reach 100% even when results come from cache."""
        cached_result = PluginResult.success(
            "scan_cache_test", "example.com",
            findings=[Finding.medium("Cached")],
        )
        await cache.put("example.com", cached_result)

        executor = AsyncExecutor(max_concurrency=10)
        pipeline = Pipeline(
            registry, executor, ctx,
            cache=cache,
            cache_ttl={"scanning": 1.0},
        )

        scope = TargetScope()
        scope.add(Target.domain("example.com"))
        state = await pipeline.run(scope, phases=["scanning"])

        phase = state.phases["scanning"]
        assert phase.status == "done"
        assert phase.total > 0
        assert phase.completed == phase.total
