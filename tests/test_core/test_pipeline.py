"""Tests for pipeline — orchestration, phase tracking, scope expansion."""

import pytest

from basilisk.config import Settings
from basilisk.core.executor import AsyncExecutor, PluginContext
from basilisk.core.pipeline import PhaseProgress, Pipeline, PipelineState
from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.core.registry import PluginRegistry
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target, TargetScope


class ReconPlugin(BasePlugin):
    meta = PluginMeta(
        name="recon_test", display_name="Recon Test",
        category=PluginCategory.RECON,
    )

    async def run(self, target, ctx):
        return PluginResult.success(
            "recon_test", target.host,
            findings=[Finding.info(f"Recon on {target.host}")],
            data={"subdomains": ["sub1.example.com", "sub2.example.com"]},
        )


class ScanPlugin(BasePlugin):
    meta = PluginMeta(
        name="scan_test", display_name="Scan Test",
        category=PluginCategory.SCANNING,
        depends_on=["recon_test"],
    )

    async def run(self, target, ctx):
        return PluginResult.success(
            "scan_test", target.host,
            findings=[Finding.medium(f"Port open on {target.host}")],
        )


class AnalysisPlugin(BasePlugin):
    meta = PluginMeta(
        name="analysis_test", display_name="Analysis Test",
        category=PluginCategory.ANALYSIS,
        depends_on=["scan_test"],
    )

    async def run(self, target, ctx):
        return PluginResult.success(
            "analysis_test", target.host,
            findings=[Finding.high(f"Missing header on {target.host}")],
        )


@pytest.fixture
def registry():
    reg = PluginRegistry()
    reg.register(ReconPlugin)
    reg.register(ScanPlugin)
    reg.register(AnalysisPlugin)
    return reg


@pytest.fixture
def ctx():
    return PluginContext(config=Settings())


class TestPipeline:
    async def test_full_pipeline(self, registry, ctx):
        executor = AsyncExecutor(max_concurrency=10)
        pipeline = Pipeline(registry, executor, ctx)

        scope = TargetScope()
        scope.add(Target.domain("example.com"))

        state = await pipeline.run(scope, phases=["recon", "scanning", "analysis"])

        assert state.status == "completed"
        assert state.total_findings > 0
        assert len(state.results) > 0

    async def test_scope_expansion(self, registry, ctx):
        executor = AsyncExecutor(max_concurrency=10)
        pipeline = Pipeline(registry, executor, ctx)

        scope = TargetScope()
        scope.add(Target.domain("example.com"))

        await pipeline.run(scope, phases=["recon"])

        # Recon should have expanded scope with subdomains
        assert len(scope) == 3  # original + 2 subs
        hosts = scope.hosts
        assert "sub1.example.com" in hosts
        assert "sub2.example.com" in hosts

    async def test_phase_progress(self, registry, ctx):
        progress_updates: list[PipelineState] = []

        executor = AsyncExecutor(max_concurrency=10)
        pipeline = Pipeline(
            registry, executor, ctx,
            on_progress=lambda s: progress_updates.append(
                PipelineState(
                    status=s.status,
                    phases={k: PhaseProgress(phase=v.phase, status=v.status)
                            for k, v in s.phases.items()},
                )
            ),
        )

        scope = TargetScope()
        scope.add(Target.domain("example.com"))
        await pipeline.run(scope, phases=["recon"])

        assert len(progress_updates) > 0

    async def test_single_phase(self, registry, ctx):
        executor = AsyncExecutor(max_concurrency=10)
        pipeline = Pipeline(registry, executor, ctx)

        scope = TargetScope()
        scope.add(Target.domain("example.com"))

        state = await pipeline.run(scope, phases=["recon"])
        assert "recon" in state.phases
        assert state.phases["recon"].status == "done"

    async def test_pipeline_context_stores_results(self, registry, ctx):
        executor = AsyncExecutor(max_concurrency=10)
        pipeline = Pipeline(registry, executor, ctx)

        scope = TargetScope()
        scope.add(Target.domain("example.com"))

        await pipeline.run(scope, phases=["recon"])
        assert "recon_test:example.com" in ctx.pipeline

    async def test_progress_reaches_100_pct(self, registry, ctx):
        """Phase progress must reach exactly 100% when all work is done."""
        executor = AsyncExecutor(max_concurrency=10)
        pipeline = Pipeline(registry, executor, ctx)

        scope = TargetScope()
        scope.add(Target.domain("example.com"))

        state = await pipeline.run(scope, phases=["scanning"])
        phase = state.phases["scanning"]
        assert phase.status == "done"
        assert phase.total > 0
        assert phase.completed == phase.total
        assert phase.progress_pct == 100.0

    async def test_progress_with_resume_skips(self, registry, ctx):
        """Resumed pipeline must still reach 100% with skipped targets."""
        executor = AsyncExecutor(max_concurrency=10)
        completed = {("recon_test", "example.com")}
        pipeline = Pipeline(registry, executor, ctx, completed_pairs=completed)

        scope = TargetScope()
        scope.add(Target.domain("example.com"))

        state = await pipeline.run(scope, phases=["recon"])
        phase = state.phases["recon"]
        assert phase.status == "done"
        assert phase.completed == phase.total
