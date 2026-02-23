"""Tests for async executor and plugin context."""

import asyncio

import pytest

from basilisk.config import Settings
from basilisk.core.executor import AsyncExecutor, PluginContext
from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class FastPlugin(BasePlugin):
    meta = PluginMeta(
        name="fast", display_name="Fast",
        category=PluginCategory.RECON, timeout=5.0,
    )

    async def run(self, target, ctx):
        return PluginResult.success(
            "fast", target.host,
            findings=[Finding.info(f"Checked {target.host}")],
        )


class SlowPlugin(BasePlugin):
    meta = PluginMeta(
        name="slow", display_name="Slow",
        category=PluginCategory.SCANNING, timeout=0.1,
    )

    async def run(self, target, ctx):
        await asyncio.sleep(5)
        return PluginResult.success("slow", target.host)


class FailingPlugin(BasePlugin):
    meta = PluginMeta(
        name="failing", display_name="Failing",
        category=PluginCategory.ANALYSIS, timeout=5.0,
    )

    async def run(self, target, ctx):
        msg = "Intentional error"
        raise RuntimeError(msg)


class SelectivePlugin(BasePlugin):
    meta = PluginMeta(
        name="selective", display_name="Selective",
        category=PluginCategory.SCANNING, timeout=5.0,
    )

    def accepts(self, target):
        return target.host.startswith("web")

    async def run(self, target, ctx):
        return PluginResult.success("selective", target.host)


@pytest.fixture
def ctx():
    return PluginContext(config=Settings())


@pytest.fixture
def executor():
    return AsyncExecutor(max_concurrency=10)


class TestAsyncExecutor:
    async def test_run_one_success(self, executor, ctx):
        plugin = FastPlugin()
        target = Target.domain("example.com")
        result = await executor.run_one(plugin, target, ctx)
        assert result.ok
        assert result.duration > 0

    async def test_run_one_timeout(self, executor, ctx):
        plugin = SlowPlugin()
        target = Target.domain("example.com")
        result = await executor.run_one(plugin, target, ctx)
        assert result.status == "timeout"
        assert "Timed out" in result.error

    async def test_run_one_error(self, executor, ctx):
        plugin = FailingPlugin()
        target = Target.domain("example.com")
        result = await executor.run_one(plugin, target, ctx)
        assert result.status == "error"
        assert "Intentional error" in result.error

    async def test_run_batch(self, executor, ctx):
        plugin = FastPlugin()
        targets = [Target.domain(f"site{i}.com") for i in range(5)]
        results = await executor.run_batch(plugin, targets, ctx)
        assert len(results) == 5
        assert all(r.ok for r in results)

    async def test_run_batch_selective(self, executor, ctx):
        plugin = SelectivePlugin()
        targets = [
            Target.domain("web1.com"),
            Target.domain("api.com"),
            Target.domain("web2.com"),
        ]
        results = await executor.run_batch(plugin, targets, ctx)
        assert len(results) == 2

    async def test_emit_callback(self, executor):
        findings_received: list[Finding] = []
        ctx = PluginContext(
            config=Settings(),
            emit=lambda f, t="": findings_received.append(f),
        )
        plugin = FastPlugin()
        targets = [Target.domain("example.com")]
        await executor.run_batch(plugin, targets, ctx)
        assert len(findings_received) == 1


class TestPluginContext:
    def test_defaults(self, ctx):
        assert ctx.pipeline == {}
        assert ctx.state == {}
        assert ctx.http is None

    def test_pipeline_storage(self, ctx):
        result = PluginResult.success("test", "example.com")
        ctx.pipeline["test:example.com"] = result
        assert ctx.pipeline["test:example.com"].ok
