"""Tests for privilege escalation category plugins — meta, discovery, mock run()."""

from __future__ import annotations

import pytest

from basilisk.core.plugin import BasePlugin, PluginCategory
from basilisk.core.registry import PluginRegistry
from basilisk.models.result import PluginResult
from basilisk.models.target import Target

PRIVESC_PLUGINS = [
    "capability_exploit", "cron_exploit", "kernel_exploit",
    "sudo_exploit", "suid_exploit", "win_service_exploit",
    "win_token_exploit",
]


class TestPrivescDiscovery:
    """Verify all privesc plugins are discovered and have valid meta."""

    def test_all_privesc_discovered(self):
        registry = PluginRegistry()
        registry.discover()
        found = registry.by_category(PluginCategory.PRIVESC)
        names = {p.meta.name for p in found}
        for expected in PRIVESC_PLUGINS:
            assert expected in names, f"Missing privesc plugin: {expected}"

    def test_privesc_count(self):
        registry = PluginRegistry()
        registry.discover()
        found = registry.by_category(PluginCategory.PRIVESC)
        assert len(found) == 7


class TestPrivescMeta:
    """Validate metadata for each privesc plugin."""

    @pytest.fixture
    def registry(self):
        r = PluginRegistry()
        r.discover()
        return r

    @pytest.mark.parametrize("plugin_name", PRIVESC_PLUGINS)
    def test_meta_fields(self, registry, plugin_name):
        cls = registry.get(plugin_name)
        assert cls is not None, f"Plugin {plugin_name} not found"
        meta = cls.meta
        assert meta.name == plugin_name
        assert meta.display_name
        assert meta.category == PluginCategory.PRIVESC
        assert meta.timeout > 0
        assert isinstance(meta.produces, list)

    @pytest.mark.parametrize("plugin_name", PRIVESC_PLUGINS)
    def test_is_base_plugin(self, registry, plugin_name):
        cls = registry.get(plugin_name)
        assert issubclass(cls, BasePlugin)


class TestCapabilityExploitRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.privesc.capability_exploit import CapabilityExploitPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = CapabilityExploitPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestCronExploitRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.privesc.cron_exploit import CronExploitPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = CronExploitPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestKernelExploitRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.privesc.kernel_exploit import KernelExploitPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = KernelExploitPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestSudoExploitRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.privesc.sudo_exploit import SudoExploitPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = SudoExploitPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestSuidExploitRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.privesc.suid_exploit import SuidExploitPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = SuidExploitPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestWinServiceExploitRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.privesc.win_service_exploit import WinServiceExploitPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = WinServiceExploitPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestWinTokenExploitRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.privesc.win_token_exploit import WinTokenExploitPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = WinTokenExploitPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)
