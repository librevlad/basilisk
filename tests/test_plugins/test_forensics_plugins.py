"""Tests for forensics category plugins — meta, discovery, mock run()."""

from __future__ import annotations

import pytest

from basilisk.core.plugin import BasePlugin, PluginCategory
from basilisk.core.registry import PluginRegistry
from basilisk.models.result import PluginResult
from basilisk.models.target import Target

FORENSICS_PLUGINS = [
    "disk_forensics", "file_forensics", "log_analyze",
    "memory_analyze", "pcap_analyze", "steganography",
]


class TestForensicsDiscovery:
    """Verify all forensics plugins are discovered and have valid meta."""

    def test_all_forensics_discovered(self):
        registry = PluginRegistry()
        registry.discover()
        found = registry.by_category(PluginCategory.FORENSICS)
        names = {p.meta.name for p in found}
        for expected in FORENSICS_PLUGINS:
            assert expected in names, f"Missing forensics plugin: {expected}"

    def test_forensics_count(self):
        registry = PluginRegistry()
        registry.discover()
        found = registry.by_category(PluginCategory.FORENSICS)
        assert len(found) == 6


class TestForensicsMeta:
    """Validate metadata for each forensics plugin."""

    @pytest.fixture
    def registry(self):
        r = PluginRegistry()
        r.discover()
        return r

    @pytest.mark.parametrize("plugin_name", FORENSICS_PLUGINS)
    def test_meta_fields(self, registry, plugin_name):
        cls = registry.get(plugin_name)
        assert cls is not None, f"Plugin {plugin_name} not found"
        meta = cls.meta
        assert meta.name == plugin_name
        assert meta.display_name
        assert meta.category == PluginCategory.FORENSICS
        assert meta.timeout > 0
        assert isinstance(meta.produces, list)

    @pytest.mark.parametrize("plugin_name", FORENSICS_PLUGINS)
    def test_is_base_plugin(self, registry, plugin_name):
        cls = registry.get(plugin_name)
        assert issubclass(cls, BasePlugin)


class TestDiskForensicsRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.forensics.disk_forensics import DiskForensicsPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = DiskForensicsPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestFileForensicsRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.forensics.file_forensics import FileForensicsPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = FileForensicsPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestLogAnalyzeRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.forensics.log_analyze import LogAnalyzePlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = LogAnalyzePlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestMemoryAnalyzeRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.forensics.memory_analyze import MemoryAnalyzePlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = MemoryAnalyzePlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestPcapAnalyzeRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.forensics.pcap_analyze import PcapAnalyzePlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = PcapAnalyzePlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestSteganographyRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.forensics.steganography import SteganographyPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = SteganographyPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)
