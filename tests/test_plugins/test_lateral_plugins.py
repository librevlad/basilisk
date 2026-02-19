"""Tests for lateral movement category plugins — meta, discovery, mock run()."""

from __future__ import annotations

import pytest

from basilisk.core.plugin import BasePlugin, PluginCategory
from basilisk.core.registry import PluginRegistry
from basilisk.models.result import PluginResult
from basilisk.models.target import Target

LATERAL_PLUGINS = [
    "ad_acl_abuse", "ad_cert_attack", "asrep_roast",
    "bloodhound_collect", "constrained_deleg", "dcsync",
    "gpp_decrypt", "kerberoast", "ntlm_relay",
    "pass_the_hash", "pass_the_ticket", "secrets_dump",
]


class TestLateralDiscovery:
    """Verify all lateral plugins are discovered and have valid meta."""

    def test_all_lateral_discovered(self):
        registry = PluginRegistry()
        registry.discover()
        found = registry.by_category(PluginCategory.LATERAL)
        names = {p.meta.name for p in found}
        for expected in LATERAL_PLUGINS:
            assert expected in names, f"Missing lateral plugin: {expected}"

    def test_lateral_count(self):
        registry = PluginRegistry()
        registry.discover()
        found = registry.by_category(PluginCategory.LATERAL)
        assert len(found) == 12


class TestLateralMeta:
    """Validate metadata for each lateral plugin."""

    @pytest.fixture
    def registry(self):
        r = PluginRegistry()
        r.discover()
        return r

    @pytest.mark.parametrize("plugin_name", LATERAL_PLUGINS)
    def test_meta_fields(self, registry, plugin_name):
        cls = registry.get(plugin_name)
        assert cls is not None, f"Plugin {plugin_name} not found"
        meta = cls.meta
        assert meta.name == plugin_name
        assert meta.display_name
        assert meta.category == PluginCategory.LATERAL
        assert meta.timeout > 0
        assert isinstance(meta.produces, list)

    @pytest.mark.parametrize("plugin_name", LATERAL_PLUGINS)
    def test_is_base_plugin(self, registry, plugin_name):
        cls = registry.get(plugin_name)
        assert issubclass(cls, BasePlugin)


class TestAdAclAbuseRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.ad_acl_abuse import AdAclAbusePlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = AdAclAbusePlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestAdCertAttackRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.ad_cert_attack import AdCertAttackPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = AdCertAttackPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestAsrepRoastRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.asrep_roast import AsrepRoastPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = AsrepRoastPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestBloodhoundCollectRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.bloodhound_collect import BloodHoundCollectPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = BloodHoundCollectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestConstrainedDelegRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.constrained_deleg import ConstrainedDelegPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = ConstrainedDelegPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestDcSyncRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.dcsync import DcSyncPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = DcSyncPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestGppDecryptRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.gpp_decrypt import GppDecryptPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = GppDecryptPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestKerberoastRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.kerberoast import KerberoastPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = KerberoastPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestNtlmRelayRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.ntlm_relay import NtlmRelayPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = NtlmRelayPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestPassTheHashRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.pass_the_hash import PassTheHashPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = PassTheHashPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestPassTheTicketRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.pass_the_ticket import PassTheTicketPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = PassTheTicketPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestSecretsDumpRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.lateral.secrets_dump import SecretsDumpPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = SecretsDumpPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)
