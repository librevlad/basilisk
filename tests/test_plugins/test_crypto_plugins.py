"""Tests for crypto category plugins — meta, discovery, mock run()."""

from __future__ import annotations

import pytest

from basilisk.core.plugin import BasePlugin, PluginCategory
from basilisk.core.registry import PluginRegistry
from basilisk.models.result import PluginResult
from basilisk.models.target import Target

CRYPTO_PLUGINS = [
    "aes_attack", "classical_cipher", "custom_crypto", "hash_crack",
    "hash_extension", "jwt_forge", "prng_crack", "rsa_attack",
]


class TestCryptoDiscovery:
    """Verify all crypto plugins are discovered and have valid meta."""

    def test_all_crypto_discovered(self):
        registry = PluginRegistry()
        registry.discover()
        found = registry.by_category(PluginCategory.CRYPTO)
        names = {p.meta.name for p in found}
        for expected in CRYPTO_PLUGINS:
            assert expected in names, f"Missing crypto plugin: {expected}"

    def test_crypto_count(self):
        registry = PluginRegistry()
        registry.discover()
        found = registry.by_category(PluginCategory.CRYPTO)
        assert len(found) == 8


class TestCryptoMeta:
    """Validate metadata for each crypto plugin."""

    @pytest.fixture
    def registry(self):
        r = PluginRegistry()
        r.discover()
        return r

    @pytest.mark.parametrize("plugin_name", CRYPTO_PLUGINS)
    def test_meta_fields(self, registry, plugin_name):
        cls = registry.get(plugin_name)
        assert cls is not None, f"Plugin {plugin_name} not found"
        meta = cls.meta
        assert meta.name == plugin_name
        assert meta.display_name
        assert meta.category == PluginCategory.CRYPTO
        assert meta.timeout > 0
        assert isinstance(meta.produces, list)

    @pytest.mark.parametrize("plugin_name", CRYPTO_PLUGINS)
    def test_is_base_plugin(self, registry, plugin_name):
        cls = registry.get(plugin_name)
        assert issubclass(cls, BasePlugin)


class TestAesAttackRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.crypto.aes_attack import AesAttackPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = AesAttackPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestClassicalCipherRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.crypto.classical_cipher import ClassicalCipherPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = ClassicalCipherPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestCustomCryptoRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.crypto.custom_crypto import CustomCryptoPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = CustomCryptoPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestHashCrackRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.crypto.hash_crack import HashCrackPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = HashCrackPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestHashExtensionRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.crypto.hash_extension import HashExtensionPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = HashExtensionPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestJwtForgeRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.crypto.jwt_forge import JwtForgePlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = JwtForgePlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestPrngCrackRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.crypto.prng_crack import PrngCrackPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = PrngCrackPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)


class TestRsaAttackRun:
    async def test_run_returns_result(self, mock_ctx):
        from basilisk.plugins.crypto.rsa_attack import RsaAttackPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}
        plugin = RsaAttackPlugin()
        result = await plugin.run(target, mock_ctx)
        assert isinstance(result, PluginResult)
