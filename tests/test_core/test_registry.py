"""Tests for plugin registry — discovery, registration, ordering."""

import pytest

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.core.registry import PluginRegistry
from basilisk.models.result import PluginResult

# === Mock plugins ===

class MockDnsEnum(BasePlugin):
    meta = PluginMeta(
        name="dns_enum",
        display_name="DNS Enumeration",
        category=PluginCategory.RECON,
        produces=["dns_records"],
    )

    async def run(self, target, ctx):
        return PluginResult.success("dns_enum", target.host)


class MockSslCheck(BasePlugin):
    meta = PluginMeta(
        name="ssl_check",
        display_name="SSL/TLS Check",
        category=PluginCategory.SCANNING,
        depends_on=["dns_enum"],
    )

    async def run(self, target, ctx):
        return PluginResult.success("ssl_check", target.host)


class MockHttpHeaders(BasePlugin):
    meta = PluginMeta(
        name="http_headers",
        display_name="HTTP Headers",
        category=PluginCategory.ANALYSIS,
        depends_on=["ssl_check"],
    )

    async def run(self, target, ctx):
        return PluginResult.success("http_headers", target.host)


class MockSubCrtsh(BasePlugin):
    meta = PluginMeta(
        name="subdomain_crtsh",
        display_name="crt.sh Subdomains",
        category=PluginCategory.RECON,
        provides="subdomains",
    )

    async def run(self, target, ctx):
        return PluginResult.success("subdomain_crtsh", target.host)


class MockSubHT(BasePlugin):
    meta = PluginMeta(
        name="subdomain_hackertarget",
        display_name="HackerTarget Subdomains",
        category=PluginCategory.RECON,
        provides="subdomains",
    )

    async def run(self, target, ctx):
        return PluginResult.success("subdomain_hackertarget", target.host)


class TestPluginRegistry:
    def test_register_and_get(self):
        reg = PluginRegistry()
        reg.register(MockDnsEnum)
        assert reg.get("dns_enum") is MockDnsEnum
        assert reg.get("nonexistent") is None

    def test_all(self):
        reg = PluginRegistry()
        reg.register(MockDnsEnum)
        reg.register(MockSslCheck)
        assert len(reg.all()) == 2

    def test_names(self):
        reg = PluginRegistry()
        reg.register(MockDnsEnum)
        reg.register(MockSslCheck)
        assert "dns_enum" in reg.names
        assert "ssl_check" in reg.names

    def test_by_category(self):
        reg = PluginRegistry()
        reg.register(MockDnsEnum)
        reg.register(MockSslCheck)
        reg.register(MockHttpHeaders)
        recon = reg.by_category(PluginCategory.RECON)
        assert len(recon) == 1
        assert recon[0].meta.name == "dns_enum"

    def test_by_provides(self):
        reg = PluginRegistry()
        reg.register(MockSubCrtsh)
        reg.register(MockSubHT)
        reg.register(MockDnsEnum)
        providers = reg.by_provides("subdomains")
        assert len(providers) == 2


class TestTopologicalSort:
    def test_basic_ordering(self):
        reg = PluginRegistry()
        reg.register(MockHttpHeaders)  # depends on ssl_check
        reg.register(MockDnsEnum)      # no deps
        reg.register(MockSslCheck)     # depends on dns_enum

        order = reg.resolve_order()
        names = [p.meta.name for p in order]
        assert names.index("dns_enum") < names.index("ssl_check")
        assert names.index("ssl_check") < names.index("http_headers")

    def test_category_stable_sort(self):
        reg = PluginRegistry()
        reg.register(MockDnsEnum)
        reg.register(MockSubCrtsh)
        order = reg.resolve_order()
        # Both are recon with no deps between them — should both appear
        assert len(order) == 2

    def test_subset(self):
        reg = PluginRegistry()
        reg.register(MockDnsEnum)
        reg.register(MockSslCheck)
        reg.register(MockHttpHeaders)

        order = reg.resolve_order(["dns_enum", "ssl_check"])
        names = [p.meta.name for p in order]
        assert "http_headers" not in names
        assert names.index("dns_enum") < names.index("ssl_check")

    def test_circular_dependency(self):
        class PluginA(BasePlugin):
            meta = PluginMeta(
                name="a", display_name="A",
                category=PluginCategory.RECON, depends_on=["b"],
            )
            async def run(self, target, ctx):
                pass

        class PluginB(BasePlugin):
            meta = PluginMeta(
                name="b", display_name="B",
                category=PluginCategory.RECON, depends_on=["a"],
            )
            async def run(self, target, ctx):
                pass

        reg = PluginRegistry()
        reg.register(PluginA)
        reg.register(PluginB)

        with pytest.raises(ValueError, match="Circular dependency"):
            reg.resolve_order()
