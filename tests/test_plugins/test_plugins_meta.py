"""Tests for plugin metadata and registry auto-discovery."""

from basilisk.core.plugin import PluginCategory
from basilisk.core.registry import PluginRegistry
from basilisk.plugins.analysis.http_headers import HttpHeadersPlugin
from basilisk.plugins.recon.dns_enum import DnsEnumPlugin
from basilisk.plugins.scanning.port_scan import PortScanPlugin
from basilisk.plugins.scanning.ssl_check import SslCheckPlugin


class TestPluginMeta:
    def test_dns_enum_meta(self):
        assert DnsEnumPlugin.meta.name == "dns_enum"
        assert DnsEnumPlugin.meta.category == PluginCategory.RECON
        assert "dns_records" in DnsEnumPlugin.meta.produces

    def test_port_scan_meta(self):
        assert PortScanPlugin.meta.name == "port_scan"
        assert PortScanPlugin.meta.category == PluginCategory.SCANNING
        assert "dns_enum" in PortScanPlugin.meta.depends_on

    def test_ssl_check_meta(self):
        assert SslCheckPlugin.meta.name == "ssl_check"
        assert SslCheckPlugin.meta.category == PluginCategory.SCANNING

    def test_http_headers_meta(self):
        assert HttpHeadersPlugin.meta.name == "http_headers"
        assert HttpHeadersPlugin.meta.category == PluginCategory.ANALYSIS


class TestAutoDiscovery:
    def test_discover_plugins(self):
        reg = PluginRegistry()
        count = reg.discover()
        assert count >= 4
        assert "dns_enum" in reg.names
        assert "port_scan" in reg.names
        assert "ssl_check" in reg.names
        assert "http_headers" in reg.names

    def test_execution_order(self):
        reg = PluginRegistry()
        reg.discover()
        order = reg.resolve_order()
        names = [p.meta.name for p in order]

        # dns_enum must come before port_scan and ssl_check
        assert names.index("dns_enum") < names.index("port_scan")
        assert names.index("dns_enum") < names.index("ssl_check")
