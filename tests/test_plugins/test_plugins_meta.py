"""Tests for plugin metadata and registry auto-discovery."""

from basilisk.core.plugin import PluginCategory
from basilisk.core.registry import PluginRegistry
from basilisk.plugins.analysis.http_headers import HttpHeadersPlugin
from basilisk.plugins.recon.dns_enum import DnsEnumPlugin
from basilisk.plugins.scanning.port_scan import PortScanPlugin
from basilisk.plugins.scanning.ssl_check import SslCheckPlugin
from basilisk.plugins.scanning.ssl_compliance import SslCompliancePlugin
from basilisk.plugins.scanning.ssl_protocols import SslProtocolsPlugin
from basilisk.plugins.scanning.ssl_vulns import SslVulnsPlugin


class TestPluginMeta:
    def test_dns_enum_meta(self):
        assert DnsEnumPlugin.meta.name == "dns_enum"
        assert DnsEnumPlugin.meta.category == PluginCategory.RECON
        assert "dns_records" in DnsEnumPlugin.meta.produces

    def test_port_scan_meta(self):
        assert PortScanPlugin.meta.name == "port_scan"
        assert PortScanPlugin.meta.category == PluginCategory.SCANNING
        assert PortScanPlugin.meta.depends_on == []

    def test_ssl_check_meta(self):
        assert SslCheckPlugin.meta.name == "ssl_check"
        assert SslCheckPlugin.meta.category == PluginCategory.SCANNING
        assert "ssl_info" in SslCheckPlugin.meta.produces

    def test_ssl_protocols_meta(self):
        assert SslProtocolsPlugin.meta.name == "ssl_protocols"
        assert SslProtocolsPlugin.meta.category == PluginCategory.SCANNING
        assert "ssl_check" in SslProtocolsPlugin.meta.depends_on
        assert "ssl_protocols" in SslProtocolsPlugin.meta.produces

    def test_ssl_vulns_meta(self):
        assert SslVulnsPlugin.meta.name == "ssl_vulns"
        assert SslVulnsPlugin.meta.category == PluginCategory.SCANNING
        assert "ssl_check" in SslVulnsPlugin.meta.depends_on
        assert "ssl_protocols" in SslVulnsPlugin.meta.depends_on
        assert "ssl_vulns" in SslVulnsPlugin.meta.produces

    def test_ssl_compliance_meta(self):
        assert SslCompliancePlugin.meta.name == "ssl_compliance"
        assert SslCompliancePlugin.meta.category == PluginCategory.SCANNING
        assert "ssl_check" in SslCompliancePlugin.meta.depends_on
        assert "ssl_compliance" in SslCompliancePlugin.meta.produces

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
        assert "ssl_protocols" in reg.names
        assert "ssl_vulns" in reg.names
        assert "ssl_compliance" in reg.names
        assert "http_headers" in reg.names

    def test_execution_order(self):
        reg = PluginRegistry()
        reg.discover()
        order = reg.resolve_order()
        names = [p.meta.name for p in order]

        # dns_enum must come before port_scan and ssl_check
        assert names.index("dns_enum") < names.index("port_scan")
        assert names.index("dns_enum") < names.index("ssl_check")

        # ssl_check must come before ssl_protocols, ssl_vulns, ssl_compliance
        assert names.index("ssl_check") < names.index("ssl_protocols")
        assert names.index("ssl_check") < names.index("ssl_vulns")
        assert names.index("ssl_check") < names.index("ssl_compliance")

        # ssl_protocols must come before ssl_vulns
        assert names.index("ssl_protocols") < names.index("ssl_vulns")
