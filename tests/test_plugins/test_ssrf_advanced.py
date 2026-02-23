"""Tests for ssrf_advanced plugin."""

from __future__ import annotations

from basilisk.core.plugin import PluginCategory
from basilisk.plugins.pentesting.ssrf_advanced import (
    INTERNAL_PORTS,
    PROTOCOL_PAYLOADS,
    URL_BYPASS_TEMPLATES,
    SsrfAdvancedPlugin,
)


class TestSsrfAdvancedMeta:
    def test_meta_name(self):
        assert SsrfAdvancedPlugin.meta.name == "ssrf_advanced"

    def test_meta_category(self):
        assert SsrfAdvancedPlugin.meta.category == PluginCategory.PENTESTING

    def test_depends_on_ssrf_check(self):
        assert "ssrf_check" in SsrfAdvancedPlugin.meta.depends_on

    def test_produces(self):
        assert "ssrf_advanced_findings" in SsrfAdvancedPlugin.meta.produces

    def test_timeout(self):
        assert SsrfAdvancedPlugin.meta.timeout == 90.0


class TestSsrfAdvancedData:
    def test_protocol_payloads(self):
        assert len(PROTOCOL_PAYLOADS) >= 5
        protocols = {p[0].split("://")[0] for p in PROTOCOL_PAYLOADS}
        assert "file" in protocols
        assert "dict" in protocols
        assert "gopher" in protocols

    def test_url_bypass_templates(self):
        assert len(URL_BYPASS_TEMPLATES) >= 10

    def test_internal_ports(self):
        assert len(INTERNAL_PORTS) >= 10
        port_numbers = {p[0] for p in INTERNAL_PORTS}
        assert 22 in port_numbers   # SSH
        assert 3306 in port_numbers  # MySQL
        assert 6379 in port_numbers  # Redis

    def test_url_bypass_some_have_placeholders(self):
        has_placeholder = sum(
            1 for template, _ in URL_BYPASS_TEMPLATES
            if "{host}" in template or "{scheme}" in template
        )
        # At least half should have placeholders for dynamic bypass
        assert has_placeholder >= 3
