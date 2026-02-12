"""Tests for xss_advanced plugin."""

from __future__ import annotations

from basilisk.core.plugin import PluginCategory
from basilisk.plugins.pentesting.xss_advanced import (
    CONTEXT_PAYLOADS,
    CSP_BYPASSES,
    DOM_SINKS,
    DOM_SOURCES,
    XssAdvancedPlugin,
)


class TestXssAdvancedMeta:
    def test_meta_name(self):
        assert XssAdvancedPlugin.meta.name == "xss_advanced"

    def test_meta_category(self):
        assert XssAdvancedPlugin.meta.category == PluginCategory.PENTESTING

    def test_depends_on_xss_basic(self):
        assert "xss_basic" in XssAdvancedPlugin.meta.depends_on

    def test_produces(self):
        assert "xss_advanced_findings" in XssAdvancedPlugin.meta.produces


class TestXssAdvancedData:
    def test_context_payloads_contexts(self):
        expected = {"html_tag", "html_attr", "js_string", "js_template", "url_context"}
        assert expected.issubset(set(CONTEXT_PAYLOADS.keys()))

    def test_context_payloads_non_empty(self):
        for context, payloads in CONTEXT_PAYLOADS.items():
            assert len(payloads) > 0, f"No payloads for context {context}"

    def test_dom_sources(self):
        assert len(DOM_SOURCES) >= 10
        assert "location.href" in DOM_SOURCES
        assert "document.URL" in DOM_SOURCES

    def test_dom_sinks(self):
        assert len(DOM_SINKS) >= 10
        assert "eval(" in DOM_SINKS
        assert ".innerHTML" in DOM_SINKS
        assert "document.write(" in DOM_SINKS

    def test_csp_bypasses(self):
        assert "unsafe-inline" in CSP_BYPASSES
        assert "unsafe-eval" in CSP_BYPASSES

    def test_canary_in_payloads(self):
        from basilisk.plugins.pentesting.xss_advanced import CANARY
        for context, payloads in CONTEXT_PAYLOADS.items():
            for payload, desc in payloads:
                assert CANARY in payload, (
                    f"Canary missing in {context}/{desc}"
                )
