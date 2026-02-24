"""Tests for xss_dom plugin."""

from __future__ import annotations

from basilisk.core.plugin import PluginCategory
from basilisk.plugins.pentesting.xss_dom import (
    DOM_SINKS,
    DOM_SOURCES,
    XssDomPlugin,
)


class TestXssDomMeta:
    def test_meta_name(self):
        assert XssDomPlugin.meta.name == "xss_dom"

    def test_meta_category(self):
        assert XssDomPlugin.meta.category == PluginCategory.PENTESTING

    def test_depends_on_web_crawler(self):
        assert "web_crawler" in XssDomPlugin.meta.depends_on

    def test_produces(self):
        assert "dom_xss" in XssDomPlugin.meta.produces

    def test_requires_http(self):
        assert XssDomPlugin.meta.requires_http is True


class TestXssDomData:
    def test_dom_sources_populated(self):
        assert len(DOM_SOURCES) >= 10
        assert "location.hash" in DOM_SOURCES
        assert "document.URL" in DOM_SOURCES
        assert "document.referrer" in DOM_SOURCES
        assert "window.name" in DOM_SOURCES

    def test_dom_sinks_populated(self):
        assert len(DOM_SINKS) >= 10
        assert ".innerHTML" in DOM_SINKS
        assert "eval(" in DOM_SINKS
        assert "document.write(" in DOM_SINKS
        assert ".outerHTML" in DOM_SINKS

    def test_source_sink_pair_detection(self):
        js_code = """
        var hash = location.hash;
        document.getElementById('output').innerHTML = hash;
        """
        pairs = XssDomPlugin._find_source_sink_pairs(
            js_code, ["location.hash"], [".innerHTML"],
        )
        assert len(pairs) >= 1
        assert ("location.hash", ".innerHTML") in pairs

    def test_no_pairs_for_clean_code(self):
        js_code = """
        var x = 42;
        document.getElementById('output').textContent = x;
        """
        pairs = XssDomPlugin._find_source_sink_pairs(
            js_code, ["location.hash"], [".innerHTML"],
        )
        assert len(pairs) == 0

    def test_extract_inline_js(self):
        html = """
        <html><body>
        <script>var x = 1;</script>
        <p>hello</p>
        <script>var y = 2;</script>
        </body></html>
        """
        js = XssDomPlugin._extract_inline_js(html)
        assert "var x = 1" in js
        assert "var y = 2" in js

    def test_resolve_url_absolute(self):
        assert XssDomPlugin._resolve_url(
            "https://cdn.example.com/app.js", "https://example.com",
        ) == "https://cdn.example.com/app.js"

    def test_resolve_url_relative(self):
        assert XssDomPlugin._resolve_url(
            "/js/app.js", "https://example.com",
        ) == "https://example.com/js/app.js"

    def test_resolve_url_protocol_relative(self):
        assert XssDomPlugin._resolve_url(
            "//cdn.example.com/app.js", "https://example.com",
        ) == "https://cdn.example.com/app.js"


class TestXssDomDiscovery:
    def test_plugin_discovered(self):
        from basilisk.core.registry import PluginRegistry

        registry = PluginRegistry()
        registry.discover()
        names = {p.meta.name for p in registry.all()}
        assert "xss_dom" in names
