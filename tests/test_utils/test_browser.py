"""Tests for headless browser manager (without Playwright dependency)."""

from __future__ import annotations

from basilisk.utils.browser import (
    BrowserManager,
    RenderedPage,
    XSSConfirmation,
)


class TestBrowserManagerNoPlaywright:
    """Tests that work without Playwright installed."""

    def test_rendered_page_defaults(self):
        page = RenderedPage(url="https://example.com")
        assert page.url == "https://example.com"
        assert page.html == ""
        assert page.status == 0
        assert page.api_calls == []
        assert page.links == []
        assert page.forms == []
        assert page.screenshot == b""

    def test_xss_confirmation_defaults(self):
        result = XSSConfirmation(url="https://example.com", payload="<script>")
        assert not result.executed
        assert result.alert_text == ""
        assert result.screenshot == b""

    def test_manager_not_available_without_start(self):
        mgr = BrowserManager()
        assert not mgr.available

    async def test_render_returns_empty_when_unavailable(self):
        mgr = BrowserManager()
        page = await mgr.render("https://example.com")
        assert page.html == ""
        assert page.status == 0

    async def test_confirm_xss_returns_false_when_unavailable(self):
        mgr = BrowserManager()
        result = await mgr.confirm_xss(
            "https://example.com", "<script>alert(1)</script>"
        )
        assert not result.executed

    async def test_crawl_spa_returns_empty_when_unavailable(self):
        mgr = BrowserManager()
        urls = await mgr.crawl_spa("https://example.com")
        assert urls == []

    async def test_extract_js_routes_returns_empty_when_unavailable(self):
        mgr = BrowserManager()
        routes = await mgr.extract_js_routes("https://example.com")
        assert routes == []

    def test_filter_api_calls(self):
        urls = [
            "https://example.com/api/users",
            "https://example.com/static/app.js",
            "https://example.com/v1/data?page=1",
            "https://cdn.other.com/lib.js",
            "https://example.com/images/logo.png",
            "https://example.com/graphql",
            "https://example.com/style.css",
        ]
        result = BrowserManager._filter_api_calls(
            urls, "https://example.com"
        )
        assert "https://example.com/api/users" in result
        assert "https://example.com/v1/data?page=1" in result
        assert "https://example.com/graphql" in result
        # Static assets and other domains filtered out
        assert "https://example.com/static/app.js" not in result
        assert "https://cdn.other.com/lib.js" not in result
        assert "https://example.com/images/logo.png" not in result
        assert "https://example.com/style.css" not in result
