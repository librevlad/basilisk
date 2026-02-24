"""Tests for auth_bypass plugin."""

from __future__ import annotations

from basilisk.core.plugin import PluginCategory
from basilisk.plugins.pentesting.auth_bypass import (
    AUTH_ENDPOINTS,
    LOGIN_SQLI,
    PROTECTED_PAGES,
    RESET_ENDPOINTS,
    AuthBypassPlugin,
)


class TestAuthBypassMeta:
    def test_meta_name(self):
        assert AuthBypassPlugin.meta.name == "auth_bypass"

    def test_meta_category(self):
        assert AuthBypassPlugin.meta.category == PluginCategory.PENTESTING

    def test_depends_on_web_crawler(self):
        assert "web_crawler" in AuthBypassPlugin.meta.depends_on

    def test_produces(self):
        assert "auth_bypass" in AuthBypassPlugin.meta.produces

    def test_requires_http(self):
        assert AuthBypassPlugin.meta.requires_http is True


class TestAuthBypassData:
    def test_auth_endpoints_populated(self):
        assert len(AUTH_ENDPOINTS) >= 5
        assert "/login" in AUTH_ENDPOINTS
        assert "/signin" in AUTH_ENDPOINTS

    def test_reset_endpoints_populated(self):
        assert len(RESET_ENDPOINTS) >= 3
        assert "/forgot-password" in RESET_ENDPOINTS

    def test_protected_pages_populated(self):
        assert len(PROTECTED_PAGES) >= 5
        assert "/admin" in PROTECTED_PAGES
        assert "/dashboard" in PROTECTED_PAGES

    def test_login_sqli_payloads(self):
        assert len(LOGIN_SQLI) >= 3
        assert any("OR" in p for p in LOGIN_SQLI)

    def test_has_admin_content_positive(self):
        body = "<html><body>Admin Dashboard<form><table></table></form></body></html>"
        assert AuthBypassPlugin._has_admin_content(body)

    def test_has_admin_content_negative(self):
        body = "<html><body>404 Not Found</body></html>"
        assert not AuthBypassPlugin._has_admin_content(body)

    def test_find_field(self):
        html = '<input type="text" name="username" /><input type="password" name="password" />'
        assert AuthBypassPlugin._find_field(html, ["username", "user"]) == "username"
        assert AuthBypassPlugin._find_field(html, ["password", "pass"]) == "password"
        assert AuthBypassPlugin._find_field(html, ["nonexistent"]) is None

    def test_responses_differ_meaningfully_same(self):
        assert not AuthBypassPlugin._responses_differ_meaningfully("body", "body")

    def test_responses_differ_meaningfully_error_msg(self):
        body1 = "Invalid password"
        body2 = "User not found"
        assert AuthBypassPlugin._responses_differ_meaningfully(body1, body2)

    def test_responses_differ_meaningfully_length(self):
        body1 = "short"
        body2 = "a" * 200
        assert AuthBypassPlugin._responses_differ_meaningfully(body1, body2)


class TestAuthBypassDiscovery:
    def test_plugin_discovered(self):
        from basilisk.core.registry import PluginRegistry

        registry = PluginRegistry()
        registry.discover()
        names = {p.meta.name for p in registry.all()}
        assert "auth_bypass" in names
