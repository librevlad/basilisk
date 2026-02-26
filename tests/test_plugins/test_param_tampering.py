"""Tests for param_tampering plugin."""

from __future__ import annotations

from basilisk.core.plugin import PluginCategory
from basilisk.plugins.pentesting.param_tampering import (
    AUTH_FIELDS,
    BUSINESS_FIELDS,
    NUMERIC_TAMPERS,
    PRIV_PARAMS,
    ParamTamperingPlugin,
)


class TestParamTamperingMeta:
    def test_meta_name(self):
        assert ParamTamperingPlugin.meta.name == "param_tampering"

    def test_meta_category(self):
        assert ParamTamperingPlugin.meta.category == PluginCategory.PENTESTING

    def test_no_hard_dependency(self):
        assert ParamTamperingPlugin.meta.depends_on == []

    def test_produces(self):
        assert "param_tampering" in ParamTamperingPlugin.meta.produces

    def test_requires_http(self):
        assert ParamTamperingPlugin.meta.requires_http is True


class TestParamTamperingData:
    def test_priv_params_populated(self):
        assert len(PRIV_PARAMS) >= 5
        names = [p[0] for p in PRIV_PARAMS]
        assert "admin" in names
        assert "role" in names
        assert "debug" in names

    def test_numeric_tampers_populated(self):
        assert len(NUMERIC_TAMPERS) >= 4
        values = [t[0] for t in NUMERIC_TAMPERS]
        assert "0" in values
        assert "-1" in values

    def test_business_fields_regex(self):
        assert BUSINESS_FIELDS.search("price")
        assert BUSINESS_FIELDS.search("total_amount")
        assert BUSINESS_FIELDS.search("quantity")
        assert not BUSINESS_FIELDS.search("username")

    def test_auth_fields_regex(self):
        assert AUTH_FIELDS.search("role")
        assert AUTH_FIELDS.search("is_admin")
        assert AUTH_FIELDS.search("permission_level")
        assert not AUTH_FIELDS.search("email")

    def test_indicates_escalation(self):
        baseline = "<html>Welcome, user</html>"
        escalated = "<html>Welcome, admin dashboard</html>"
        assert ParamTamperingPlugin._indicates_escalation(baseline, escalated)

    def test_no_escalation(self):
        baseline = "<html>Welcome, user</html>"
        response = "<html>Welcome, user</html>"
        assert not ParamTamperingPlugin._indicates_escalation(baseline, response)

    def test_accepted_tamper_reflected(self):
        baseline = "<html>Price: 100</html>"
        response = "<html>Price: -1</html>"
        assert ParamTamperingPlugin._accepted_tamper(baseline, response, "-1")

    def test_not_accepted_tamper_error(self):
        baseline = "<html>Price: 100</html>"
        response = "<html>Error: invalid value</html>"
        assert not ParamTamperingPlugin._accepted_tamper(baseline, response, "-1")

    def test_has_stack_trace(self):
        body = "Traceback (most recent call last):\n  File..."
        assert ParamTamperingPlugin._has_stack_trace(body)

    def test_no_stack_trace(self):
        body = "<html>Normal page</html>"
        assert not ParamTamperingPlugin._has_stack_trace(body)


class TestParamTamperingDiscovery:
    def test_plugin_discovered(self):
        from basilisk.core.registry import PluginRegistry

        registry = PluginRegistry()
        registry.discover()
        names = {p.meta.name for p in registry.all()}
        assert "param_tampering" in names
