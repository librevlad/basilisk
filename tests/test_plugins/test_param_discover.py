"""Tests for parameter discovery plugin."""

from __future__ import annotations

from basilisk.plugins.pentesting.param_discover import (
    COMMON_PARAMS,
    ParamDiscoverPlugin,
)


class TestParamDiscover:
    def test_meta(self):
        plugin = ParamDiscoverPlugin()
        assert plugin.meta.name == "param_discover"
        assert "discovered_params" in plugin.meta.produces
        assert plugin.meta.timeout == 60.0

    def test_common_params_count(self):
        assert len(COMMON_PARAMS) >= 100

    def test_common_params_no_duplicates(self):
        assert len(COMMON_PARAMS) == len(set(COMMON_PARAMS))

    def test_common_params_include_idor_targets(self):
        """IDOR-relevant params should be included."""
        idor_params = {"id", "uid", "user_id", "account_id", "order_id"}
        assert idor_params.issubset(set(COMMON_PARAMS))

    def test_common_params_include_injection_targets(self):
        """Injection-relevant params should be included."""
        injection_params = {"url", "redirect", "template", "cmd", "include"}
        assert injection_params.issubset(set(COMMON_PARAMS))

    def test_common_params_include_auth_targets(self):
        """Auth-relevant params should be included."""
        auth_params = {"token", "api_key", "secret", "password"}
        assert auth_params.issubset(set(COMMON_PARAMS))

    def test_common_params_include_api_params(self):
        """API-related params should be included."""
        api_params = {"page", "limit", "sort", "filter", "fields"}
        assert api_params.issubset(set(COMMON_PARAMS))
