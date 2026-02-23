"""Tests for Audit facade — fluent API."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from basilisk.config import Settings
from basilisk.core.facade import Audit, _split_host_port
from basilisk.models.target import TargetType


class TestAuditInit:
    def test_single_target(self):
        a = Audit("example.com")
        assert a._targets == ["example.com"]

    def test_multiple_targets(self):
        a = Audit("a.com", "b.com", "c.com")
        assert a._targets == ["a.com", "b.com", "c.com"]

    def test_targets_classmethod(self):
        a = Audit.targets(["a.com", "b.com"])
        assert a._targets == ["a.com", "b.com"]

    def test_default_phases_empty(self):
        a = Audit("example.com")
        assert a._phases == []


class TestFluentChaining:
    def test_discover(self):
        a = Audit("example.com").discover()
        assert "recon" in a._phases

    def test_scan(self):
        a = Audit("example.com").scan()
        assert "scanning" in a._phases

    def test_scan_with_ports(self):
        a = Audit("example.com").scan(ports=[80, 443])
        assert a._ports == [80, 443]

    def test_analyze(self):
        a = Audit("example.com").analyze()
        assert "analysis" in a._phases

    def test_pentest(self):
        a = Audit("example.com").pentest()
        assert "pentesting" in a._phases

    def test_pentest_with_checks(self):
        a = Audit("example.com").pentest(checks=["sqli_basic"])
        assert a._checks == ["sqli_basic"]

    def test_full_chain(self):
        a = Audit("example.com").discover().scan().analyze().pentest()
        assert a._phases == ["recon", "scanning", "analysis", "pentesting"]

    def test_plugins_filter(self):
        a = Audit("example.com").plugins("ssl_check", "dns_enum")
        assert a._plugins == ["ssl_check", "dns_enum"]

    def test_wordlists(self):
        a = Audit("example.com").wordlists("dirs_common", "files_common")
        assert a._wordlists == ["dirs_common", "files_common"]

    def test_on_progress(self):
        def cb(state):
            pass

        a = Audit("example.com").on_progress(cb)
        assert a._on_progress is cb

    def test_on_finding(self):
        def cb(f, t):
            pass

        a = Audit("example.com").on_finding(cb)
        assert a._on_finding is cb

    def test_authenticate(self):
        a = Audit("example.com").authenticate("example.com", "admin", "pass")
        assert a._credentials == {"example.com": ("admin", "pass")}

    def test_bearer(self):
        a = Audit("example.com").bearer("example.com", "tok123")
        assert a._bearer_tokens == {"example.com": "tok123"}

    def test_for_project(self):
        proj = MagicMock()
        a = Audit("example.com").for_project(proj)
        assert a._project is proj

    def test_live_report(self):
        a = Audit("example.com").live_report("/tmp/report.html")
        assert a._live_report_path == Path("/tmp/report.html")

    def test_report_formats_string(self):
        a = Audit("example.com").report("html")
        assert a._formats == ["html"]

    def test_report_formats_list(self):
        a = Audit("example.com").report(["json", "csv"])
        assert a._formats == ["json", "csv"]

    def test_with_config_settings(self):
        s = Settings()
        a = Audit("example.com").with_config(s)
        assert a._config is s

    def test_with_config_string(self):
        a = Audit("example.com").with_config("/path/to/config.yaml")
        assert a._config == "/path/to/config.yaml"

    def test_returns_self(self):
        """All fluent methods return self."""
        a = Audit("example.com")
        assert a.discover() is a
        assert a.scan() is a
        assert a.analyze() is a
        assert a.pentest() is a
        assert a.report() is a


class TestResolveConfig:
    def test_none_loads_default(self):
        a = Audit("example.com")
        cfg = a._resolve_config()
        assert isinstance(cfg, Settings)

    def test_settings_object(self):
        s = Settings()
        a = Audit("example.com", config=s)
        assert a._resolve_config() is s

    def test_string_path(self, tmp_path):
        config_file = tmp_path / "test.yaml"
        config_file.write_text("http:\n  timeout: 20.0\n")
        a = Audit("example.com", config=str(config_file))
        cfg = a._resolve_config()
        assert cfg.http.timeout == 20.0


class TestAuditRun:
    async def test_run_creates_pipeline(self):
        """Verify run() creates and calls the pipeline."""
        a = Audit("example.com").discover()

        mock_state = MagicMock()
        mock_state.status = "completed"

        with (
            patch("basilisk.core.facade.Pipeline") as mock_pipeline_cls,
            patch("basilisk.core.facade.PluginRegistry") as mock_reg,
            patch("basilisk.core.facade.AsyncHttpClient") as mock_http,
        ):
            mock_pipeline = mock_pipeline_cls.return_value
            mock_pipeline.run = AsyncMock(return_value=mock_state)
            mock_http_inst = mock_http.return_value
            mock_http_inst.close = AsyncMock()
            mock_reg.return_value.discover = MagicMock()

            state = await a.run()

        assert state is mock_state
        mock_pipeline.run.assert_awaited_once()

    async def test_run_default_phases(self):
        """When no phases specified, all 4 are used."""
        a = Audit("example.com")

        mock_state = MagicMock()
        with (
            patch("basilisk.core.facade.Pipeline") as mock_pipeline_cls,
            patch("basilisk.core.facade.PluginRegistry"),
            patch("basilisk.core.facade.AsyncHttpClient") as mock_http,
        ):
            mock_pipeline = mock_pipeline_cls.return_value
            mock_pipeline.run = AsyncMock(return_value=mock_state)
            mock_http.return_value.close = AsyncMock()

            await a.run()

            call_args = mock_pipeline.run.call_args
            phases = call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get("phases")
            # Positional args: scope, plugins, phases
            assert phases == [
                "recon", "scanning", "analysis", "pentesting",
                "exploitation", "post_exploit", "privesc", "lateral",
                "crypto", "forensics",
            ]


class TestBuildScopeIpTargets:
    def test_build_scope_ip_target(self):
        audit = Audit("127.0.0.1")
        scope = audit._build_scope(Settings())
        assert scope.targets[0].type == TargetType.IP

    def test_build_scope_ip_with_port(self):
        audit = Audit("192.168.1.1:8080")
        scope = audit._build_scope(Settings())
        assert scope.targets[0].type == TargetType.IP
        assert scope.targets[0].host == "192.168.1.1:8080"
        assert scope.targets[0].ports == [8080]

    def test_build_scope_localhost(self):
        audit = Audit("localhost")
        scope = audit._build_scope(Settings())
        assert scope.targets[0].type == TargetType.IP

    def test_build_scope_domain_unchanged(self):
        audit = Audit("example.com")
        scope = audit._build_scope(Settings())
        assert scope.targets[0].type == TargetType.DOMAIN

    def test_build_scope_ipv6_localhost(self):
        audit = Audit("[::1]:4280")
        scope = audit._build_scope(Settings())
        assert scope.targets[0].type == TargetType.IP
        assert scope.targets[0].host == "[::1]:4280"
        assert scope.targets[0].ports == [4280]

    def test_build_scope_ipv6_no_port(self):
        audit = Audit("[::1]")
        scope = audit._build_scope(Settings())
        assert scope.targets[0].type == TargetType.IP
        assert scope.targets[0].host == "::1"
        assert scope.targets[0].ports == []


class TestSplitHostPort:
    def test_ipv4_with_port(self):
        assert _split_host_port("192.168.1.1:8080") == ("192.168.1.1", 8080)

    def test_ipv4_no_port(self):
        assert _split_host_port("192.168.1.1") == ("192.168.1.1", None)

    def test_localhost_no_port(self):
        assert _split_host_port("localhost") == ("localhost", None)

    def test_localhost_with_port(self):
        assert _split_host_port("localhost:4280") == ("localhost", 4280)

    def test_ipv6_with_port(self):
        assert _split_host_port("[::1]:8080") == ("::1", 8080)

    def test_ipv6_no_port(self):
        assert _split_host_port("[::1]") == ("::1", None)


class TestProbeTargetScheme:
    async def test_returns_https_when_available(self):
        ctx = MagicMock()
        ctx.http = AsyncMock()
        ctx.http.head = AsyncMock(return_value=MagicMock())
        result = await Audit._probe_target_scheme(ctx, "example.com")
        assert result == "https"

    async def test_returns_http_fallback(self):
        ctx = MagicMock()
        ctx.http = AsyncMock()
        ctx.http.head = AsyncMock(side_effect=Exception("Connection refused"))
        result = await Audit._probe_target_scheme(ctx, "example.com")
        assert result == "http"

    async def test_returns_http_when_no_http_client(self):
        ctx = MagicMock()
        ctx.http = None
        result = await Audit._probe_target_scheme(ctx, "example.com")
        assert result == "http"


class TestBuildScopePortPreservation:
    def test_ip_with_port_preserves_full_host(self):
        audit = Audit("127.0.0.1:4280")
        scope = audit._build_scope(Settings())
        assert scope.targets[0].host == "127.0.0.1:4280"
        assert scope.targets[0].ports == [4280]
        assert scope.targets[0].type == TargetType.IP

    def test_ip_without_port_uses_bare_ip(self):
        audit = Audit("192.168.1.1")
        scope = audit._build_scope(Settings())
        assert scope.targets[0].host == "192.168.1.1"
        assert scope.targets[0].ports == []


class TestRunPlugin:
    async def test_run_plugin_success(self):
        """Static run_plugin should execute a single plugin."""
        mock_result = MagicMock()
        mock_result.ok = True

        with (
            patch("basilisk.core.facade.PluginRegistry") as mock_reg,
            patch("basilisk.core.facade.AsyncExecutor") as mock_exec,
            patch("basilisk.core.facade.AsyncHttpClient") as mock_http,
        ):
            mock_plugin_cls = MagicMock()
            mock_plugin_inst = mock_plugin_cls.return_value
            mock_plugin_inst.setup = AsyncMock()
            mock_plugin_inst.teardown = AsyncMock()
            mock_reg.return_value.get.return_value = mock_plugin_cls
            mock_reg.return_value.discover = MagicMock()
            mock_exec.return_value.run_batch = AsyncMock(return_value=[mock_result])
            mock_http.return_value.close = AsyncMock()

            results = await Audit.run_plugin("ssl_check", ["example.com"])

        assert len(results) == 1
        assert results[0] is mock_result

    async def test_run_plugin_not_found(self):
        with (
            patch("basilisk.core.facade.PluginRegistry") as mock_reg,
        ):
            mock_reg.return_value.get.return_value = None
            mock_reg.return_value.discover = MagicMock()

            with pytest.raises(ValueError, match="not found"):
                await Audit.run_plugin("nonexistent", ["example.com"])
