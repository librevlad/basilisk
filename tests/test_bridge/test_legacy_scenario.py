"""Tests for legacy plugin scenario adapter."""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import MagicMock

from basilisk.bridge.legacy_scenario import LegacyPluginScenario, _noise_from_risk, _to_v3_target
from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.domain.target import LiveTarget
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class FakePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="fake_plugin",
        display_name="Fake Plugin",
        category=PluginCategory.SCANNING,
        description="A fake plugin for testing",
        produces=["ports"],
        timeout=15.0,
        risk_level="safe",
    )

    async def run(self, target, ctx):
        return PluginResult.success(
            self.meta.name, target.host,
            findings=[Finding.info("Port 80 open")],
            data={"open_ports": [80]},
        )


class TestLegacyPluginScenario:
    def test_wrap_derives_meta(self):
        scenario = LegacyPluginScenario.wrap(FakePlugin)
        assert scenario.meta.name == "fake_plugin"
        assert scenario.meta.display_name == "Fake Plugin"
        assert scenario.meta.category == "scanning"
        assert scenario.meta.timeout == 15.0

    def test_wrap_preserves_plugin_cls(self):
        scenario = LegacyPluginScenario.wrap(FakePlugin)
        assert scenario.plugin_cls is FakePlugin

    async def test_run_through_bridge(self):
        scenario = LegacyPluginScenario.wrap(FakePlugin)
        target = LiveTarget.domain("example.com")
        actor = MagicMock()
        actor.http_client = None
        actor.dns_client = None
        actor.net_utils = None
        actor.rate_limiter = None
        actor.browser = None
        actor._deadline = 0.0

        result = await scenario.run(target, actor, [], {"state": {}})
        assert result.ok
        assert result.scenario == "fake_plugin"
        assert len(result.findings) == 1
        assert result.data["open_ports"] == [80]

    def test_accepts_delegates(self):
        scenario = LegacyPluginScenario.wrap(FakePlugin)
        target = LiveTarget.domain("example.com")
        assert scenario.accepts(target)

    def test_repr(self):
        scenario = LegacyPluginScenario.wrap(FakePlugin)
        assert "fake_plugin" in repr(scenario)


class TestHelpers:
    def test_to_v3_target_from_live(self):
        live = LiveTarget.domain("example.com", ports=[80, 443])
        v3 = _to_v3_target(live)
        assert isinstance(v3, Target)
        assert v3.host == "example.com"
        assert v3.ports == [80, 443]

    def test_to_v3_target_passthrough(self):
        v3 = Target.domain("example.com")
        result = _to_v3_target(v3)
        assert result is v3

    def test_noise_from_risk(self):
        assert _noise_from_risk("safe") == 1.0
        assert _noise_from_risk("noisy") == 5.0
        assert _noise_from_risk("destructive") == 8.0
        assert _noise_from_risk("unknown") == 1.0

    def test_wrap_multiple_plugins(self):
        s1 = LegacyPluginScenario.wrap(FakePlugin)

        class FakePlugin2(BasePlugin):
            meta: ClassVar[PluginMeta] = PluginMeta(
                name="fake_plugin2",
                display_name="Fake 2",
                category=PluginCategory.RECON,
            )
            async def run(self, target, ctx):
                return PluginResult.success(self.meta.name, target.host)

        s2 = LegacyPluginScenario.wrap(FakePlugin2)
        assert s1.meta.name == "fake_plugin"
        assert s2.meta.name == "fake_plugin2"
