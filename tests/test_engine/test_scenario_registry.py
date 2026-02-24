"""Tests for scenario registry."""

from __future__ import annotations

from typing import ClassVar

from basilisk.bridge.legacy_scenario import LegacyPluginScenario
from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.domain.scenario import Scenario, ScenarioMeta, ScenarioResult
from basilisk.engine.scenario_registry import ScenarioRegistry
from basilisk.models.result import PluginResult


class FakePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="fake_for_registry",
        display_name="Fake For Registry",
        category=PluginCategory.SCANNING,
    )

    async def run(self, target, ctx):
        return PluginResult.success(self.meta.name, target.host)


class FakeNativeScenario(Scenario):
    meta: ClassVar[ScenarioMeta] = ScenarioMeta(
        name="native_test",
        display_name="Native Test",
        category="scanning",
    )

    async def run(self, target, actor, surfaces, tools) -> ScenarioResult:
        return ScenarioResult(scenario="native_test", target=target.host)


class TestScenarioRegistry:
    def test_register_and_get(self):
        reg = ScenarioRegistry()
        scenario = LegacyPluginScenario.wrap(FakePlugin)
        reg.register(scenario)
        assert reg.get("fake_for_registry") is not None

    def test_list_all(self):
        reg = ScenarioRegistry()
        reg.register(LegacyPluginScenario.wrap(FakePlugin))
        assert len(reg.list_all()) == 1
        assert reg.list_all()[0].name == "fake_for_registry"

    def test_by_category(self):
        reg = ScenarioRegistry()
        reg.register(LegacyPluginScenario.wrap(FakePlugin))
        scanning = reg.by_category("scanning")
        assert len(scanning) == 1

    def test_native_priority(self):
        reg = ScenarioRegistry()
        # Register legacy first
        legacy = LegacyPluginScenario.wrap(FakePlugin)
        reg.register(legacy)
        # Native with same name should override
        class Override(Scenario):
            meta: ClassVar[ScenarioMeta] = ScenarioMeta(
                name="fake_for_registry",
                display_name="Override",
                category="scanning",
            )
            async def run(self, target, actor, surfaces, tools):
                return ScenarioResult(scenario="override", target=target.host)

        reg.register(Override())
        assert reg.get("fake_for_registry").meta.display_name == "Override"

    def test_names_property(self):
        reg = ScenarioRegistry()
        reg.register(FakeNativeScenario())
        assert "native_test" in reg.names

    def test_resolve_order_no_deps(self):
        reg = ScenarioRegistry()
        reg.register(FakeNativeScenario())
        reg.register(LegacyPluginScenario.wrap(FakePlugin))
        ordered = reg.resolve_order()
        assert len(ordered) == 2

    def test_resolve_order_with_deps(self):
        reg = ScenarioRegistry()

        class A(Scenario):
            meta: ClassVar[ScenarioMeta] = ScenarioMeta(
                name="a", display_name="A", category="recon",
            )
            async def run(self, target, actor, surfaces, tools):
                return ScenarioResult(scenario="a", target="")

        class B(Scenario):
            meta: ClassVar[ScenarioMeta] = ScenarioMeta(
                name="b", display_name="B", category="scanning",
                depends_on=["a"],
            )
            async def run(self, target, actor, surfaces, tools):
                return ScenarioResult(scenario="b", target="")

        reg.register(B())
        reg.register(A())
        ordered = reg.resolve_order()
        names = [s.meta.name for s in ordered]
        assert names.index("a") < names.index("b")

    def test_discover_finds_real_plugins(self):
        reg = ScenarioRegistry()
        count = reg.discover()
        assert count > 100  # Should find 194+ legacy plugins

    def test_all_scenarios(self):
        reg = ScenarioRegistry()
        reg.register(FakeNativeScenario())
        assert len(reg.all_scenarios()) == 1
