"""Integration tests for the v4 execution path."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from basilisk.bridge.legacy_scenario import LegacyPluginScenario
from basilisk.capabilities.mapping import (
    CAPABILITY_MAP,
    build_capabilities,
    build_capabilities_from_scenarios,
)
from basilisk.core.registry import PluginRegistry
from basilisk.domain.scenario import ScenarioResult
from basilisk.engine.scenario_registry import ScenarioRegistry
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.orchestrator.scenario_executor import ScenarioExecutor


class TestV4IntegrationPath:
    def test_scenario_registry_discovers_all(self):
        """All legacy plugins + native scenarios discovered."""
        registry = ScenarioRegistry()
        registry.discover()
        total = len(registry.all_scenarios())
        assert total >= 190  # 188 legacy + 5 native = 193

    def test_capabilities_from_scenarios_parity(self):
        """All CAPABILITY_MAP entries present + native scenarios added."""
        registry = ScenarioRegistry()
        registry.discover()
        caps = build_capabilities_from_scenarios(registry)

        # All explicit CAPABILITY_MAP keys must be present
        for name in CAPABILITY_MAP:
            assert name in caps, f"{name} from CAPABILITY_MAP missing in scenario caps"

        # Native scenarios should also be present
        native_names = [
            s.meta.name for s in registry.all_scenarios()
            if not isinstance(s, LegacyPluginScenario)
        ]
        for name in native_names:
            assert name in caps, f"native scenario {name} missing from caps"

    async def test_scenario_executor_runs_native(self):
        """Native scenario executes via ScenarioExecutor, returns observations."""
        mock_scenario = AsyncMock()
        mock_scenario.run.return_value = ScenarioResult(
            scenario="dns_scenario",
            target="test.com",
            data={"dns_records": [{"type": "A", "name": "test.com", "value": "1.2.3.4"}]},
        )
        registry = MagicMock()
        registry.get.return_value = mock_scenario

        executor = ScenarioExecutor(
            registry=registry, actor=MagicMock(), settings=MagicMock(),
        )
        cap = MagicMock()
        cap.plugin_name = "dns_scenario"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        obs = await executor.execute(cap, host, graph)

        assert len(obs) >= 1
        mock_scenario.run.assert_called_once()

    async def test_scenario_executor_runs_legacy(self):
        """Legacy plugin executes via ScenarioExecutor bridge, returns observations."""
        mock_scenario = AsyncMock()
        mock_scenario.run.return_value = ScenarioResult(
            scenario="port_scan", target="test.com",
            data={"open_ports": [{"port": 80, "protocol": "tcp"}]},
        )
        registry = MagicMock()
        registry.get.return_value = mock_scenario

        executor = ScenarioExecutor(
            registry=registry, actor=MagicMock(), settings=MagicMock(),
        )
        cap = MagicMock()
        cap.plugin_name = "port_scan"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        obs = await executor.execute(cap, host, graph)

        assert len(obs) >= 1

    def test_full_pipeline_compatibility(self):
        """build_capabilities_from_scenarios() produces same keys for legacy."""
        v3_registry = PluginRegistry()
        v3_registry.discover()
        v3_caps = build_capabilities(v3_registry)

        v4_registry = ScenarioRegistry()
        v4_registry.discover()
        v4_caps = build_capabilities_from_scenarios(v4_registry)

        # Every v3 cap key must be in v4 caps
        for key in v3_caps:
            assert key in v4_caps, f"v3 key {key} missing from v4 caps"

        # v4 should have extra native scenario entries
        assert len(v4_caps) >= len(v3_caps)
