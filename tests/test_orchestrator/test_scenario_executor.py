"""Tests for ScenarioExecutor."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.models.result import PluginResult
from basilisk.orchestrator.scenario_executor import ScenarioExecutor


def _make_executor(
    *,
    scenario_result=None,
    scenario=None,
) -> ScenarioExecutor:
    """Create a ScenarioExecutor with mock registry/actor."""
    registry = MagicMock()

    if scenario is not None:
        registry.get.return_value = scenario
    else:
        mock_scenario = AsyncMock()
        if scenario_result is not None:
            mock_scenario.run.return_value = scenario_result
        else:
            from basilisk.domain.scenario import ScenarioResult

            mock_scenario.run.return_value = ScenarioResult(
                scenario="test_plugin", target="test.com",
            )
        registry.get.return_value = mock_scenario

    settings = MagicMock()
    actor = MagicMock()

    return ScenarioExecutor(
        registry=registry, actor=actor, settings=settings,
    )


class TestExecuteLegacyScenario:
    async def test_execute_returns_observations(self):
        from basilisk.domain.scenario import ScenarioResult

        result = ScenarioResult(
            scenario="web_crawler",
            target="test.com",
            data={"crawled_urls": ["http://test.com/a"]},
        )
        ex = _make_executor(scenario_result=result)
        cap = MagicMock()
        cap.plugin_name = "web_crawler"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        observations = await ex.execute(cap, host, graph)

        # Should return at least the host observation
        assert isinstance(observations, list)
        assert len(observations) >= 1


class TestExecuteNativeScenario:
    async def test_execute_native_returns_observations(self):
        from basilisk.domain.finding import Finding
        from basilisk.domain.scenario import ScenarioResult

        result = ScenarioResult(
            scenario="dns_scenario",
            target="test.com",
            findings=[Finding.info("Test finding", scenario_name="dns_scenario")],
            data={"dns_records": [{"type": "A", "name": "test.com", "value": "1.2.3.4"}]},
        )
        ex = _make_executor(scenario_result=result)
        cap = MagicMock()
        cap.plugin_name = "dns_scenario"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        observations = await ex.execute(cap, host, graph)

        assert isinstance(observations, list)
        assert len(observations) >= 1


class TestPipelinePopulated:
    async def test_pipeline_has_result_after_execute(self):
        from basilisk.domain.scenario import ScenarioResult

        result = ScenarioResult(scenario="port_scan", target="test.com")
        ex = _make_executor(scenario_result=result)
        cap = MagicMock()
        cap.plugin_name = "port_scan"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "port_scan:test.com" in ex.ctx.pipeline
        assert isinstance(ex.ctx.pipeline["port_scan:test.com"], PluginResult)


class TestMissingScenario:
    async def test_missing_scenario_returns_empty(self):
        registry = MagicMock()
        registry.get.return_value = None
        settings = MagicMock()
        actor = MagicMock()
        ex = ScenarioExecutor(registry=registry, actor=actor, settings=settings)

        cap = MagicMock()
        cap.plugin_name = "nonexistent"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        observations = await ex.execute(cap, host, graph)

        assert observations == []


class TestStatePopulated:
    async def test_crawled_urls_in_state(self):
        from basilisk.domain.scenario import ScenarioResult

        result = ScenarioResult(
            scenario="web_crawler",
            target="test.com",
            data={"crawled_urls": ["http://test.com/x", "http://test.com/y"]},
        )
        ex = _make_executor(scenario_result=result)
        cap = MagicMock()
        cap.plugin_name = "web_crawler"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "crawled_urls" in ex.ctx.state
        assert "test.com" in ex.ctx.state["crawled_urls"]
        assert len(ex.ctx.state["crawled_urls"]["test.com"]) == 2
