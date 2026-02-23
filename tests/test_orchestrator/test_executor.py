"""Tests for OrchestratorExecutor."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.models.result import PluginResult
from basilisk.models.target import TargetType
from basilisk.orchestrator.executor import OrchestratorExecutor


def _make_executor(*, result: PluginResult | None = None) -> OrchestratorExecutor:
    registry = MagicMock()
    plugin_cls = MagicMock()
    plugin_inst = plugin_cls.return_value
    plugin_inst.setup = AsyncMock()
    plugin_inst.teardown = AsyncMock()
    registry.get.return_value = plugin_cls

    core_executor = AsyncMock()
    if result is not None:
        core_executor.run_one.return_value = result
    else:
        core_executor.run_one.return_value = PluginResult.success(
            "test_plugin", "test.com",
        )

    ctx = MagicMock()
    ctx.pipeline = {}
    ctx.state = {}
    ctx.emit = MagicMock()

    return OrchestratorExecutor(registry, core_executor, ctx)


class TestPopulateState:
    async def test_crawled_urls_populated(self):
        result = PluginResult.success(
            "web_crawler", "test.com",
            data={"crawled_urls": ["http://test.com/a", "http://test.com/b"]},
        )
        ex = _make_executor(result=result)
        cap = MagicMock()
        cap.plugin_name = "web_crawler"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "crawled_urls" in ex.ctx.state
        assert "test.com" in ex.ctx.state["crawled_urls"]
        assert len(ex.ctx.state["crawled_urls"]["test.com"]) == 2

    async def test_forms_populated(self):
        result = PluginResult.success(
            "form_analyzer", "test.com",
            data={"forms": [{"action": "/login", "method": "POST"}]},
        )
        ex = _make_executor(result=result)
        cap = MagicMock()
        cap.plugin_name = "form_analyzer"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "discovered_forms" in ex.ctx.state
        assert len(ex.ctx.state["discovered_forms"]["test.com"]) == 1

    async def test_api_paths_populated(self):
        result = PluginResult.success(
            "api_detect", "test.com",
            data={"api_paths": ["/api/v1/users"], "interesting_paths": ["/admin"]},
        )
        ex = _make_executor(result=result)
        cap = MagicMock()
        cap.plugin_name = "api_detect"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "discovered_api_paths" in ex.ctx.state
        paths = ex.ctx.state["discovered_api_paths"]["test.com"]
        assert "/api/v1/users" in paths
        assert "/admin" in paths

    async def test_crawled_urls_dedup(self):
        result = PluginResult.success(
            "web_crawler", "test.com",
            data={"crawled_urls": ["http://test.com/a", "http://test.com/a"]},
        )
        ex = _make_executor(result=result)
        # Pre-populate state
        ex.ctx.state["crawled_urls"] = {"test.com": ["http://test.com/a"]}

        cap = MagicMock()
        cap.plugin_name = "web_crawler"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        # Should not duplicate
        assert len(ex.ctx.state["crawled_urls"]["test.com"]) == 1

    async def test_waf_map_populated(self):
        result = PluginResult.success(
            "waf_detect", "test.com",
            data={"waf": ["Cloudflare"]},
        )
        ex = _make_executor(result=result)
        cap = MagicMock()
        cap.plugin_name = "waf_detect"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert ex.ctx.state["waf_map"]["test.com"] == ["Cloudflare"]

    async def test_no_state_on_failed_result(self):
        result = PluginResult.fail("test_plugin", "test.com", error="fail")
        ex = _make_executor(result=result)
        cap = MagicMock()
        cap.plugin_name = "test_plugin"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "crawled_urls" not in ex.ctx.state


class TestNosqliSstiState:
    async def test_nosqli_tests_propagated(self):
        result = PluginResult.success(
            "nosqli_check", "test.com",
            data={"nosqli_tests": [{"url": "/api", "param": "q", "type": "auth_bypass"}]},
        )
        ex = _make_executor(result=result)
        cap = MagicMock()
        cap.plugin_name = "nosqli_check"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "nosqli_tests" in ex.ctx.state
        assert len(ex.ctx.state["nosqli_tests"]) == 1
        assert ex.ctx.state["nosqli_tests"][0]["param"] == "q"

    async def test_ssti_tests_propagated(self):
        result = PluginResult.success(
            "ssti_check", "test.com",
            data={"ssti_tests": [{"url": "/render", "param": "tpl", "engine": "jinja2"}]},
        )
        ex = _make_executor(result=result)
        cap = MagicMock()
        cap.plugin_name = "ssti_check"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "ssti_tests" in ex.ctx.state
        assert len(ex.ctx.state["ssti_tests"]) == 1
        assert ex.ctx.state["ssti_tests"][0]["engine"] == "jinja2"


class TestDetectedTechState:
    async def test_technologies_propagated(self):
        result = PluginResult.success(
            "tech_detect", "test.com",
            data={"technologies": [{"name": "PHP", "version": "8.2"}, "nginx"]},
        )
        ex = _make_executor(result=result)
        cap = MagicMock()
        cap.plugin_name = "tech_detect"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "detected_tech" in ex.ctx.state
        techs = ex.ctx.state["detected_tech"]["test.com"]
        assert "PHP" in techs
        assert "nginx" in techs

    async def test_technologies_dedup(self):
        result = PluginResult.success(
            "tech_detect", "test.com",
            data={"technologies": ["PHP", "PHP"]},
        )
        ex = _make_executor(result=result)
        ex.ctx.state["detected_tech"] = {"test.com": ["PHP"]}
        cap = MagicMock()
        cap.plugin_name = "tech_detect"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert len(ex.ctx.state["detected_tech"]["test.com"]) == 1


class TestSubdomainsState:
    async def test_subdomains_propagated(self):
        result = PluginResult.success(
            "subdomain_crtsh", "test.com",
            data={"subdomains": ["a.test.com", "b.test.com"]},
        )
        ex = _make_executor(result=result)
        cap = MagicMock()
        cap.plugin_name = "subdomain_crtsh"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "subdomains" in ex.ctx.state
        subs = ex.ctx.state["subdomains"]["test.com"]
        assert "a.test.com" in subs
        assert "b.test.com" in subs

    async def test_subdomains_dedup(self):
        result = PluginResult.success(
            "subdomain_crtsh", "test.com",
            data={"subdomains": ["a.test.com"]},
        )
        ex = _make_executor(result=result)
        ex.ctx.state["subdomains"] = {"test.com": ["a.test.com"]}
        cap = MagicMock()
        cap.plugin_name = "subdomain_crtsh"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert len(ex.ctx.state["subdomains"]["test.com"]) == 1


class TestUploadEndpointsState:
    async def test_upload_endpoints_merged_to_crawled_urls(self):
        result = PluginResult.success(
            "file_upload_check", "test.com",
            data={"upload_endpoints": ["/upload", "/api/files"]},
        )
        ex = _make_executor(result=result)
        ex.ctx.state["http_scheme"] = {"test.com": "https"}

        cap = MagicMock()
        cap.plugin_name = "file_upload_check"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert "crawled_urls" in ex.ctx.state
        urls = ex.ctx.state["crawled_urls"]["test.com"]
        assert "https://test.com/upload" in urls
        assert "https://test.com/api/files" in urls

    async def test_upload_endpoints_dedup_with_existing(self):
        result = PluginResult.success(
            "file_upload_check", "test.com",
            data={"upload_endpoints": ["/upload"]},
        )
        ex = _make_executor(result=result)
        ex.ctx.state["http_scheme"] = {"test.com": "http"}
        ex.ctx.state["crawled_urls"] = {"test.com": ["http://test.com/upload"]}

        cap = MagicMock()
        cap.plugin_name = "file_upload_check"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        assert len(ex.ctx.state["crawled_urls"]["test.com"]) == 1

    async def test_upload_endpoints_default_http_scheme(self):
        result = PluginResult.success(
            "file_upload_check", "test.com",
            data={"upload_endpoints": ["/upload"]},
        )
        ex = _make_executor(result=result)
        # No http_scheme in state — should default to http

        cap = MagicMock()
        cap.plugin_name = "file_upload_check"
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)

        await ex.execute(cap, host, graph)

        urls = ex.ctx.state["crawled_urls"]["test.com"]
        assert "http://test.com/upload" in urls


class TestEntityToTargetIp:
    def test_ip_host_returns_ip_target(self):
        graph = KnowledgeGraph()
        ep = Entity.endpoint("127.0.0.1:4280", "/vuln")
        graph.add_entity(ep)
        target = OrchestratorExecutor._entity_to_target(ep, graph)
        assert target.type == TargetType.IP
        assert target.host == "127.0.0.1:4280"

    def test_domain_host_returns_domain_target(self):
        graph = KnowledgeGraph()
        ep = Entity.endpoint("example.com", "/search")
        graph.add_entity(ep)
        target = OrchestratorExecutor._entity_to_target(ep, graph)
        assert target.type == TargetType.DOMAIN
        assert target.host == "example.com"

    def test_ip_with_port_returns_ip_target(self):
        graph = KnowledgeGraph()
        ep = Entity.endpoint("10.0.0.1:8080", "/api")
        graph.add_entity(ep)
        target = OrchestratorExecutor._entity_to_target(ep, graph)
        assert target.type == TargetType.IP

    def test_host_entity_delegates_to_graph(self):
        graph = KnowledgeGraph()
        host = Entity.host("test.com")
        graph.add_entity(host)
        target = OrchestratorExecutor._entity_to_target(host, graph)
        assert target.host == "test.com"


class TestEndpointNotMarkedVulnTested:
    """vuln_tested flag was removed — loop uses was_executed() fingerprints for dedup."""

    async def test_endpoint_not_marked_after_execution(self):
        result = PluginResult.success("sqli_basic", "test.com")
        ex = _make_executor(result=result)
        cap = MagicMock()
        cap.plugin_name = "sqli_basic"
        graph = KnowledgeGraph()
        ep = Entity.endpoint("test.com", "/search")
        ep.data["has_params"] = True
        graph.add_entity(ep)

        await ex.execute(cap, ep, graph)

        updated = graph.get(ep.id)
        assert updated is not None
        assert "vuln_tested" not in updated.data
