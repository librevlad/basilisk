"""Tests for orchestrator.executor_utils — shared populate_state / entity_to_target."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.models.result import PluginResult
from basilisk.orchestrator.executor_utils import entity_to_target, populate_state


class TestPopulateState:
    def test_crawled_urls_dedup(self):
        state: dict = {}
        result = PluginResult.success("p", "h.com", data={"crawled_urls": ["/a", "/b", "/a"]})
        populate_state(state, result)
        assert state["crawled_urls"]["h.com"] == ["/a", "/b"]

    def test_forms_appended(self):
        state: dict = {}
        result = PluginResult.success("p", "h.com", data={"forms": [{"action": "/login"}]})
        populate_state(state, result)
        assert len(state["discovered_forms"]["h.com"]) == 1

    def test_waf_map(self):
        state: dict = {}
        result = PluginResult.success("p", "h.com", data={"waf": ["cloudflare"]})
        populate_state(state, result)
        assert state["waf_map"]["h.com"] == ["cloudflare"]

    def test_technologies_dedup(self):
        state: dict = {}
        r1 = PluginResult.success("p", "h.com", data={"technologies": ["nginx"]})
        r2 = PluginResult.success("p", "h.com", data={"technologies": ["nginx", "php"]})
        populate_state(state, r1)
        populate_state(state, r2)
        assert state["detected_tech"]["h.com"] == ["nginx", "php"]

    def test_subdomains_dedup(self):
        state: dict = {}
        result = PluginResult.success("p", "h.com", data={"subdomains": ["a.h.com", "a.h.com"]})
        populate_state(state, result)
        assert state["subdomains"]["h.com"] == ["a.h.com"]

    def test_upload_endpoints_as_urls(self):
        state: dict = {}
        result = PluginResult.success("p", "h.com", data={"upload_endpoints": ["/upload"]})
        populate_state(state, result)
        assert "http://h.com/upload" in state["crawled_urls"]["h.com"]

    def test_skip_on_failure(self):
        state: dict = {}
        result = PluginResult.fail("p", "h.com", error="fail")
        populate_state(state, result)
        assert state == {}

    def test_containers_appended(self):
        state: dict = {}
        result = PluginResult.success("p", "h.com", data={"containers": [{"id": "abc"}]})
        populate_state(state, result)
        assert len(state["containers"]["h.com"]) == 1

    def test_nosqli_ssti_tests(self):
        state: dict = {}
        result = PluginResult.success(
            "p", "h.com",
            data={"nosqli_tests": [{"t": 1}], "ssti_tests": [{"t": 2}]},
        )
        populate_state(state, result)
        assert len(state["nosqli_tests"]) == 1
        assert len(state["ssti_tests"]) == 1


class TestEntityToTarget:
    def test_host_entity(self):
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        graph.add_entity(host)
        target = entity_to_target(host, graph)
        assert target.host == "example.com"

    def test_host_with_services_populates_ports(self):
        graph = KnowledgeGraph()
        host = Entity.host("example.com")
        svc = Entity.service("example.com", 443, "tcp")
        graph.add_entity(host)
        graph.add_entity(svc)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        target = entity_to_target(host, graph)
        assert 443 in target.ports

    def test_service_entity_resolves_host(self):
        graph = KnowledgeGraph()
        host = Entity.host("svc.com")
        svc = Entity.service("svc.com", 80, "tcp")
        graph.add_entity(host)
        graph.add_entity(svc)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        target = entity_to_target(svc, graph)
        assert target.host == "svc.com"

    def test_ip_entity(self):
        graph = KnowledgeGraph()
        host = Entity.host("192.168.1.1")
        host.data["type"] = "ip"
        graph.add_entity(host)
        svc_entity = Entity(
            id=Entity.make_id(EntityType.SERVICE, host="192.168.1.1", port="80", protocol="tcp"),
            type=EntityType.SERVICE,
            data={"host": "192.168.1.1", "port": 80},
        )
        graph.add_entity(svc_entity)
        target = entity_to_target(svc_entity, graph)
        assert target.host == "192.168.1.1"

    def test_unknown_fallback(self):
        graph = KnowledgeGraph()
        entity = Entity(
            id="orphan",
            type=EntityType.TECHNOLOGY,
            data={},
        )
        graph.add_entity(entity)
        target = entity_to_target(entity, graph)
        assert target.host == "unknown"
