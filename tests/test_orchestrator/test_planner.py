"""Tests for the knowledge gap planner."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.orchestrator.planner import Planner


class TestHostWithoutServices:
    def test_detects_gap(self):
        g = KnowledgeGraph()
        g.add_entity(Entity.host("test.com"))
        gaps = Planner().find_gaps(g)
        service_gaps = [gap for gap in gaps if gap.missing == "services"]
        assert len(service_gaps) == 1

    def test_no_gap_when_services_exist(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        svc = Entity.service("test.com", 80)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        gaps = Planner().find_gaps(g)
        service_gaps = [gap for gap in gaps if gap.missing == "services"]
        assert len(service_gaps) == 0


class TestHostWithoutDns:
    def test_detects_gap(self):
        g = KnowledgeGraph()
        g.add_entity(Entity.host("test.com"))
        gaps = Planner().find_gaps(g)
        dns_gaps = [gap for gap in gaps if gap.missing == "dns"]
        assert len(dns_gaps) == 1

    def test_no_gap_when_dns_data_present(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        host.data["dns_records"] = [{"type": "A", "value": "1.2.3.4"}]
        g.add_entity(host)
        gaps = Planner().find_gaps(g)
        dns_gaps = [gap for gap in gaps if gap.missing == "dns"]
        assert len(dns_gaps) == 0

    def test_no_dns_gap_for_ip_targets(self):
        g = KnowledgeGraph()
        host = Entity.host("10.10.10.1")
        host.data["type"] = "ip"
        g.add_entity(host)
        gaps = Planner().find_gaps(g)
        dns_gaps = [gap for gap in gaps if gap.missing == "dns"]
        assert len(dns_gaps) == 0


class TestHttpServiceWithoutTech:
    def test_detects_gap(self):
        g = KnowledgeGraph()
        host = Entity.host("web.com")
        svc = Entity.service("web.com", 80)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        gaps = Planner().find_gaps(g)
        tech_gaps = [gap for gap in gaps if gap.missing == "technology"]
        assert len(tech_gaps) == 1

    def test_no_gap_when_tech_detected(self):
        g = KnowledgeGraph()
        host = Entity.host("web.com")
        svc = Entity.service("web.com", 80)
        tech = Entity.technology("web.com", "nginx")
        g.add_entity(host)
        g.add_entity(svc)
        g.add_entity(tech)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        g.add_relation(Relation(
            source_id=host.id, target_id=tech.id, type=RelationType.RUNS,
        ))
        gaps = Planner().find_gaps(g)
        tech_gaps = [gap for gap in gaps if gap.missing == "technology"]
        assert len(tech_gaps) == 0


class TestEndpointWithoutTesting:
    def test_detects_gap_for_param_endpoint(self):
        g = KnowledgeGraph()
        ep = Entity.endpoint("test.com", "/search")
        ep.data["has_params"] = True
        g.add_entity(ep)
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "vulnerability_testing"]
        assert len(vuln_gaps) == 1

    def test_no_gap_for_static_endpoint(self):
        g = KnowledgeGraph()
        ep = Entity.endpoint("test.com", "/about")
        g.add_entity(ep)
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "vulnerability_testing"]
        assert len(vuln_gaps) == 0


class TestTechnologyWithoutVersion:
    def test_detects_gap(self):
        g = KnowledgeGraph()
        tech = Entity.technology("test.com", "nginx")
        g.add_entity(tech)
        gaps = Planner().find_gaps(g)
        ver_gaps = [gap for gap in gaps if gap.missing == "version"]
        assert len(ver_gaps) == 1

    def test_no_gap_when_version_known(self):
        g = KnowledgeGraph()
        tech = Entity.technology("test.com", "nginx", "1.24")
        g.add_entity(tech)
        gaps = Planner().find_gaps(g)
        ver_gaps = [gap for gap in gaps if gap.missing == "version"]
        assert len(ver_gaps) == 0


class TestLowConfidence:
    def test_detects_low_confidence_host(self):
        g = KnowledgeGraph()
        host = Entity.host("shaky.com")
        host.confidence = 0.3
        g.add_entity(host)
        gaps = Planner().find_gaps(g)
        conf_gaps = [gap for gap in gaps if gap.missing == "confirmation"]
        assert len(conf_gaps) == 1

    def test_no_gap_for_high_confidence(self):
        g = KnowledgeGraph()
        host = Entity.host("solid.com")
        host.confidence = 0.9
        g.add_entity(host)
        gaps = Planner().find_gaps(g)
        conf_gaps = [gap for gap in gaps if gap.missing == "confirmation"]
        assert len(conf_gaps) == 0


class TestPlannerSorting:
    def test_gaps_sorted_by_priority(self):
        g = KnowledgeGraph()
        g.add_entity(Entity.host("test.com"))
        gaps = Planner().find_gaps(g)
        priorities = [gap.priority for gap in gaps]
        assert priorities == sorted(priorities, reverse=True)
