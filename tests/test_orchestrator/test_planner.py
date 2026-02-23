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

    def test_gap_always_fires_for_param_endpoint(self):
        """vuln_tested removed — gaps always fire, loop dedup handles the rest."""
        g = KnowledgeGraph()
        ep = Entity.endpoint("test.com", "/search")
        ep.data["has_params"] = True
        g.add_entity(ep)
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "vulnerability_testing"]
        assert len(vuln_gaps) == 1

    def test_multiple_endpoints_same_host_one_gap(self):
        """Multiple endpoints on same host → one gap (plugins scan all endpoints per host)."""
        g = KnowledgeGraph()
        ep1 = Entity.endpoint("test.com", "/search")
        ep1.data["has_params"] = True
        ep2 = Entity.endpoint("test.com", "/login")
        ep2.data["has_params"] = True
        g.add_entity(ep1)
        g.add_entity(ep2)
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "vulnerability_testing"]
        assert len(vuln_gaps) == 1

    def test_endpoints_different_hosts_independent_gaps(self):
        """Endpoints on different hosts → separate gaps."""
        g = KnowledgeGraph()
        ep1 = Entity.endpoint("host1.com", "/search")
        ep1.data["has_params"] = True
        ep2 = Entity.endpoint("host2.com", "/login")
        ep2.data["has_params"] = True
        g.add_entity(ep1)
        g.add_entity(ep2)
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "vulnerability_testing"]
        assert len(vuln_gaps) == 2


class TestHttpHostWithoutVulnTesting:
    def test_detects_gap_when_http_service_exists(self):
        g = KnowledgeGraph()
        host = Entity.host("web.com")
        svc = Entity.service("web.com", 80)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "host_vulnerability_testing"]
        assert len(vuln_gaps) == 1
        assert vuln_gaps[0].priority == 4.5

    def test_no_gap_without_http_service(self):
        g = KnowledgeGraph()
        host = Entity.host("ssh.com")
        svc = Entity.service("ssh.com", 22)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "host_vulnerability_testing"]
        assert len(vuln_gaps) == 0

    def test_no_gap_without_services(self):
        g = KnowledgeGraph()
        g.add_entity(Entity.host("bare.com"))
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "host_vulnerability_testing"]
        assert len(vuln_gaps) == 0

    def test_port_3000_triggers_gap(self):
        g = KnowledgeGraph()
        host = Entity.host("127.0.0.1:3000")
        svc = Entity.service("127.0.0.1:3000", 3000)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "host_vulnerability_testing"]
        assert len(vuln_gaps) == 1

    def test_gap_always_fires_for_http_host(self):
        """host_vuln_tested removed — gap always fires, loop dedup handles the rest."""
        g = KnowledgeGraph()
        host = Entity.host("web.com")
        svc = Entity.service("web.com", 80)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        # Even with findings already present, gap still fires
        finding = Entity(
            id=Entity.make_id(EntityType.FINDING, host="web.com", title="test"),
            type=EntityType.FINDING,
            data={"host": "web.com", "title": "test", "severity": "high"},
        )
        g.add_entity(finding)
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "host_vulnerability_testing"]
        assert len(vuln_gaps) == 1


class TestEndpointScanPath:
    def test_scan_path_endpoint_gets_gap(self):
        """Endpoints with scan_path=True always get vulnerability_testing gap."""
        g = KnowledgeGraph()
        ep = Entity.endpoint("test.com", "/vulnerabilities/upload/")
        ep.data["scan_path"] = True
        g.add_entity(ep)
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "vulnerability_testing"]
        assert len(vuln_gaps) == 1

    def test_scan_path_without_params_gets_gap(self):
        """scan_path=True triggers gap even when has_params=False."""
        g = KnowledgeGraph()
        ep = Entity.endpoint("test.com", "/b2b/v2/orders")
        ep.data["has_params"] = False
        ep.data["scan_path"] = True
        g.add_entity(ep)
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "vulnerability_testing"]
        assert len(vuln_gaps) == 1


class TestUploadEndpointGap:
    def test_upload_endpoint_gets_vuln_testing_gap(self):
        """Endpoints with is_upload=True get vulnerability_testing gap."""
        g = KnowledgeGraph()
        ep = Entity.endpoint("test.com", "/upload")
        ep.data["is_upload"] = True
        g.add_entity(ep)
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "vulnerability_testing"]
        assert len(vuln_gaps) == 1

    def test_plain_endpoint_no_gap(self):
        """Plain endpoints without params/scan_path/upload get no vuln testing gap."""
        g = KnowledgeGraph()
        ep = Entity.endpoint("test.com", "/about")
        g.add_entity(ep)
        gaps = Planner().find_gaps(g)
        vuln_gaps = [gap for gap in gaps if gap.missing == "vulnerability_testing"]
        assert len(vuln_gaps) == 0


class TestCredentialExploitation:
    def test_credential_triggers_gap(self):
        """Credential entities trigger credential_exploitation gap."""
        g = KnowledgeGraph()
        cred = Entity(
            id=Entity.make_id(EntityType.CREDENTIAL, host="test.com", username="admin"),
            type=EntityType.CREDENTIAL,
            data={"host": "test.com", "username": "admin", "password": "pass"},
        )
        g.add_entity(cred)
        gaps = Planner().find_gaps(g)
        cred_gaps = [gap for gap in gaps if gap.missing == "credential_exploitation"]
        assert len(cred_gaps) == 1
        assert cred_gaps[0].priority == 7.5

    def test_no_credentials_no_gap(self):
        """No credentials → no credential_exploitation gap."""
        g = KnowledgeGraph()
        g.add_entity(Entity.host("test.com"))
        gaps = Planner().find_gaps(g)
        cred_gaps = [gap for gap in gaps if gap.missing == "credential_exploitation"]
        assert len(cred_gaps) == 0


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


class TestIsHttpService:
    def test_port_3000_triggers_tech_gap(self):
        g = KnowledgeGraph()
        host = Entity.host("127.0.0.1:3000")
        svc = Entity.service("127.0.0.1:3000", 3000)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        gaps = Planner().find_gaps(g)
        tech_gaps = [gap for gap in gaps if gap.missing == "technology"]
        assert len(tech_gaps) == 1

    def test_port_4280_triggers_tech_gap(self):
        g = KnowledgeGraph()
        host = Entity.host("127.0.0.1:4280")
        svc = Entity.service("127.0.0.1:4280", 4280)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        gaps = Planner().find_gaps(g)
        tech_gaps = [gap for gap in gaps if gap.missing == "technology"]
        assert len(tech_gaps) == 1

    def test_non_http_port_no_tech_gap(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        svc = Entity.service("test.com", 22)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))
        gaps = Planner().find_gaps(g)
        tech_gaps = [gap for gap in gaps if gap.missing == "technology"]
        assert len(tech_gaps) == 0


class TestPlannerSorting:
    def test_gaps_sorted_by_priority(self):
        g = KnowledgeGraph()
        g.add_entity(Entity.host("test.com"))
        gaps = Planner().find_gaps(g)
        priorities = [gap.priority for gap in gaps]
        assert priorities == sorted(priorities, reverse=True)
