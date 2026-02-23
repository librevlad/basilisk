"""Tests for capability selector."""

from __future__ import annotations

from basilisk.capabilities.capability import Capability
from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.orchestrator.planner import KnowledgeGap
from basilisk.orchestrator.selector import Selector
from basilisk.scoring.scorer import ScoredCapability


def _cap(
    name: str = "test",
    requires: list[str] | None = None,
    produces: list[str] | None = None,
) -> Capability:
    return Capability(
        name=name,
        plugin_name=name,
        category="recon",
        requires_knowledge=requires or ["Host"],
        produces_knowledge=produces or ["Finding"],
        cost_score=2.0,
        noise_score=2.0,
    )


def _gap(entity: Entity, missing: str = "services") -> KnowledgeGap:
    return KnowledgeGap(entity=entity, missing=missing, priority=5.0, description="test gap")


class TestSelectorMatch:
    def test_matches_service_producing_cap_to_service_gap(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        g.add_entity(host)

        selector = Selector({"port_scan": _cap("port_scan", produces=["Service"])})
        gaps = [_gap(host, "services")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 1
        assert candidates[0][0].name == "port_scan"

    def test_no_match_when_produces_mismatch(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        g.add_entity(host)

        selector = Selector({"xss": _cap("xss", produces=["Finding:xss"])})
        gaps = [_gap(host, "services")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 0

    def test_match_requires_http_service(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        svc = Entity.service("test.com", 80)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))

        selector = Selector({
            "tech": _cap("tech", requires=["Host", "Service:http"], produces=["Technology"]),
        })
        gaps = [_gap(host, "technology")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 1

    def test_no_match_when_requirements_unmet(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        g.add_entity(host)

        selector = Selector({
            "tech": _cap("tech", requires=["Host", "Service:http"], produces=["Technology"]),
        })
        gaps = [_gap(host, "technology")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 0

    def test_dedup_candidates(self):
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        g.add_entity(host)

        selector = Selector({"scan": _cap("scan", produces=["Service"])})
        gaps = [_gap(host, "services"), _gap(host, "services")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 1


class TestHostVulnGapMatching:
    def test_host_vuln_gap_matches_host_plugins(self):
        """host_vulnerability_testing gap matches plugins producing Finding."""
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        svc = Entity.service("test.com", 80)
        g.add_entity(host)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))

        selector = Selector({
            "jwt_attack": _cap(
                "jwt_attack",
                requires=["Host", "Service:http"],
                produces=["Finding", "Vulnerability"],
            ),
            "git_exposure": _cap(
                "git_exposure",
                requires=["Host", "Service:http"],
                produces=["Finding"],
            ),
            "port_scan": _cap(
                "port_scan",
                requires=["Host"],
                produces=["Service"],
            ),
        })
        gaps = [_gap(host, "host_vulnerability_testing")]
        candidates = selector.match(gaps, g)
        names = [c[0].name for c in candidates]
        assert "jwt_attack" in names
        assert "git_exposure" in names
        # port_scan produces Service, not Finding — should NOT match
        assert "port_scan" not in names

    def test_host_vuln_gap_requires_http_service(self):
        """host_vulnerability_testing caps with Service:http require HTTP service."""
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        g.add_entity(host)
        # No service → requirements not met

        selector = Selector({
            "jwt_attack": _cap(
                "jwt_attack",
                requires=["Host", "Service:http"],
                produces=["Finding"],
            ),
        })
        gaps = [_gap(host, "host_vulnerability_testing")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 0


class TestSelectorIpFiltering:
    def test_match_skips_domain_only_for_ip(self):
        g = KnowledgeGraph()
        host = Entity.host("127.0.0.1")
        host.data["type"] = "ip"
        g.add_entity(host)

        selector = Selector({
            "dns_enum": _cap("dns_enum", produces=["Host:dns_data"]),
            "port_scan": _cap("port_scan", produces=["Service"]),
        })
        gaps = [_gap(host, "services"), _gap(host, "dns")]
        candidates = selector.match(gaps, g)
        names = [c[0].name for c in candidates]
        assert "port_scan" in names
        assert "dns_enum" not in names

    def test_match_skips_subdomain_prefix_for_ip(self):
        g = KnowledgeGraph()
        host = Entity.host("192.168.1.1")
        g.add_entity(host)

        selector = Selector({
            "subdomain_bruteforce": _cap("subdomain_bruteforce", produces=["Host:dns_data"]),
            "http_headers": _cap("http_headers", requires=["Host"], produces=["Finding"]),
        })
        gaps = [_gap(host, "dns"), _gap(host, "vulnerability_testing")]
        candidates = selector.match(gaps, g)
        names = [c[0].name for c in candidates]
        assert "subdomain_bruteforce" not in names
        assert "http_headers" in names

    def test_match_skips_whois_for_localhost(self):
        g = KnowledgeGraph()
        host = Entity.host("localhost")
        g.add_entity(host)

        selector = Selector({
            "whois": _cap("whois", produces=["Host:dns_data"]),
        })
        gaps = [_gap(host, "dns")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 0

    def test_match_keeps_domain_only_for_domain(self):
        g = KnowledgeGraph()
        host = Entity.host("example.com")
        g.add_entity(host)

        selector = Selector({
            "dns_enum": _cap("dns_enum", produces=["Host:dns_data"]),
            "port_scan": _cap("port_scan", produces=["Service"]),
        })
        gaps = [_gap(host, "services"), _gap(host, "dns")]
        candidates = selector.match(gaps, g)
        names = [c[0].name for c in candidates]
        assert "dns_enum" in names
        assert "port_scan" in names


class TestSelectorPick:
    def test_pick_respects_budget(self):
        host = Entity.host("test.com")
        scored = [
            ScoredCapability(capability=_cap(f"c{i}"), target_entity=host, score=10 - i, reason="")
            for i in range(10)
        ]
        chosen = Selector.pick(scored, budget=3)
        assert len(chosen) == 3

    def test_pick_dedup_plugin_entity(self):
        host = Entity.host("test.com")
        cap = _cap("scan")
        scored = [
            ScoredCapability(capability=cap, target_entity=host, score=10, reason=""),
            ScoredCapability(capability=cap, target_entity=host, score=8, reason=""),
        ]
        chosen = Selector.pick(scored, budget=5)
        assert len(chosen) == 1

    def test_pick_allows_different_targets(self):
        h1 = Entity.host("a.com")
        h2 = Entity.host("b.com")
        cap = _cap("scan")
        scored = [
            ScoredCapability(capability=cap, target_entity=h1, score=10, reason=""),
            ScoredCapability(capability=cap, target_entity=h2, score=8, reason=""),
        ]
        chosen = Selector.pick(scored, budget=5)
        assert len(chosen) == 2

    def test_pick_empty(self):
        chosen = Selector.pick([], budget=5)
        assert chosen == []


class TestScanPathEndpoints:
    def test_scan_path_satisfies_endpoint_params(self):
        """scan_path=True endpoints satisfy Endpoint:params requirement."""
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        endpoint = Entity.endpoint("test.com", "/api/upload", has_params=False, scan_path=True)
        svc = Entity.service("test.com", 80)
        g.add_entity(host)
        g.add_entity(endpoint)
        g.add_entity(svc)
        g.add_relation(Relation(
            source_id=host.id, target_id=endpoint.id, type=RelationType.HAS_ENDPOINT,
        ))
        g.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))

        selector = Selector({
            "sqli_basic": _cap(
                "sqli_basic", requires=["Endpoint:params"], produces=["Vulnerability"],
            ),
        })
        gaps = [_gap(endpoint, "vulnerability_testing")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 1
        assert candidates[0][0].name == "sqli_basic"

    def test_no_scan_path_no_params_rejects_endpoint_params(self):
        """Endpoints without scan_path and has_params are rejected for Endpoint:params."""
        g = KnowledgeGraph()
        host = Entity.host("test.com")
        endpoint = Entity.endpoint("test.com", "/static/page", has_params=False)
        g.add_entity(host)
        g.add_entity(endpoint)
        g.add_relation(Relation(
            source_id=host.id, target_id=endpoint.id, type=RelationType.HAS_ENDPOINT,
        ))

        selector = Selector({
            "sqli_basic": _cap(
                "sqli_basic", requires=["Endpoint:params"], produces=["Vulnerability"],
            ),
        })
        gaps = [_gap(endpoint, "vulnerability_testing")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 0


class TestWafSubtype:
    def test_waf_bypass_matches_waf_entity(self):
        """waf_bypass matches Technology entity with is_waf=True."""
        g = KnowledgeGraph()
        tech = Entity.technology("test.com", "Cloudflare")
        tech.data["is_waf"] = True
        g.add_entity(tech)

        selector = Selector({
            "waf_bypass": _cap("waf_bypass", requires=["Technology:waf"], produces=["Finding"]),
        })
        gaps = [_gap(tech, "version")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 1

    def test_waf_bypass_rejects_non_waf_tech(self):
        """waf_bypass does NOT match non-WAF Technology entities."""
        g = KnowledgeGraph()
        tech = Entity.technology("test.com", "nginx")
        g.add_entity(tech)

        selector = Selector({
            "waf_bypass": _cap("waf_bypass", requires=["Technology:waf"], produces=["Finding"]),
        })
        gaps = [_gap(tech, "version")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 0

    def test_credential_exploitation_gap(self):
        """Credential entities match credential_reuse through credential_exploitation gap."""
        g = KnowledgeGraph()
        cred = Entity(
            id=Entity.make_id(EntityType.CREDENTIAL, host="test.com", username="admin"),
            type=EntityType.CREDENTIAL,
            data={"host": "test.com", "username": "admin"},
        )
        g.add_entity(cred)

        selector = Selector({
            "credential_reuse": _cap(
                "credential_reuse", requires=["Credential"], produces=["Credential"],
            ),
        })
        gaps = [_gap(cred, "credential_exploitation")]
        candidates = selector.match(gaps, g)
        assert len(candidates) == 1


class TestMatchesServiceType:
    def test_port_3000_recognized_as_http(self):
        from basilisk.orchestrator.selector import _matches_service_type

        svc = Entity.service("127.0.0.1:3000", 3000)
        assert _matches_service_type(svc, "http") is True

    def test_port_4280_recognized_as_http(self):
        from basilisk.orchestrator.selector import _matches_service_type

        svc = Entity.service("127.0.0.1:4280", 4280)
        assert _matches_service_type(svc, "http") is True

    def test_port_5000_recognized_as_http(self):
        from basilisk.orchestrator.selector import _matches_service_type

        svc = Entity.service("127.0.0.1:5000", 5000)
        assert _matches_service_type(svc, "http") is True

    def test_port_22_not_http(self):
        from basilisk.orchestrator.selector import _matches_service_type

        svc = Entity.service("test.com", 22)
        assert _matches_service_type(svc, "http") is False

    def test_service_name_http_matches(self):
        from basilisk.orchestrator.selector import _matches_service_type

        svc = Entity.service("test.com", 9999)
        svc.data["service"] = "http-proxy"
        assert _matches_service_type(svc, "http") is True
