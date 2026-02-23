"""Tests for PluginResult → Observation adapter."""

from __future__ import annotations

from basilisk.knowledge.entities import EntityType
from basilisk.knowledge.relations import RelationType
from basilisk.models.result import Finding, PluginResult
from basilisk.observations.adapter import adapt_result


def _make_result(plugin: str = "test_plugin", host: str = "example.com", **data) -> PluginResult:
    return PluginResult.success(plugin, host, data=data)


class TestAdapterHost:
    def test_always_emits_host(self):
        result = _make_result()
        obs = adapt_result(result)
        host_obs = [o for o in obs if o.entity_type == EntityType.HOST]
        assert len(host_obs) >= 1
        assert host_obs[0].key_fields["host"] == "example.com"

    def test_skips_failed_results(self):
        result = PluginResult.fail("test", "example.com", error="timeout")
        obs = adapt_result(result)
        assert len(obs) == 0


class TestAdapterServices:
    def test_open_ports_dict(self):
        result = _make_result(open_ports=[{"port": 80, "protocol": "tcp", "service": "http"}])
        obs = adapt_result(result)
        svc_obs = [o for o in obs if o.entity_type == EntityType.SERVICE]
        assert len(svc_obs) == 1
        assert svc_obs[0].entity_data["port"] == 80
        assert svc_obs[0].relation is not None
        assert svc_obs[0].relation.type == RelationType.EXPOSES

    def test_open_ports_int(self):
        result = _make_result(open_ports=[443])
        obs = adapt_result(result)
        svc_obs = [o for o in obs if o.entity_type == EntityType.SERVICE]
        assert len(svc_obs) == 1
        assert svc_obs[0].entity_data["port"] == 443

    def test_services_list(self):
        result = _make_result(services=[{"port": 22, "protocol": "tcp", "service": "ssh"}])
        obs = adapt_result(result)
        svc_obs = [o for o in obs if o.entity_type == EntityType.SERVICE]
        assert len(svc_obs) == 1

    def test_multiple_ports(self):
        result = _make_result(open_ports=[
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ])
        obs = adapt_result(result)
        svc_obs = [o for o in obs if o.entity_type == EntityType.SERVICE]
        assert len(svc_obs) == 2


class TestAdapterTechnologies:
    def test_technology_dict(self):
        result = _make_result(technologies=[{"name": "nginx", "version": "1.24"}])
        obs = adapt_result(result)
        tech_obs = [o for o in obs if o.entity_type == EntityType.TECHNOLOGY]
        assert len(tech_obs) == 1
        assert tech_obs[0].entity_data["name"] == "nginx"
        assert tech_obs[0].relation.type == RelationType.RUNS

    def test_technology_string(self):
        result = _make_result(technologies=["Apache"])
        obs = adapt_result(result)
        tech_obs = [o for o in obs if o.entity_type == EntityType.TECHNOLOGY]
        assert len(tech_obs) == 1
        assert tech_obs[0].entity_data["name"] == "Apache"

    def test_cms_detection(self):
        result = _make_result(cms=[{"name": "WordPress", "version": "6.4"}])
        obs = adapt_result(result)
        tech_obs = [o for o in obs if o.entity_type == EntityType.TECHNOLOGY]
        assert len(tech_obs) == 1
        assert tech_obs[0].entity_data["is_cms"] is True


class TestAdapterSubdomains:
    def test_subdomain_creates_host(self):
        result = _make_result(subdomains=["sub.example.com"])
        obs = adapt_result(result)
        host_obs = [o for o in obs if o.entity_type == EntityType.HOST]
        # Original host + subdomain
        assert len(host_obs) == 2
        sub_obs = [o for o in host_obs if o.entity_data.get("type") == "subdomain"]
        assert len(sub_obs) == 1
        assert sub_obs[0].entity_data["host"] == "sub.example.com"

    def test_subdomain_parent_of_relation(self):
        result = _make_result(subdomains=["sub.example.com"])
        obs = adapt_result(result)
        sub_obs = [o for o in obs if o.entity_data.get("type") == "subdomain"]
        assert sub_obs[0].relation.type == RelationType.PARENT_OF

    def test_multiple_subdomains(self):
        result = _make_result(subdomains=["a.example.com", "b.example.com", "c.example.com"])
        obs = adapt_result(result)
        sub_obs = [o for o in obs if o.entity_data.get("type") == "subdomain"]
        assert len(sub_obs) == 3


class TestAdapterEndpoints:
    def test_crawled_urls(self):
        result = _make_result(crawled_urls=["https://example.com/api/users"])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 1
        assert ep_obs[0].entity_data["path"] == "/api/users"

    def test_found_paths_dict(self):
        result = _make_result(found_paths=[{"path": "/admin", "status": 200}])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 1
        assert ep_obs[0].entity_data["status"] == 200

    def test_found_paths_string(self):
        result = _make_result(found_paths=["/robots.txt"])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 1

    def test_api_endpoints_dict(self):
        result = _make_result(api_endpoints=[{"path": "/api/v1/users"}])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 1
        assert ep_obs[0].entity_data["is_api"] is True

    def test_api_endpoints_string(self):
        result = _make_result(api_endpoints=["/graphql"])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 1

    def test_internal_links(self):
        result = _make_result(internal_links=["https://example.com/about"])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 1


class TestAdapterCredentials:
    def test_credential_dict(self):
        result = _make_result(credentials=[{"username": "admin", "password": "pass123"}])
        obs = adapt_result(result)
        cred_obs = [o for o in obs if o.entity_type == EntityType.CREDENTIAL]
        assert len(cred_obs) == 1
        assert cred_obs[0].entity_data["username"] == "admin"
        assert cred_obs[0].relation.type == RelationType.ACCESSES

    def test_credential_without_username_skipped(self):
        result = _make_result(credentials=[{"password": "orphan"}])
        obs = adapt_result(result)
        cred_obs = [o for o in obs if o.entity_type == EntityType.CREDENTIAL]
        assert len(cred_obs) == 0


class TestAdapterWaf:
    def test_waf_string(self):
        result = _make_result(waf=["Cloudflare"])
        obs = adapt_result(result)
        tech_obs = [
            o for o in obs
            if o.entity_type == EntityType.TECHNOLOGY and o.entity_data.get("is_waf")
        ]
        assert len(tech_obs) == 1
        assert tech_obs[0].entity_data["name"] == "Cloudflare"

    def test_waf_dict(self):
        result = _make_result(waf=[{"name": "ModSecurity"}])
        obs = adapt_result(result)
        tech_obs = [o for o in obs if o.entity_data.get("is_waf")]
        assert len(tech_obs) == 1


class TestAdapterFindings:
    def test_finding_creates_entity(self):
        result = PluginResult.success(
            "test", "example.com",
            findings=[Finding.high("SQL Injection in /login", evidence="' OR 1=1")],
        )
        obs = adapt_result(result)
        finding_obs = [o for o in obs if o.entity_type == EntityType.FINDING]
        assert len(finding_obs) == 1
        assert finding_obs[0].entity_data["severity"] == "high"
        assert finding_obs[0].entity_data["title"] == "SQL Injection in /login"
        assert finding_obs[0].relation.type == RelationType.RELATES_TO

    def test_multiple_findings(self):
        result = PluginResult.success(
            "test", "example.com",
            findings=[
                Finding.info("Server header exposed"),
                Finding.medium("Missing CSP", evidence="No CSP header"),
                Finding.critical("RCE via SSTI", evidence="{{7*7}}=49"),
            ],
        )
        obs = adapt_result(result)
        finding_obs = [o for o in obs if o.entity_type == EntityType.FINDING]
        assert len(finding_obs) == 3


class TestAdapterSitemapUrls:
    def test_sitemap_urls_create_endpoints(self):
        result = _make_result(urls=[
            "https://example.com/page1",
            "https://example.com/page2",
        ])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 2
        paths = {o.entity_data["path"] for o in ep_obs}
        assert "/page1" in paths
        assert "/page2" in paths

    def test_sitemap_empty_urls_skipped(self):
        result = _make_result(urls=["", None])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 0


class TestAdapterForms:
    def test_forms_create_endpoint_entities(self):
        result = _make_result(forms=[
            {"action": "/login", "method": "POST"},
            {"action": "/register", "method": "POST"},
        ])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 2
        paths = {o.entity_data["path"] for o in ep_obs}
        assert "/login" in paths
        assert "/register" in paths

    def test_forms_skip_empty_action(self):
        result = _make_result(forms=[{"action": "", "method": "POST"}])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 0

    def test_forms_skip_non_dict(self):
        result = _make_result(forms=["not-a-dict"])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 0


class TestAdapterUploadEndpoints:
    def test_upload_endpoint_creates_entity(self):
        result = _make_result(upload_endpoints=["/upload", "/api/files"])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 2
        paths = {o.entity_data["path"] for o in ep_obs}
        assert "/upload" in paths
        assert "/api/files" in paths

    def test_upload_endpoint_has_is_upload_flag(self):
        result = _make_result(upload_endpoints=["/upload"])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 1
        assert ep_obs[0].entity_data.get("is_upload") is True

    def test_upload_endpoint_has_relation(self):
        result = _make_result(upload_endpoints=["/upload"])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert ep_obs[0].relation is not None
        assert ep_obs[0].relation.type == RelationType.HAS_ENDPOINT

    def test_upload_endpoint_skips_empty(self):
        result = _make_result(upload_endpoints=["", None, "/valid"])
        obs = adapt_result(result)
        ep_obs = [o for o in obs if o.entity_type == EntityType.ENDPOINT]
        assert len(ep_obs) == 1
        assert ep_obs[0].entity_data["path"] == "/valid"


class TestAdapterEnrichment:
    def test_ssl_info_enriches_host(self):
        result = _make_result(ssl_info={"protocol": "TLSv1.3", "cipher": "AES256"})
        obs = adapt_result(result)
        host_obs = [o for o in obs if o.entity_type == EntityType.HOST]
        ssl_enriched = [o for o in host_obs if "ssl_info" in o.entity_data]
        assert len(ssl_enriched) == 1

    def test_dns_records_enrich_host(self):
        result = _make_result(records=[{"type": "A", "value": "1.2.3.4"}])
        obs = adapt_result(result)
        host_obs = [o for o in obs if o.entity_type == EntityType.HOST]
        dns_enriched = [o for o in host_obs if "dns_records" in o.entity_data]
        assert len(dns_enriched) == 1
