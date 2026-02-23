"""Tests for campaign memory models."""

from __future__ import annotations

from datetime import UTC, datetime

from basilisk.campaign.models import (
    PluginEfficacy,
    ServiceRecord,
    TargetProfile,
    TechFingerprint,
    TechRecord,
    TechStackRecord,
)


class TestServiceRecord:
    def test_defaults(self):
        s = ServiceRecord(port=443)
        assert s.port == 443
        assert s.protocol == "tcp"
        assert s.service == ""

    def test_full(self):
        s = ServiceRecord(port=22, protocol="tcp", service="ssh")
        assert s.service == "ssh"


class TestTechRecord:
    def test_defaults(self):
        t = TechRecord(name="nginx")
        assert t.name == "nginx"
        assert t.version == ""
        assert t.is_cms is False
        assert t.is_waf is False

    def test_cms(self):
        t = TechRecord(name="wordpress", is_cms=True)
        assert t.is_cms is True


class TestTargetProfile:
    def test_defaults(self):
        p = TargetProfile(host="example.com")
        assert p.host == "example.com"
        assert p.audit_count == 1
        assert p.known_services == []
        assert p.known_technologies == []
        assert p.known_endpoints_count == 0
        assert p.known_findings_count == 0
        assert p.finding_severities == {}

    def test_with_services(self):
        p = TargetProfile(
            host="example.com",
            known_services=[
                ServiceRecord(port=80),
                ServiceRecord(port=443, service="https"),
            ],
        )
        assert len(p.known_services) == 2

    def test_serialization_roundtrip(self):
        p = TargetProfile(
            host="test.com",
            audit_count=3,
            known_services=[ServiceRecord(port=80)],
            known_technologies=[TechRecord(name="nginx", version="1.24")],
            finding_severities={"HIGH": 2, "CRITICAL": 1},
        )
        data = p.model_dump(mode="json")
        restored = TargetProfile.model_validate(data)
        assert restored.host == "test.com"
        assert restored.audit_count == 3
        assert len(restored.known_services) == 1
        assert restored.known_technologies[0].name == "nginx"
        assert restored.finding_severities["HIGH"] == 2


class TestTechStackRecord:
    def test_success_rate_zero(self):
        ts = TechStackRecord()
        assert ts.success_rate == 0.0

    def test_success_rate(self):
        ts = TechStackRecord(runs=10, successes=7)
        assert ts.success_rate == 0.7


class TestPluginEfficacy:
    def test_defaults(self):
        e = PluginEfficacy(plugin_name="port_scan")
        assert e.total_runs == 0
        assert e.success_rate == 0.0

    def test_success_rate(self):
        e = PluginEfficacy(plugin_name="port_scan", total_runs=20, total_successes=15)
        assert e.success_rate == 0.75

    def test_tech_stack_key(self):
        e = PluginEfficacy(plugin_name="test")
        assert e.tech_stack_key(["Nginx", "PHP"]) == "nginx,php"
        assert e.tech_stack_key(["PHP", "nginx"]) == "nginx,php"
        assert e.tech_stack_key([]) == ""

    def test_tech_stack_key_filters_empty(self):
        e = PluginEfficacy(plugin_name="test")
        assert e.tech_stack_key(["nginx", "", "php"]) == "nginx,php"


class TestTechFingerprint:
    def test_defaults(self):
        fp = TechFingerprint(base_domain="example.com")
        assert fp.technologies == []
        assert fp.observation_count == 1

    def test_with_techs(self):
        fp = TechFingerprint(
            base_domain="example.com",
            technologies=["nginx", "php", "wordpress"],
            observation_count=3,
            last_seen=datetime(2025, 1, 1, tzinfo=UTC),
        )
        assert len(fp.technologies) == 3
        assert fp.observation_count == 3
