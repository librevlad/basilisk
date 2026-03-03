"""Tests for the shared execution fingerprint."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.fingerprint import make_execution_fingerprint


class TestMakeExecutionFingerprint:
    def test_host_entity_uses_entity_id(self):
        entity = Entity.host("example.com")
        fp = make_execution_fingerprint("port_scan", entity)
        assert fp == f"port_scan:{entity.id}"

    def test_service_entity_uses_entity_id(self):
        entity = Entity.service("example.com", 443, "tcp")
        fp = make_execution_fingerprint("ssl_check", entity)
        assert fp == f"ssl_check:{entity.id}"

    def test_endpoint_entity_uses_host(self):
        entity = Entity.endpoint("example.com", "/login")
        fp = make_execution_fingerprint("sqli_basic", entity)
        assert fp == "sqli_basic:example.com"

    def test_endpoint_without_host_falls_back_to_id(self):
        entity = Entity(
            id="abc123",
            type=EntityType.ENDPOINT,
            data={"path": "/test"},
        )
        fp = make_execution_fingerprint("xss_basic", entity)
        assert fp == "xss_basic:abc123"

    def test_technology_entity_uses_entity_id(self):
        entity = Entity.technology("example.com", "nginx", "1.21")
        fp = make_execution_fingerprint("version_detect", entity)
        assert fp == f"version_detect:{entity.id}"

    def test_finding_entity_uses_entity_id(self):
        entity = Entity.finding("example.com", "XSS found", "high")
        fp = make_execution_fingerprint("xss_advanced", entity)
        assert fp == f"xss_advanced:{entity.id}"

    def test_different_plugins_different_fingerprints(self):
        entity = Entity.host("example.com")
        fp1 = make_execution_fingerprint("port_scan", entity)
        fp2 = make_execution_fingerprint("dns_enum", entity)
        assert fp1 != fp2

    def test_same_endpoint_host_same_fingerprint(self):
        """Two endpoints on same host → same fingerprint for same plugin."""
        e1 = Entity.endpoint("example.com", "/login")
        e2 = Entity.endpoint("example.com", "/admin")
        fp1 = make_execution_fingerprint("sqli_basic", e1)
        fp2 = make_execution_fingerprint("sqli_basic", e2)
        assert fp1 == fp2
