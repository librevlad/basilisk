"""Tests for knowledge graph entities."""

from __future__ import annotations

from datetime import datetime

from basilisk.knowledge.entities import Entity, EntityType


class TestEntityMakeId:
    def test_deterministic(self):
        id1 = Entity.make_id(EntityType.HOST, host="example.com")
        id2 = Entity.make_id(EntityType.HOST, host="example.com")
        assert id1 == id2

    def test_different_for_different_inputs(self):
        id1 = Entity.make_id(EntityType.HOST, host="a.com")
        id2 = Entity.make_id(EntityType.HOST, host="b.com")
        assert id1 != id2

    def test_different_types_different_ids(self):
        id1 = Entity.make_id(EntityType.HOST, host="example.com")
        id2 = Entity.make_id(EntityType.SERVICE, host="example.com")
        assert id1 != id2

    def test_key_order_irrelevant(self):
        id1 = Entity.make_id(EntityType.SERVICE, host="x.com", port="80")
        id2 = Entity.make_id(EntityType.SERVICE, port="80", host="x.com")
        assert id1 == id2

    def test_length_is_16(self):
        eid = Entity.make_id(EntityType.HOST, host="test.com")
        assert len(eid) == 16

    def test_hex_characters(self):
        eid = Entity.make_id(EntityType.HOST, host="hex.com")
        assert all(c in "0123456789abcdef" for c in eid)


class TestEntityFactory:
    def test_host_factory(self):
        entity = Entity.host("example.com")
        assert entity.type == EntityType.HOST
        assert entity.data["host"] == "example.com"
        assert entity.confidence == 1.0
        assert entity.observation_count == 1

    def test_service_factory(self):
        entity = Entity.service("example.com", 443, "https")
        assert entity.type == EntityType.SERVICE
        assert entity.data["port"] == 443
        assert entity.data["protocol"] == "https"

    def test_endpoint_factory(self):
        entity = Entity.endpoint("example.com", "/api/users")
        assert entity.type == EntityType.ENDPOINT
        assert entity.data["path"] == "/api/users"

    def test_technology_factory(self):
        entity = Entity.technology("example.com", "nginx", "1.24")
        assert entity.type == EntityType.TECHNOLOGY
        assert entity.data["name"] == "nginx"
        assert entity.data["version"] == "1.24"

    def test_credential_factory(self):
        entity = Entity.credential("example.com", "admin", "password123")
        assert entity.type == EntityType.CREDENTIAL
        assert entity.data["username"] == "admin"

    def test_finding_factory(self):
        entity = Entity.finding("example.com", "XSS in login", severity="high")
        assert entity.type == EntityType.FINDING
        assert entity.data["severity"] == "high"

    def test_vulnerability_factory(self):
        entity = Entity.vulnerability("example.com", "CVE-2024-1234")
        assert entity.type == EntityType.VULNERABILITY
        assert entity.data["name"] == "CVE-2024-1234"

    def test_timestamps_set(self):
        entity = Entity.host("time.com")
        assert isinstance(entity.first_seen, datetime)
        assert isinstance(entity.last_seen, datetime)
