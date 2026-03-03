"""Tests for canonical vulnerability identity."""

from __future__ import annotations

from basilisk.knowledge.identity import vulnerability_id


class TestVulnerabilityId:
    """Test vulnerability_id() canonical hashing."""

    def test_deterministic(self):
        id1 = vulnerability_id("example.com", "/login", "sqli", "1=1")
        id2 = vulnerability_id("example.com", "/login", "sqli", "1=1")
        assert id1 == id2
        assert len(id1) == 16

    def test_same_id_different_case(self):
        id1 = vulnerability_id("EXAMPLE.COM", "/login", "sqli", "1=1")
        id2 = vulnerability_id("example.com", "/login", "sqli", "1=1")
        assert id1 == id2

    def test_same_id_with_protocol_prefix(self):
        id1 = vulnerability_id("https://example.com/", "/login", "sqli", "1=1")
        id2 = vulnerability_id("example.com", "/login", "sqli", "1=1")
        assert id1 == id2

    def test_different_vuln_type_different_id(self):
        id1 = vulnerability_id("example.com", "/login", "sqli", "1=1")
        id2 = vulnerability_id("example.com", "/login", "xss", "1=1")
        assert id1 != id2

    def test_different_surface_different_id(self):
        id1 = vulnerability_id("example.com", "/login", "sqli", "1=1")
        id2 = vulnerability_id("example.com", "/admin", "sqli", "1=1")
        assert id1 != id2

    def test_path_normalization(self):
        id1 = vulnerability_id("example.com", "/login?user=x", "sqli", "1=1")
        id2 = vulnerability_id("example.com", "/login", "sqli", "1=1")
        assert id1 == id2

    def test_non_path_surface_lowercased(self):
        id1 = vulnerability_id("example.com", "login-form", "sqli", "1=1")
        id2 = vulnerability_id("example.com", "LOGIN-FORM", "sqli", "1=1")
        assert id1 == id2

    def test_proof_key_matters(self):
        id1 = vulnerability_id("example.com", "/login", "sqli", "proof_a")
        id2 = vulnerability_id("example.com", "/login", "sqli", "proof_b")
        assert id1 != id2
