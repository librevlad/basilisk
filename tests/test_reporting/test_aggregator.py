"""Tests for VulnerabilityAggregator — finding dedup and aggregation."""

from __future__ import annotations

from basilisk.reporting.aggregator import VulnerabilityAggregator


class TestVulnerabilityAggregator:
    """Test finding aggregation logic."""

    def test_empty_input(self):
        result = VulnerabilityAggregator.aggregate([], "example.com")
        assert result == []

    def test_single_finding(self):
        findings = [
            {
                "title": "SQL Injection in /login",
                "severity": "high",
                "host": "example.com",
                "evidence": "1' OR '1'='1 returned 200",
                "tags": ["sqli"],
                "confidence": 0.8,
            },
        ]
        result = VulnerabilityAggregator.aggregate(findings, "example.com")
        assert len(result) == 1
        assert result[0].vuln_type == "sqli"
        assert result[0].severity == "HIGH"
        assert result[0].confidence_aggregate == 0.8

    def test_same_endpoint_same_type_collapse(self):
        """3 SQLi findings on same endpoint -> 1 vulnerability."""
        findings = [
            {
                "title": "SQL Injection in /login",
                "severity": "high",
                "host": "example.com",
                "evidence": "1' OR '1'='1 returned 200",
                "tags": ["sqli"],
                "confidence": 0.7,
            },
            {
                "title": "SQL Injection in /login",
                "severity": "high",
                "host": "example.com",
                "evidence": "1' OR '1'='1 returned 200",
                "tags": ["sqli_blind"],
                "confidence": 0.8,
            },
            {
                "title": "SQL Injection in /login",
                "severity": "critical",
                "host": "example.com",
                "evidence": "1' OR '1'='1 returned 200",
                "tags": ["sqli_time"],
                "confidence": 0.6,
            },
        ]
        result = VulnerabilityAggregator.aggregate(findings, "example.com")
        assert len(result) == 1
        assert result[0].vuln_type == "sqli"
        # Highest severity wins
        assert result[0].severity == "CRITICAL"

    def test_different_endpoints_separate(self):
        """Different endpoints -> different vulnerabilities."""
        findings = [
            {
                "title": "SQL Injection in /login",
                "severity": "high",
                "host": "example.com",
                "evidence": "1' OR '1'='1 on /login",
                "tags": ["sqli"],
                "confidence": 0.8,
            },
            {
                "title": "SQL Injection in /api/users",
                "severity": "high",
                "host": "example.com",
                "evidence": "1' OR '1'='1 on /api/users",
                "tags": ["sqli"],
                "confidence": 0.7,
            },
        ]
        result = VulnerabilityAggregator.aggregate(findings, "example.com")
        assert len(result) == 2

    def test_confidence_aggregation(self):
        """0.7, 0.8 -> 1 - (1-0.7)*(1-0.8) = 1 - 0.3*0.2 = 0.94."""
        findings = [
            {
                "title": "SQL Injection in /login",
                "severity": "high",
                "host": "example.com",
                "evidence": "union select",
                "tags": ["sqli"],
                "confidence": 0.7,
            },
            {
                "title": "SQL Injection in /login",
                "severity": "high",
                "host": "example.com",
                "evidence": "union select",
                "tags": ["sqli_union"],
                "confidence": 0.8,
            },
        ]
        result = VulnerabilityAggregator.aggregate(findings, "example.com")
        assert len(result) == 1
        assert result[0].confidence_aggregate == 0.94

    def test_proofs_deduplicated(self):
        findings = [
            {
                "title": "XSS in /search",
                "severity": "medium",
                "host": "example.com",
                "evidence": "<script>alert(1)</script>",
                "tags": ["xss"],
                "confidence": 0.9,
            },
            {
                "title": "XSS in /search",
                "severity": "medium",
                "host": "example.com",
                "evidence": "<script>alert(1)</script>",
                "tags": ["xss_reflected"],
                "confidence": 0.8,
            },
        ]
        result = VulnerabilityAggregator.aggregate(findings, "example.com")
        assert len(result) == 1
        # Same evidence text should not duplicate
        assert len(result[0].proofs) == 1

    def test_scenarios_collected(self):
        findings = [
            {
                "title": "SQL Injection in /login",
                "severity": "high",
                "host": "example.com",
                "evidence": "test",
                "tags": ["sqli_basic"],
                "confidence": 0.7,
            },
            {
                "title": "SQL Injection in /login",
                "severity": "high",
                "host": "example.com",
                "evidence": "test",
                "tags": ["sqli_blind"],
                "confidence": 0.6,
            },
        ]
        result = VulnerabilityAggregator.aggregate(findings, "example.com")
        assert len(result) == 1
        assert "sqli_basic" in result[0].scenarios
        assert "sqli_blind" in result[0].scenarios


class TestExtractVulnType:
    """Test vuln type extraction from tags/title."""

    def test_sqli_from_tags(self):
        f = {"tags": ["sqli"], "title": ""}
        assert VulnerabilityAggregator._extract_vuln_type(f) == "sqli"

    def test_xss_from_title(self):
        f = {"tags": [], "title": "Cross-Site Scripting in /search"}
        assert VulnerabilityAggregator._extract_vuln_type(f) == "xss"

    def test_unknown_type(self):
        f = {"tags": [], "title": "Something unusual"}
        assert VulnerabilityAggregator._extract_vuln_type(f) == "unknown"

    def test_ssrf_from_title(self):
        f = {"tags": [], "title": "Server-Side Request Forgery"}
        assert VulnerabilityAggregator._extract_vuln_type(f) == "ssrf"

    def test_cors_from_tags(self):
        f = {"tags": ["cors"], "title": ""}
        assert VulnerabilityAggregator._extract_vuln_type(f) == "cors"


class TestNormalizeProof:
    """Test proof normalization for stable hashing."""

    def test_empty(self):
        assert VulnerabilityAggregator._normalize_proof("") == ""

    def test_strips_session_id(self):
        proof = "response with session_id=abc123def"
        normalized = VulnerabilityAggregator._normalize_proof(proof)
        assert "abc123def" not in normalized

    def test_strips_token(self):
        proof = "token=xyz789 was leaked"
        normalized = VulnerabilityAggregator._normalize_proof(proof)
        assert "xyz789" not in normalized


class TestIdentityHash:
    """Test deterministic identity hashing."""

    def test_deterministic(self):
        h1 = VulnerabilityAggregator._identity_hash("a.com", "/login", "sqli", "proof")
        h2 = VulnerabilityAggregator._identity_hash("a.com", "/login", "sqli", "proof")
        assert h1 == h2

    def test_different_inputs(self):
        h1 = VulnerabilityAggregator._identity_hash("a.com", "/login", "sqli", "proof")
        h2 = VulnerabilityAggregator._identity_hash("a.com", "/api", "sqli", "proof")
        assert h1 != h2

    def test_length(self):
        h = VulnerabilityAggregator._identity_hash("a", "b", "c", "d")
        assert len(h) == 16
