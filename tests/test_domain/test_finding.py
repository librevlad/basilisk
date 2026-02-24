"""Tests for domain finding model."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from basilisk.domain.finding import Finding, Proof, ReproductionStep, Severity


class TestFinding:
    def test_info_factory(self):
        f = Finding.info("Server version disclosed")
        assert f.severity == Severity.INFO
        assert f.title == "Server version disclosed"

    def test_low_factory(self):
        f = Finding.low("Missing security header")
        assert f.severity == Severity.LOW

    def test_medium_factory(self):
        f = Finding.medium("Open redirect")
        assert f.severity == Severity.MEDIUM

    def test_high_factory(self):
        proof = Proof(description="Reflected XSS", payload_used="<script>alert(1)</script>")
        f = Finding.high("XSS in /search", proof=proof)
        assert f.severity == Severity.HIGH
        assert f.proof is not None
        assert f.proof.payload_used == "<script>alert(1)</script>"

    def test_critical_factory(self):
        proof = Proof(description="SQL injection", payload_used="' OR 1=1--")
        f = Finding.critical("SQLi in login", proof=proof)
        assert f.severity == Severity.CRITICAL

    def test_immutability(self):
        f = Finding.info("Test")
        with pytest.raises((TypeError, ValidationError)):
            f.title = "Changed"

    def test_high_without_proof_warns(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="basilisk.quality"):
            Finding.high("XSS without proof")
        assert any("no proof description" in r.message for r in caplog.records)

    def test_critical_without_proof_warns(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="basilisk.quality"):
            Finding.critical("RCE without proof")
        assert any("no proof description" in r.message for r in caplog.records)

    def test_high_with_proof_no_warning(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="basilisk.quality"):
            Finding.high("XSS", proof=Proof(description="Confirmed"))
        quality_warnings = [r for r in caplog.records if "no proof description" in r.message]
        assert len(quality_warnings) == 0

    def test_tags_frozenset(self):
        f = Finding.info("Test", tags=frozenset({"web", "xss"}))
        assert "web" in f.tags
        assert isinstance(f.tags, frozenset)

    def test_reproduction_steps(self):
        steps = (
            ReproductionStep(order=1, action="Navigate to /search"),
            ReproductionStep(order=2, action="Enter payload", expected_result="Alert box"),
        )
        f = Finding.medium("XSS", reproduction_steps=steps)
        assert len(f.reproduction_steps) == 2
        assert f.reproduction_steps[0].order == 1

    def test_confidence_bounds(self):
        f = Finding.info("Test", confidence=0.5)
        assert f.confidence == 0.5
        with pytest.raises(ValueError):
            Finding.info("Bad", confidence=1.5)
