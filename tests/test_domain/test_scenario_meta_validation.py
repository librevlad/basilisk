"""Tests for ScenarioMeta knowledge ref validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from basilisk.domain.scenario import ScenarioMeta


class TestKnowledgeRefValidation:
    def test_valid_produces_knowledge(self):
        meta = ScenarioMeta(
            name="test", display_name="Test", category="scanning",
            produces_knowledge=["Host", "Service", "Finding", "Vulnerability"],
        )
        assert meta.produces_knowledge == ["Host", "Service", "Finding", "Vulnerability"]

    def test_valid_requires_knowledge_with_qualifier(self):
        meta = ScenarioMeta(
            name="test", display_name="Test", category="scanning",
            requires_knowledge=["Service:http", "Host", "Endpoint:params"],
        )
        assert meta.requires_knowledge == ["Service:http", "Host", "Endpoint:params"]

    def test_invalid_produces_knowledge_rejected(self):
        with pytest.raises(ValidationError, match="Invalid knowledge ref 'FooBar'"):
            ScenarioMeta(
                name="test", display_name="Test", category="scanning",
                produces_knowledge=["FooBar"],
            )

    def test_invalid_requires_knowledge_rejected(self):
        with pytest.raises(ValidationError, match="Invalid knowledge ref 'Unknown:xyz'"):
            ScenarioMeta(
                name="test", display_name="Test", category="scanning",
                requires_knowledge=["Unknown:xyz"],
            )

    def test_empty_knowledge_lists_ok(self):
        meta = ScenarioMeta(
            name="test", display_name="Test", category="scanning",
            produces_knowledge=[], requires_knowledge=[],
        )
        assert meta.produces_knowledge == []
        assert meta.requires_knowledge == []

    def test_all_valid_prefixes(self):
        all_prefixes = [
            "Host", "Service", "Endpoint", "Technology", "Credential",
            "Finding", "Vulnerability", "Container", "Image",
        ]
        meta = ScenarioMeta(
            name="test", display_name="Test", category="scanning",
            produces_knowledge=all_prefixes,
        )
        assert len(meta.produces_knowledge) == 9

    def test_qualified_produces_knowledge(self):
        meta = ScenarioMeta(
            name="test", display_name="Test", category="scanning",
            produces_knowledge=["Host:ssl_data", "Technology:cms"],
        )
        assert meta.produces_knowledge == ["Host:ssl_data", "Technology:cms"]
