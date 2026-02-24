"""Tests for the confidence model."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.vulns.registry import ConfidenceThresholds, VulnDefinition, VulnRegistry
from basilisk.verification.confidence import ConfidenceModel, ConfidenceUpdate


def _finding(confidence: float = 0.5) -> Entity:
    e = Entity.finding("example.com", "SQLi in /login")
    e.confidence = confidence
    return e


def _registry() -> VulnRegistry:
    return VulnRegistry([
        VulnDefinition(
            id="sqli_error",
            name="SQL Injection",
            category="sqli",
            confidence_thresholds=ConfidenceThresholds(
                verification_bonus=0.35,
                false_positive_cap=0.25,
                multi_source_bonus=0.2,
            ),
        ),
    ])


class TestConfidenceModel:
    def test_confirmed_verdict(self):
        model = ConfidenceModel()
        entity = _finding(0.5)
        update = model.update_from_verification(entity, "confirmed")
        assert update.new_confidence > update.old_confidence
        assert update.new_confidence == 0.8  # 0.5 + 0.3

    def test_false_positive_verdict(self):
        model = ConfidenceModel()
        entity = _finding(0.5)
        update = model.update_from_verification(entity, "false_positive")
        assert update.new_confidence < update.old_confidence
        assert update.new_confidence == 0.2  # 0.5 - 0.3

    def test_inconclusive_verdict(self):
        model = ConfidenceModel()
        entity = _finding(0.5)
        update = model.update_from_verification(entity, "inconclusive")
        assert update.new_confidence == update.old_confidence

    def test_likely_verdict(self):
        model = ConfidenceModel()
        entity = _finding(0.5)
        update = model.update_from_verification(entity, "likely")
        assert update.new_confidence == 0.6  # 0.5 + 0.1

    def test_registry_thresholds_confirmed(self):
        model = ConfidenceModel(vuln_registry=_registry())
        entity = _finding(0.5)
        update = model.update_from_verification(entity, "confirmed", category="sqli")
        assert update.new_confidence == 0.85  # 0.5 + 0.35

    def test_registry_thresholds_false_positive(self):
        model = ConfidenceModel(vuln_registry=_registry())
        entity = _finding(0.5)
        update = model.update_from_verification(entity, "false_positive", category="sqli")
        assert update.new_confidence == 0.25  # 0.5 - 0.25

    def test_multi_source_bonus(self):
        model = ConfidenceModel()
        entity = _finding(0.5)
        update = model.update_from_verification(entity, "confirmed", source_count=3)
        # 0.5 + 0.3 + min(2*0.05, 0.15) = 0.5 + 0.3 + 0.1 = 0.9
        assert update.new_confidence == 0.9

    def test_confidence_clamped_high(self):
        model = ConfidenceModel()
        entity = _finding(0.9)
        update = model.update_from_verification(entity, "confirmed", source_count=5)
        assert update.new_confidence <= 1.0

    def test_confidence_clamped_low(self):
        model = ConfidenceModel()
        entity = _finding(0.1)
        update = model.update_from_verification(entity, "false_positive")
        assert update.new_confidence >= 0.0

    def test_aggregate_multi_source(self):
        result = ConfidenceModel.aggregate_multi_source([0.5, 0.5])
        assert abs(result - 0.75) < 0.01

    def test_aggregate_multi_source_empty(self):
        assert ConfidenceModel.aggregate_multi_source([]) == 0.0

    def test_apply_updates_graph(self):
        graph = KnowledgeGraph()
        entity = _finding(0.5)
        graph.add_entity(entity)

        update = ConfidenceUpdate(
            entity_id=entity.id,
            old_confidence=0.5,
            new_confidence=0.8,
            reason="test",
        )
        ConfidenceModel.apply(update, graph)

        e = graph.get(entity.id)
        assert e is not None
        assert e.confidence == 0.8
