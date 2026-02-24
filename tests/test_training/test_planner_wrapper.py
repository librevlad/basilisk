"""Tests for TrainingPlanner wrapper."""

from __future__ import annotations

from unittest.mock import MagicMock

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.orchestrator.planner import KnowledgeGap
from basilisk.training.planner_wrapper import TrainingPlanner
from basilisk.training.profile import ExpectedFinding, TrainingProfile
from basilisk.training.validator import FindingTracker


def _make_profile() -> TrainingProfile:
    return TrainingProfile(
        name="test",
        target="localhost",
        expected_findings=[
            ExpectedFinding(
                title="SQL Injection",
                severity="critical",
                category="sqli",
                plugin_hints=["sqli_basic"],
            ),
            ExpectedFinding(
                title="XSS Reflected",
                severity="high",
                category="xss",
                plugin_hints=["xss_basic"],
            ),
        ],
    )


class TestTrainingPlanner:
    def test_delegates_to_real_planner(self):
        profile = _make_profile()
        tracker = FindingTracker(profile)

        real_planner = MagicMock()
        host = Entity.host("localhost")
        gap = KnowledgeGap(entity=host, missing="services", priority=10.0, description="test")
        real_planner.find_gaps.return_value = [gap]

        wrapper = TrainingPlanner(real_planner, tracker, profile)
        graph = KnowledgeGraph()
        graph.add_entity(host)

        gaps = wrapper.find_gaps(graph)
        real_planner.find_gaps.assert_called_once_with(graph)
        # Should contain the original gap plus injected training gaps
        assert any(g.missing == "services" for g in gaps)

    def test_injects_gaps_for_undiscovered_findings(self):
        profile = _make_profile()
        tracker = FindingTracker(profile)

        real_planner = MagicMock()
        real_planner.find_gaps.return_value = []

        wrapper = TrainingPlanner(real_planner, tracker, profile)
        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("localhost"))

        gaps = wrapper.find_gaps(graph)
        # Should have injected gaps for both undiscovered findings
        training_gaps = [g for g in gaps if "Training:" in g.description]
        assert len(training_gaps) >= 2
        assert all(g.priority == 12.0 for g in training_gaps)

    def test_stops_injecting_when_discovered(self):
        profile = _make_profile()
        tracker = FindingTracker(profile)

        # Simulate both findings discovered
        finding1 = Entity(
            id="f1", type=EntityType.FINDING,
            data={"title": "SQL Injection in /login", "severity": "critical", "host": "localhost"},
        )
        finding2 = Entity(
            id="f2", type=EntityType.FINDING,
            data={"title": "XSS Reflected in /search", "severity": "high", "host": "localhost"},
        )

        real_planner = MagicMock()
        real_planner.find_gaps.return_value = []

        wrapper = TrainingPlanner(real_planner, tracker, profile)
        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("localhost"))
        graph.add_entity(finding1)
        graph.add_entity(finding2)

        gaps = wrapper.find_gaps(graph)
        training_gaps = [g for g in gaps if "Training:" in g.description]
        assert len(training_gaps) == 0

    def test_boosts_verification_priority(self):
        profile = _make_profile()
        tracker = FindingTracker(profile)

        # Mark first finding as discovered but not verified
        finding = Entity(
            id="f1", type=EntityType.FINDING,
            data={"title": "SQL Injection", "severity": "critical", "host": "localhost"},
        )

        real_planner = MagicMock()
        verification_gap = KnowledgeGap(
            entity=finding,
            missing="finding_verification",
            priority=6.0,
            description="needs verification",
        )
        real_planner.find_gaps.return_value = [verification_gap]

        wrapper = TrainingPlanner(real_planner, tracker, profile)
        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("localhost"))
        graph.add_entity(finding)

        gaps = wrapper.find_gaps(graph)
        # The verification gap should have boosted priority
        verif_gaps = [g for g in gaps if g.missing == "finding_verification"]
        assert len(verif_gaps) == 1
        assert verif_gaps[0].priority == 15.0

    def test_no_host_entity_no_injection(self):
        profile = _make_profile()
        tracker = FindingTracker(profile)

        real_planner = MagicMock()
        real_planner.find_gaps.return_value = []

        wrapper = TrainingPlanner(real_planner, tracker, profile)
        graph = KnowledgeGraph()  # empty graph — no hosts

        gaps = wrapper.find_gaps(graph)
        assert len(gaps) == 0
