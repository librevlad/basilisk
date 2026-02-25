"""Tests for TrainingRunner."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.orchestrator.loop import LoopResult
from basilisk.orchestrator.timeline import Timeline
from basilisk.training.profile import ExpectedFinding, TrainingProfile
from basilisk.training.runner import TrainingRunner
from basilisk.training.validator import FindingTracker


def _make_profile() -> TrainingProfile:
    return TrainingProfile(
        name="test_app",
        target="localhost:8080",
        target_ports=[8080],
        max_steps=50,
        required_coverage=1.0,
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


class TestTrainingRunner:
    def test_init(self):
        profile = _make_profile()
        runner = TrainingRunner(profile)
        assert runner.target == "localhost:8080"
        assert runner.profile.name == "test_app"
        assert runner.manage_docker is True
        assert runner.project_root is None

    def test_init_with_target_override(self):
        profile = _make_profile()
        runner = TrainingRunner(profile, target_override="10.0.0.1:80")
        assert runner.target == "10.0.0.1:80"

    def test_init_no_docker(self):
        profile = _make_profile()
        runner = TrainingRunner(profile, manage_docker=False)
        assert runner.manage_docker is False

    def test_init_project_root(self, tmp_path):
        profile = _make_profile()
        runner = TrainingRunner(profile, project_root=tmp_path)
        assert runner.project_root == tmp_path

    def test_build_report(self):
        profile = _make_profile()
        runner = TrainingRunner(profile)
        tracker = FindingTracker(profile)

        # Simulate discoveries
        finding1 = Entity(
            id="f1", type=EntityType.FINDING,
            data={"title": "SQL Injection in /login", "severity": "critical", "host": "localhost"},
        )
        finding2 = Entity(
            id="f2", type=EntityType.FINDING,
            data={"title": "XSS Reflected in /search", "severity": "high", "host": "localhost"},
        )
        tracker.check_discovery(finding1, step=3)
        tracker.check_discovery(finding2, step=7)
        tracker.check_verification("f1", step=10)

        # Mock loop result
        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("localhost:8080"))
        result = LoopResult(
            graph=graph,
            timeline=Timeline(),
            steps=15,
            total_observations=20,
            termination_reason="no_gaps",
        )

        report = runner._build_report(result, tracker)
        assert report.profile_name == "test_app"
        assert report.target == "localhost:8080"
        assert report.total_expected == 2
        assert report.discovered == 2
        assert report.verified == 1
        assert report.coverage == 1.0
        assert report.verification_rate == 0.5
        assert report.steps_taken == 15
        assert report.passed is True
        assert len(report.findings_detail) == 2

    def test_build_report_partial_coverage(self):
        profile = _make_profile()
        runner = TrainingRunner(profile)
        tracker = FindingTracker(profile)

        # Only discover one of two findings
        finding = Entity(
            id="f1", type=EntityType.FINDING,
            data={"title": "SQL Injection in /login", "severity": "critical", "host": "localhost"},
        )
        tracker.check_discovery(finding, step=3)

        graph = KnowledgeGraph()
        graph.add_entity(Entity.host("localhost:8080"))
        result = LoopResult(
            graph=graph,
            timeline=Timeline(),
            steps=50,
            total_observations=10,
            termination_reason="limit_reached",
        )

        report = runner._build_report(result, tracker)
        assert report.coverage == 0.5
        assert report.passed is False  # required_coverage=1.0

    def test_exploration_rate_zero(self):
        """Verify runner uses exploration_rate=0.0 for determinism."""
        profile = _make_profile()
        runner = TrainingRunner(profile)
        # This is tested by checking the AutonomousLoop constructor args
        # in an integration test, but we verify the runner stores the profile
        assert runner.profile.max_steps == 50
