"""Tests for FindingTracker and ValidationReport."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.training.profile import ExpectedFinding, TrainingProfile
from basilisk.training.validator import FindingTracker, ValidationReport


def _make_profile(*findings: tuple[str, str]) -> TrainingProfile:
    """Helper: create a profile with given (title, severity) pairs."""
    return TrainingProfile(
        name="test",
        target="localhost",
        expected_findings=[
            ExpectedFinding(title=t, severity=s) for t, s in findings
        ],
    )


def _make_finding_entity(title: str, severity: str, entity_id: str = "") -> Entity:
    """Helper: create a FINDING entity."""
    eid = entity_id or Entity.make_id(EntityType.FINDING, host="localhost", title=title)
    return Entity(
        id=eid,
        type=EntityType.FINDING,
        data={"host": "localhost", "title": title, "severity": severity},
    )


class TestFindingTracker:
    def test_discovery_matches_case_insensitive(self):
        profile = _make_profile(("SQL Injection", "critical"))
        tracker = FindingTracker(profile)

        entity = _make_finding_entity("Found SQL Injection in /login", "critical")
        assert tracker.check_discovery(entity, step=3) is True
        assert tracker.tracked[0].discovered is True
        assert tracker.tracked[0].discovery_step == 3
        assert tracker.tracked[0].matched_entity_id == entity.id

    def test_discovery_requires_severity_match(self):
        profile = _make_profile(("SQL Injection", "critical"))
        tracker = FindingTracker(profile)

        entity = _make_finding_entity("SQL Injection", "medium")
        assert tracker.check_discovery(entity, step=1) is False
        assert tracker.tracked[0].discovered is False

    def test_no_double_match(self):
        profile = _make_profile(("SQL Injection", "critical"))
        tracker = FindingTracker(profile)

        entity1 = _make_finding_entity("SQL Injection in /search", "critical", "id1")
        entity2 = _make_finding_entity("SQL Injection in /login", "critical", "id2")

        assert tracker.check_discovery(entity1, step=1) is True
        assert tracker.check_discovery(entity2, step=2) is False
        assert tracker.tracked[0].matched_entity_id == "id1"

    def test_check_verification(self):
        profile = _make_profile(("XSS", "high"))
        tracker = FindingTracker(profile)

        entity = _make_finding_entity("XSS Reflected in /page", "high", "xss_id")
        tracker.check_discovery(entity, step=1)
        assert tracker.check_verification("xss_id", step=5) is True
        assert tracker.tracked[0].verified is True
        assert tracker.tracked[0].verification_step == 5

    def test_verification_requires_discovery(self):
        profile = _make_profile(("XSS", "high"))
        tracker = FindingTracker(profile)
        assert tracker.check_verification("unknown_id", step=5) is False

    def test_verification_no_double(self):
        profile = _make_profile(("XSS", "high"))
        tracker = FindingTracker(profile)

        entity = _make_finding_entity("XSS Reflected", "high", "xss_id")
        tracker.check_discovery(entity, step=1)
        assert tracker.check_verification("xss_id", step=2) is True
        assert tracker.check_verification("xss_id", step=3) is False

    def test_coverage_empty(self):
        profile = TrainingProfile(name="x", target="x", expected_findings=[])
        tracker = FindingTracker(profile)
        assert tracker.coverage == 1.0

    def test_coverage_partial(self):
        profile = _make_profile(
            ("SQLi", "critical"), ("XSS", "high"), ("CSRF", "medium"),
        )
        tracker = FindingTracker(profile)

        entity = _make_finding_entity("SQLi in /search", "critical")
        tracker.check_discovery(entity, step=1)
        assert abs(tracker.coverage - 1 / 3) < 0.01

    def test_coverage_full(self):
        profile = _make_profile(("SQLi", "critical"), ("XSS", "high"))
        tracker = FindingTracker(profile)

        tracker.check_discovery(_make_finding_entity("SQLi found", "critical", "a"), step=1)
        tracker.check_discovery(_make_finding_entity("XSS found", "high", "b"), step=2)
        assert tracker.coverage == 1.0

    def test_verification_rate(self):
        profile = _make_profile(("SQLi", "critical"), ("XSS", "high"))
        tracker = FindingTracker(profile)

        tracker.check_discovery(_make_finding_entity("SQLi found", "critical", "a"), step=1)
        tracker.check_discovery(_make_finding_entity("XSS found", "high", "b"), step=2)
        tracker.check_verification("a", step=3)

        assert tracker.verification_rate == 0.5

    def test_verification_rate_no_discoveries(self):
        profile = _make_profile(("SQLi", "critical"))
        tracker = FindingTracker(profile)
        assert tracker.verification_rate == 0.0

    def test_undiscovered(self):
        profile = _make_profile(("SQLi", "critical"), ("XSS", "high"))
        tracker = FindingTracker(profile)

        tracker.check_discovery(_make_finding_entity("SQLi found", "critical", "a"), step=1)
        assert len(tracker.undiscovered) == 1
        assert tracker.undiscovered[0].expected.title == "XSS"

    def test_unverified(self):
        profile = _make_profile(("SQLi", "critical"), ("XSS", "high"))
        tracker = FindingTracker(profile)

        tracker.check_discovery(_make_finding_entity("SQLi found", "critical", "a"), step=1)
        tracker.check_discovery(_make_finding_entity("XSS found", "high", "b"), step=2)
        tracker.check_verification("a", step=3)

        assert len(tracker.unverified) == 1
        assert tracker.unverified[0].expected.title == "XSS"


class TestValidationReport:
    def test_passed_flag(self):
        report = ValidationReport(
            profile_name="test",
            target="localhost",
            total_expected=10,
            discovered=10,
            verified=8,
            coverage=1.0,
            verification_rate=0.8,
            steps_taken=50,
            passed=True,
        )
        assert report.passed is True

    def test_failed_flag(self):
        report = ValidationReport(
            profile_name="test",
            target="localhost",
            total_expected=10,
            discovered=5,
            verified=3,
            coverage=0.5,
            verification_rate=0.6,
            steps_taken=100,
            passed=False,
        )
        assert report.passed is False
        assert report.coverage == 0.5
