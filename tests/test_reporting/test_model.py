"""Tests for ReportModel — canonical frozen report model."""

from __future__ import annotations

from datetime import UTC, datetime

from basilisk.reporting.model import (
    REPORT_SCHEMA_VERSION,
    ReportModel,
    ReportStatistics,
    TimelineEvent,
    TrainingSection,
    VulnerabilityInstance,
)


class TestVulnerabilityInstance:
    """Test VulnerabilityInstance model."""

    def test_frozen(self):
        vi = VulnerabilityInstance(
            vulnerability_id="abc123",
            vuln_type="sqli",
            severity="HIGH",
            affected_surfaces=["/login"],
            scenarios=["sqli_basic"],
            confidence_aggregate=0.9,
            proofs=["1' OR '1'='1"],
        )
        try:
            vi.vuln_type = "xss"  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except Exception:
            pass

    def test_make_id_deterministic(self):
        id1 = VulnerabilityInstance.make_id("example.com", "/login", "sqli", "1=1")
        id2 = VulnerabilityInstance.make_id("example.com", "/login", "sqli", "1=1")
        assert id1 == id2
        assert len(id1) == 16

    def test_make_id_different_inputs(self):
        id1 = VulnerabilityInstance.make_id("example.com", "/login", "sqli", "1=1")
        id2 = VulnerabilityInstance.make_id("example.com", "/api", "sqli", "1=1")
        assert id1 != id2


class TestTimelineEvent:
    """Test TimelineEvent model."""

    def test_frozen(self):
        te = TimelineEvent(
            timestamp=datetime.now(UTC),
            scenario="sqli_basic",
            action="completed",
        )
        try:
            te.action = "failed"  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except Exception:
            pass

    def test_default_result(self):
        te = TimelineEvent(
            timestamp=datetime.now(UTC),
            scenario="port_scan",
            action="started",
        )
        assert te.result == {}


class TestReportStatistics:
    """Test ReportStatistics model."""

    def test_defaults(self):
        stats = ReportStatistics()
        assert stats.scenarios_executed == 0
        assert stats.findings_total == 0
        assert stats.risk_score == 0.0
        assert stats.severity_counts == {}
        assert stats.entity_counts == {}
        assert stats.kill_chain_coverage == {}


class TestTrainingSection:
    """Test TrainingSection model."""

    def test_defaults(self):
        ts = TrainingSection()
        assert ts.profile_name == ""
        assert ts.expected_total == 0
        assert ts.passed is False
        assert ts.missed == []
        assert ts.false_positives == []


class TestReportModel:
    """Test ReportModel — canonical frozen report."""

    def test_frozen(self):
        model = ReportModel(target="example.com")
        try:
            model.target = "other.com"  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except Exception:
            pass

    def test_schema_version_present(self):
        model = ReportModel(target="example.com")
        assert model.schema_version == REPORT_SCHEMA_VERSION

    def test_serialization_roundtrip(self):
        now = datetime.now(UTC)
        model = ReportModel(
            scan_id="test123",
            target="example.com",
            mode="auto",
            status="completed",
            started_at=now,
            finished_at=now,
            termination_reason="no_gaps",
            statistics=ReportStatistics(
                scenarios_executed=5,
                findings_total=2,
                severity_counts={"HIGH": 1, "MEDIUM": 1},
                risk_score=3.5,
                total_entities=42,
            ),
            vulnerabilities=[
                VulnerabilityInstance(
                    vulnerability_id="abc123",
                    vuln_type="sqli",
                    severity="HIGH",
                    affected_surfaces=["/login"],
                    scenarios=["sqli_basic"],
                    confidence_aggregate=0.9,
                    proofs=["test evidence"],
                ),
            ],
            findings_raw=[{"title": "test", "severity": "HIGH"}],
            decisions=[{"step": 1, "plugin": "port_scan"}],
        )
        data = model.model_dump(mode="json")
        restored = ReportModel.model_validate(data)
        assert restored.scan_id == model.scan_id
        assert restored.target == model.target
        assert restored.statistics.scenarios_executed == 5
        assert len(restored.vulnerabilities) == 1
        assert restored.vulnerabilities[0].vulnerability_id == "abc123"

    def test_schema_version_in_json(self):
        model = ReportModel(target="example.com")
        data = model.model_dump()
        assert "schema_version" in data
        assert data["schema_version"] == REPORT_SCHEMA_VERSION

    def test_default_training_none(self):
        model = ReportModel(target="example.com")
        assert model.training is None

    def test_with_training(self):
        model = ReportModel(
            target="example.com",
            training=TrainingSection(
                profile_name="dvwa",
                expected_total=5,
                detected=4,
                coverage_percent=80.0,
                passed=True,
            ),
        )
        assert model.training is not None
        assert model.training.profile_name == "dvwa"

    def test_schema_regression(self):
        """Field set must match expected, or REPORT_SCHEMA_VERSION must bump."""
        expected_fields = sorted([
            "schema_version", "scan_id", "target", "mode", "status",
            "started_at", "finished_at", "termination_reason",
            "statistics", "vulnerabilities", "execution_timeline",
            "training", "findings_raw", "decisions", "plugins_raw",
            "step_history", "reasoning", "topology",
        ])
        actual_fields = sorted(ReportModel.model_fields.keys())
        assert actual_fields == expected_fields, (
            f"ReportModel fields changed — bump REPORT_SCHEMA_VERSION. "
            f"Expected: {expected_fields}, got: {actual_fields}"
        )
