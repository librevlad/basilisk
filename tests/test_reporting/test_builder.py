"""Tests for ReportBuilder — canonical model construction from collector."""

from __future__ import annotations

from unittest.mock import MagicMock

from basilisk.reporting.builder import (
    ReportBuilder,
    TrainingReportBuilder,
    _compute_kill_chain,
    _compute_risk_score_from_findings,
)
from basilisk.reporting.collector import (
    HostTopology,
    ReportCollector,
    ReportDecision,
    ReportFinding,
    ReportPlugin,
    StepSnapshot,
)
from basilisk.reporting.model import REPORT_SCHEMA_VERSION


def _sample_collector() -> ReportCollector:
    """Build a collector with representative data."""
    c = ReportCollector(target="test.example.com", mode="auto", max_steps=50)
    c.step = 10
    c.total_entities = 42
    c.total_relations = 20
    c.gap_count = 3
    c.entity_counts["host"] = 2
    c.entity_counts["service"] = 8
    c.entity_counts["endpoint"] = 15
    c.entity_counts["technology"] = 5
    c.findings = [
        ReportFinding(
            title="SQL Injection in /login",
            severity="high",
            host="test.example.com",
            evidence="1' OR '1'='1 returned 200",
            description="Auth bypass via SQLi",
            tags=["sqli", "auth"],
            confidence=0.92,
            verified=True,
            step=5,
        ),
        ReportFinding(
            title="Missing HSTS Header",
            severity="info",
            host="test.example.com",
            step=2,
        ),
    ]
    c.decisions = [
        ReportDecision(step=1, plugin="port_scan", target="test.example.com", score=0.95,
                       reasoning="initial recon"),
        ReportDecision(step=5, plugin="sqli_basic", target="test.example.com", score=0.87,
                       reasoning="high priority gap", productive=True, new_entities=3),
    ]
    c.plugins = [
        ReportPlugin(name="port_scan", target="test.example.com", duration=1.5,
                     findings_count=0, step=1),
        ReportPlugin(name="sqli_basic", target="test.example.com", duration=3.2,
                     findings_count=1, step=5),
    ]
    c.step_history = [
        StepSnapshot(step=1, entities=10, relations=5, gaps=8, entities_gained=10),
        StepSnapshot(step=5, entities=42, relations=20, gaps=3, entities_gained=5),
    ]
    c.hypotheses_confirmed = 2
    c.hypotheses_rejected = 1
    c.beliefs_strengthened = 5
    c.beliefs_weakened = 1
    return c


class TestReportBuilder:
    """Test ReportBuilder.from_collector()."""

    def test_produces_report_model(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        assert model.schema_version == REPORT_SCHEMA_VERSION
        assert model.target == "test.example.com"
        assert model.mode == "auto"
        assert model.status == "running"

    def test_statistics_computed(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        stats = model.statistics
        assert stats.scenarios_executed == 2
        assert stats.findings_total == 2
        assert stats.steps_completed == 10
        assert stats.max_steps == 50
        assert stats.total_entities == 42
        assert stats.total_relations == 20

    def test_severity_counts(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        counts = model.statistics.severity_counts
        assert counts["HIGH"] == 1
        assert counts["INFO"] == 1

    def test_risk_score(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        # HIGH=2.5 + INFO=0.0 = 2.5
        assert model.statistics.risk_score == 2.5

    def test_entity_counts(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        ec = model.statistics.entity_counts
        assert ec["host"] == 2
        assert ec["service"] == 8
        assert ec["endpoint"] == 15

    def test_kill_chain_coverage(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        kc = model.statistics.kill_chain_coverage
        assert kc["Recon"] == 1  # port_scan
        assert kc["Exploit"] == 1  # sqli_basic

    def test_findings_raw(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        assert len(model.findings_raw) == 2
        assert model.findings_raw[0]["title"] == "SQL Injection in /login"
        assert model.findings_raw[0]["severity"] == "HIGH"
        assert model.findings_raw[0]["verified"] is True
        assert "remediation" in model.findings_raw[0]
        assert "false_positive_risk" in model.findings_raw[0]

    def test_decisions(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        assert len(model.decisions) == 2
        assert model.decisions[1]["productive"] is True

    def test_step_history(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        assert len(model.step_history) == 2
        assert model.step_history[0]["entities_gained"] == 10

    def test_reasoning(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        r = model.reasoning
        assert r["hypotheses_confirmed"] == 2
        assert r["beliefs_strengthened"] == 5

    def test_training_none_by_default(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        assert model.training is None

    def test_empty_collector(self):
        c = ReportCollector()
        model = ReportBuilder.from_collector(c)
        assert model.statistics.scenarios_executed == 0
        assert len(model.findings_raw) == 0
        assert model.training is None

    def test_scan_id_deterministic(self):
        c = _sample_collector()
        id1 = ReportBuilder._make_scan_id(c.target, c.started_at)
        id2 = ReportBuilder._make_scan_id(c.target, c.started_at)
        assert id1 == id2
        assert len(id1) == 16

    def test_scan_id_auto_generated(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        assert len(model.scan_id) == 16

    def test_custom_scan_id(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c, scan_id="custom123")
        assert model.scan_id == "custom123"

    def test_topology_serialized(self):
        c = _sample_collector()
        c.topology["test.example.com"] = HostTopology(
            services=[
                {"port": 443, "protocol": "tcp", "service": "https"},
                {"port": 80, "protocol": "tcp", "service": "http"},
            ],
            endpoints=["/login", "/admin", "/api"],
            technologies=[{"name": "nginx", "version": "1.21"}],
        )
        c.topology["api.test.example.com"] = HostTopology(
            is_subdomain=True, parent="test.example.com",
        )
        model = ReportBuilder.from_collector(c)
        assert "test.example.com" in model.topology
        topo = model.topology["test.example.com"]
        # Services sorted by port
        assert topo["services"][0]["port"] == 80
        assert topo["services"][1]["port"] == 443
        # Endpoints sorted
        assert topo["endpoints"] == ["/admin", "/api", "/login"]
        assert topo["technologies"][0]["name"] == "nginx"
        # Subdomain
        sub = model.topology["api.test.example.com"]
        assert sub["is_subdomain"] is True
        assert sub["parent"] == "test.example.com"

    def test_model_is_frozen(self):
        c = _sample_collector()
        model = ReportBuilder.from_collector(c)
        try:
            model.target = "other.com"  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except Exception:
            pass


class TestTrainingReportBuilder:
    """Test TrainingReportBuilder.from_training()."""

    def _make_training_mocks(self):
        report = MagicMock()
        report.profile_name = "dvwa"
        report.coverage = 0.85
        report.verification_rate = 0.7
        report.passed = True

        tracker = MagicMock()
        tf1 = MagicMock()
        tf1.expected.title = "SQL Injection"
        tf1.expected.severity = "high"
        tf1.discovered = True
        tf1.verified = True
        tf1.discovery_step = 3

        tf2 = MagicMock()
        tf2.expected.title = "XSS"
        tf2.expected.severity = "medium"
        tf2.discovered = False
        tf2.verified = False
        tf2.discovery_step = None

        tracker.tracked = [tf1, tf2]
        return report, tracker

    def test_training_section_present(self):
        c = _sample_collector()
        c.finalize("training_complete")
        c.mode = "train"
        report, tracker = self._make_training_mocks()
        model = TrainingReportBuilder.from_training(c, report, tracker)
        assert model.training is not None
        assert model.training.profile_name == "dvwa"

    def test_training_coverage(self):
        c = _sample_collector()
        c.finalize("training_complete")
        c.mode = "train"
        report, tracker = self._make_training_mocks()
        model = TrainingReportBuilder.from_training(c, report, tracker)
        assert model.training.coverage_percent == 85.0
        assert model.training.verification_rate == 70.0

    def test_training_missed(self):
        c = _sample_collector()
        c.finalize("training_complete")
        c.mode = "train"
        report, tracker = self._make_training_mocks()
        model = TrainingReportBuilder.from_training(c, report, tracker)
        assert len(model.training.missed) == 1
        assert model.training.missed[0]["title"] == "XSS"

    def test_training_detected_count(self):
        c = _sample_collector()
        c.finalize("training_complete")
        c.mode = "train"
        report, tracker = self._make_training_mocks()
        model = TrainingReportBuilder.from_training(c, report, tracker)
        assert model.training.detected == 1
        assert model.training.expected_total == 2

    def test_training_passed(self):
        c = _sample_collector()
        c.finalize("training_complete")
        c.mode = "train"
        report, tracker = self._make_training_mocks()
        model = TrainingReportBuilder.from_training(c, report, tracker)
        assert model.training.passed is True


class TestComputeRiskScore:
    """Test risk score calculation."""

    def test_empty(self):
        assert _compute_risk_score_from_findings([]) == 0.0

    def test_critical_and_high(self):
        findings = [
            MagicMock(severity="critical"),
            MagicMock(severity="high"),
        ]
        # 4.0 + 2.5 = 6.5
        assert _compute_risk_score_from_findings(findings) == 6.5

    def test_capped_at_10(self):
        findings = [MagicMock(severity="critical") for _ in range(10)]
        assert _compute_risk_score_from_findings(findings) == 10.0


class TestComputeKillChain:
    """Test kill chain classification."""

    def test_empty(self):
        result = _compute_kill_chain(set())
        assert result["Recon"] == 0
        assert result["Exploit"] == 0

    def test_recon_plugins(self):
        result = _compute_kill_chain({"port_scan", "dns_enum"})
        assert result["Recon"] == 2

    def test_exploit_plugins(self):
        result = _compute_kill_chain({"sqli_basic", "xss_scanner"})
        assert result["Exploit"] == 2

    def test_mixed(self):
        result = _compute_kill_chain({"port_scan", "sqli_basic", "finding_confirmer"})
        assert result["Recon"] == 1
        assert result["Exploit"] == 1
        assert result["Verify"] == 1
