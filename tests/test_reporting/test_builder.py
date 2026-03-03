"""Tests for ReportBuilder — canonical model construction from ScanSession."""

from __future__ import annotations

from unittest.mock import MagicMock

from basilisk.core.session import (
    ScanSession,
    SessionDecision,
    SessionPlugin,
    StepSnapshot,
)
from basilisk.events.bus import Event, EventType
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.reporting.builder import (
    ReportBuilder,
    _compute_kill_chain,
    _compute_risk_score,
)
from basilisk.reporting.model import REPORT_SCHEMA_VERSION


def _sample_session() -> ScanSession:
    """Build a session with representative data."""
    s = ScanSession("test.example.com", max_steps=50)
    g = s.graph

    # Populate KG with entities
    host = Entity.host("test.example.com")
    g.add_entity(host)

    svc1 = Entity.service("test.example.com", 80, "tcp", service="http")
    svc2 = Entity.service("test.example.com", 443, "tcp", service="https")
    g.add_entity(svc1)
    g.add_entity(svc2)
    g.add_relation(Relation(source_id=host.id, target_id=svc1.id, type=RelationType.EXPOSES))
    g.add_relation(Relation(source_id=host.id, target_id=svc2.id, type=RelationType.EXPOSES))

    for path in ["/login", "/admin", "/api"]:
        ep = Entity.endpoint("test.example.com", path)
        g.add_entity(ep)
        g.add_relation(
            Relation(source_id=svc2.id, target_id=ep.id, type=RelationType.HAS_ENDPOINT),
        )

    tech = Entity.technology("test.example.com", "nginx", "1.21")
    g.add_entity(tech)
    g.add_relation(Relation(source_id=svc2.id, target_id=tech.id, type=RelationType.RUNS))

    # Findings in the graph
    g.add_entity(Entity.finding(
        "test.example.com", "SQL Injection in /login", severity="high",
        evidence="1' OR '1'='1 returned 200", description="Auth bypass via SQLi",
        tags=["sqli", "auth"], verified=True, step=5,
    ))
    g.add_entity(Entity.finding(
        "test.example.com", "Missing HSTS Header", severity="info",
        step=2,
    ))

    # Execution metadata
    s.step = 10
    s.gap_count = 3
    s.decisions = [
        SessionDecision(
            step=1, plugin="port_scan", target="test.example.com",
            score=0.95, reasoning="initial recon",
        ),
        SessionDecision(
            step=5, plugin="sqli_basic", target="test.example.com",
            score=0.87, reasoning="high priority gap",
            productive=True, new_entities=3,
        ),
    ]
    s.plugins = [
        SessionPlugin(
            name="port_scan", target="test.example.com",
            duration=1.5, findings_count=0, step=1,
        ),
        SessionPlugin(
            name="sqli_basic", target="test.example.com",
            duration=3.2, findings_count=1, step=5,
        ),
    ]
    s.step_history = [
        StepSnapshot(step=1, entities=10, relations=5, gaps=8, entities_gained=10),
        StepSnapshot(step=5, entities=42, relations=20, gaps=3, entities_gained=5),
    ]
    s.hypotheses_confirmed = 2
    s.hypotheses_rejected = 1
    s.beliefs_strengthened = 5
    s.beliefs_weakened = 1
    return s


class TestReportBuilder:
    """Test ReportBuilder.from_session()."""

    def test_produces_report_model(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        assert model.schema_version == REPORT_SCHEMA_VERSION
        assert model.target == "test.example.com"
        assert model.mode == "auto"
        assert model.status == "running"

    def test_statistics_computed(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        stats = model.statistics
        assert stats.scenarios_executed == 2
        assert stats.findings_total == 2
        assert stats.steps_completed == 10
        assert stats.max_steps == 50
        # entity/relation counts from KG
        assert stats.total_entities == s.graph.entity_count
        assert stats.total_relations == s.graph.relation_count

    def test_severity_counts(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        counts = model.statistics.severity_counts
        assert counts["HIGH"] == 1
        assert counts["INFO"] == 1

    def test_risk_score(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        # HIGH=2.5 + INFO=0.0 = 2.5
        assert model.statistics.risk_score == 2.5

    def test_entity_counts_from_graph(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        ec = model.statistics.entity_counts
        assert ec["host"] == 1
        assert ec["service"] == 2
        assert ec["endpoint"] == 3
        assert ec["technology"] == 1
        assert ec["finding"] == 2

    def test_kill_chain_coverage(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        kc = model.statistics.kill_chain_coverage
        assert kc["Recon"] == 1  # port_scan
        assert kc["Exploit"] == 1  # sqli_basic

    def test_findings_from_graph(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        assert len(model.findings_raw) == 2
        # Sorted by severity: HIGH before INFO
        assert model.findings_raw[0]["severity"] == "HIGH"
        assert model.findings_raw[1]["severity"] == "INFO"

    def test_findings_use_kg_confidence(self):
        """Findings confidence comes from KG (probabilistic-merged), not event data."""
        s = ScanSession("test.com")
        e = Entity.finding("test.com", "Test", severity="high")
        e.confidence = 0.85
        s.graph.add_entity(e)
        model = ReportBuilder.from_session(s)
        assert model.findings_raw[0]["confidence"] == 0.85

    def test_decisions(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        assert len(model.decisions) == 2
        # Sorted by step
        assert model.decisions[0]["step"] == 1
        assert model.decisions[1]["productive"] is True

    def test_step_history(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        assert len(model.step_history) == 2
        assert model.step_history[0]["entities_gained"] == 10

    def test_reasoning(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        r = model.reasoning
        assert r["hypotheses_confirmed"] == 2
        assert r["beliefs_strengthened"] == 5

    def test_training_none_by_default(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        assert model.training is None

    def test_training_from_session(self):
        s = _sample_session()
        report = MagicMock()
        report.profile_name = "dvwa"
        report.coverage = 0.85
        report.verification_rate = 0.7
        report.passed = True

        tf = MagicMock()
        tf.expected.title = "SQL Injection"
        tf.expected.severity = "high"
        tf.discovered = True
        tf.verified = True
        tf.discovery_step = 3
        tracker = MagicMock()
        tracker.tracked = [tf]

        s.finalize_training(report, tracker)
        model = ReportBuilder.from_session(s)
        assert model.training is not None
        assert model.training.profile_name == "dvwa"
        assert model.training.coverage_percent == 85.0
        assert model.training.passed is True

    def test_empty_session(self):
        s = ScanSession("empty.com")
        model = ReportBuilder.from_session(s)
        assert model.statistics.scenarios_executed == 0
        assert len(model.findings_raw) == 0
        assert model.training is None

    def test_scan_id_auto_generated(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        assert len(model.scan_id) == 16

    def test_custom_scan_id(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s, scan_id="custom123")
        assert model.scan_id == "custom123"

    def test_topology_from_graph(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        topo = model.topology
        assert "test.example.com" in topo
        host_topo = topo["test.example.com"]
        # Services sorted by port
        assert host_topo["services"][0]["port"] == 80
        assert host_topo["services"][1]["port"] == 443
        # Endpoints sorted
        assert host_topo["endpoints"] == ["/admin", "/api", "/login"]
        # Technology
        assert host_topo["technologies"][0]["name"] == "nginx"

    def test_topology_subdomain(self):
        s = ScanSession("test.com")
        host = Entity.host("test.com")
        sub = Entity.host("api.test.com", type="subdomain", parent="test.com")
        s.graph.add_entity(host)
        s.graph.add_entity(sub)
        model = ReportBuilder.from_session(s)
        assert model.topology["api.test.com"]["is_subdomain"] is True
        assert model.topology["api.test.com"]["parent"] == "test.com"

    def test_model_is_frozen(self):
        s = _sample_session()
        model = ReportBuilder.from_session(s)
        try:
            model.target = "other.com"  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except Exception:
            pass

    def test_timeline_has_step(self):
        s = ScanSession("test.com")
        s.bus.emit(Event(type=EventType.PLUGIN_STARTED, data={
            "plugin": "port_scan", "target": "test.com", "step": 3,
        }))
        model = ReportBuilder.from_session(s)
        assert len(model.execution_timeline) == 1
        assert model.execution_timeline[0].step == 3


class TestComputeRiskScore:
    """Test risk score calculation."""

    def test_empty(self):
        assert _compute_risk_score([]) == 0.0

    def test_critical_and_high(self):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
        ]
        assert _compute_risk_score(findings) == 6.5

    def test_capped_at_10(self):
        findings = [{"severity": "CRITICAL"} for _ in range(10)]
        assert _compute_risk_score(findings) == 10.0


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
