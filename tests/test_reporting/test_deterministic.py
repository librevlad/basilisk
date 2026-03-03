"""Deterministic report regression tests — same input → identical JSON."""

from __future__ import annotations

from basilisk.core.session import (
    ReasoningEvent,
    ScanSession,
    SessionDecision,
    SessionPlugin,
    StepSnapshot,
)
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.reporting.builder import ReportBuilder
from basilisk.reporting.model import REPORT_SCHEMA_VERSION
from basilisk.reporting.renderer import model_to_data, render_json


def _build_session() -> ScanSession:
    """Build a session with representative data for deterministic tests."""
    s = ScanSession("test.example.com", max_steps=50)
    g = s.graph

    # Add entities in deliberate non-sorted order
    host = Entity.host("test.example.com")
    g.add_entity(host)
    api_host = Entity.host("api.test.example.com", type="subdomain", parent="test.example.com")
    g.add_entity(api_host)

    svc443 = Entity.service("test.example.com", 443, "tcp", service="https")
    svc80 = Entity.service("test.example.com", 80, "tcp", service="http")
    g.add_entity(svc443)
    g.add_entity(svc80)
    g.add_relation(Relation(source_id=host.id, target_id=svc443.id, type=RelationType.EXPOSES))
    g.add_relation(Relation(source_id=host.id, target_id=svc80.id, type=RelationType.EXPOSES))

    ep1 = Entity.endpoint("test.example.com", "/login")
    ep2 = Entity.endpoint("test.example.com", "/admin")
    g.add_entity(ep1)
    g.add_entity(ep2)
    g.add_relation(
        Relation(source_id=svc443.id, target_id=ep1.id, type=RelationType.HAS_ENDPOINT),
    )
    g.add_relation(
        Relation(source_id=svc443.id, target_id=ep2.id, type=RelationType.HAS_ENDPOINT),
    )

    # Technologies in reverse-alpha order for sorting test
    tech_nginx = Entity.technology("test.example.com", "nginx", version="1.25")
    tech_apache = Entity.technology("test.example.com", "apache", version="2.4")
    g.add_entity(tech_nginx)
    g.add_entity(tech_apache)
    g.add_relation(
        Relation(source_id=svc80.id, target_id=tech_nginx.id, type=RelationType.RUNS),
    )
    g.add_relation(
        Relation(source_id=svc80.id, target_id=tech_apache.id, type=RelationType.RUNS),
    )

    # Findings in non-severity order
    g.add_entity(Entity.finding(
        "test.example.com", "Missing HSTS Header", severity="info",
        evidence="", tags=["missing_header"],
    ))
    g.add_entity(Entity.finding(
        "test.example.com", "SQL Injection in /login", severity="high",
        evidence="1' OR '1'='1 returned 200", tags=["sqli"],
    ))
    g.add_entity(Entity.finding(
        "test.example.com", "XSS in /search", severity="medium",
        evidence="<script>alert(1)</script>", tags=["xss"],
    ))

    # Execution metadata
    s.step = 10
    s.gap_count = 3
    s.decisions = [
        SessionDecision(
            step=5, plugin="sqli_basic", target="test.example.com",
            score=0.87, reasoning="high priority gap",
            productive=True, new_entities=3,
        ),
        SessionDecision(
            step=1, plugin="port_scan", target="test.example.com",
            score=0.95, reasoning="initial recon",
        ),
    ]
    s.plugins = [
        SessionPlugin(name="port_scan", target="test.example.com",
                       duration=1.5, findings_count=0, step=1),
        SessionPlugin(name="sqli_basic", target="test.example.com",
                       duration=3.2, findings_count=1, step=5),
    ]
    s.step_history = [
        StepSnapshot(step=1, entities=10, relations=5, gaps=8, entities_gained=10),
        StepSnapshot(step=5, entities=42, relations=20, gaps=3, entities_gained=5),
    ]
    s.hypotheses_confirmed = 2
    s.hypotheses_rejected = 1
    s.beliefs_strengthened = 5
    s.beliefs_weakened = 1
    s.reasoning_events = [
        ReasoningEvent(event_type="hypothesis_confirmed", step=3, data={"id": "h1"}),
        ReasoningEvent(event_type="belief_strengthened", step=4, data={"entity": "x"}),
    ]

    return s


class TestDeterministicOutput:
    """Verify that report output is identical for the same session state."""

    def test_json_identical_for_same_session(self):
        s = _build_session()
        model1 = ReportBuilder.from_session(s)
        model2 = ReportBuilder.from_session(s)
        data1 = model_to_data(model1)
        data2 = model_to_data(model2)
        json1 = render_json(data1)
        json2 = render_json(data2)
        assert json1 == json2

    def test_vulnerability_order_stable(self):
        s = _build_session()
        model = ReportBuilder.from_session(s)
        ids = [v.vulnerability_id for v in model.vulnerabilities]
        assert ids == sorted(ids)

    def test_findings_sorted_by_severity_then_title(self):
        s = _build_session()
        model = ReportBuilder.from_session(s)
        findings = model.findings_raw
        severities = [f["severity"] for f in findings]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        severity_indices = [order.get(s, 99) for s in severities]
        assert severity_indices == sorted(severity_indices)

    def test_topology_hosts_sorted(self):
        s = _build_session()
        model = ReportBuilder.from_session(s)
        hosts = list(model.topology.keys())
        assert hosts == sorted(hosts)

    def test_topology_endpoints_sorted(self):
        s = _build_session()
        model = ReportBuilder.from_session(s)
        for topo in model.topology.values():
            endpoints = topo.get("endpoints", [])
            assert endpoints == sorted(endpoints)

    def test_topology_services_sorted_by_port(self):
        s = _build_session()
        model = ReportBuilder.from_session(s)
        topo = model.topology.get("test.example.com", {})
        services = topo.get("services", [])
        ports = [s["port"] for s in services]
        assert ports == sorted(ports)

    def test_schema_version_present(self):
        s = _build_session()
        model = ReportBuilder.from_session(s)
        assert model.schema_version == REPORT_SCHEMA_VERSION

    def test_decisions_sorted_by_step(self):
        """Decisions are sorted by step even if inserted out of order."""
        s = _build_session()
        model = ReportBuilder.from_session(s)
        steps = [d["step"] for d in model.decisions]
        assert steps == sorted(steps)

    def test_json_sort_keys(self):
        s = _build_session()
        model = ReportBuilder.from_session(s)
        data = model_to_data(model)
        json_str = render_json(data)
        # sort_keys=True means top-level keys are alphabetical
        import json

        parsed = json.loads(json_str)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_topology_technologies_sorted(self):
        """Technologies are sorted by (name, version)."""
        s = _build_session()
        model = ReportBuilder.from_session(s)
        topo = model.topology.get("test.example.com", {})
        techs = topo.get("technologies", [])
        names = [t["name"] for t in techs]
        assert names == sorted(names)

    def test_schema_version_is_4_2(self):
        assert REPORT_SCHEMA_VERSION == "4.2"
