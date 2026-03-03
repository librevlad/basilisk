"""Tests for viz_hints pre-computation — renderer purity audit."""

from __future__ import annotations

from basilisk.core.session import (
    ScanSession,
    SessionDecision,
    SessionPlugin,
    StepSnapshot,
)
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.reporting.builder import ReportBuilder
from basilisk.reporting.renderer import model_to_data, render_html


def _session_with_data() -> ScanSession:
    """Build a session with rich data for viz_hints testing."""
    s = ScanSession("test.example.com", max_steps=50)
    g = s.graph

    host = Entity.host("test.example.com")
    g.add_entity(host)
    api_host = Entity.host("api.test.example.com", type="subdomain", parent="test.example.com")
    g.add_entity(api_host)

    svc80 = Entity.service("test.example.com", 80, "tcp", service="http")
    svc443 = Entity.service("test.example.com", 443, "tcp", service="https")
    svc22 = Entity.service("api.test.example.com", 22, "tcp", service="ssh")
    g.add_entity(svc80)
    g.add_entity(svc443)
    g.add_entity(svc22)
    g.add_relation(Relation(source_id=host.id, target_id=svc80.id, type=RelationType.EXPOSES))
    g.add_relation(Relation(source_id=host.id, target_id=svc443.id, type=RelationType.EXPOSES))
    g.add_relation(
        Relation(source_id=api_host.id, target_id=svc22.id, type=RelationType.EXPOSES),
    )

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

    tech = Entity.technology("test.example.com", "nginx", version="1.25")
    g.add_entity(tech)
    g.add_relation(Relation(source_id=svc80.id, target_id=tech.id, type=RelationType.RUNS))

    # Findings on different hosts and steps
    g.add_entity(Entity.finding(
        "test.example.com", "SQLi in /login", severity="high",
        evidence="proof1", step=3,
    ))
    g.add_entity(Entity.finding(
        "test.example.com", "XSS in /admin", severity="medium",
        evidence="proof2", step=5,
    ))
    g.add_entity(Entity.finding(
        "api.test.example.com", "Missing HSTS", severity="info",
        evidence="", step=5,
    ))

    s.step = 10
    s.gap_count = 2
    s.decisions = [
        SessionDecision(
            step=1, plugin="port_scan", target="test.example.com",
            score=0.95, reasoning="Gap: Host has no known services. Selected port_scan",
            productive=True, new_entities=5,
        ),
        SessionDecision(
            step=3, plugin="sqli_basic", target="test.example.com",
            score=0.87, reasoning="Gap: No vulnerability testing. Selected sqli_basic",
            productive=True, new_entities=1,
        ),
        SessionDecision(
            step=5, plugin="xss_scanner", target="test.example.com",
            score=0.72, reasoning="Gap: No vulnerability testing. Selected xss_scanner",
            productive=False, new_entities=0,
        ),
    ]
    s.plugins = [
        SessionPlugin(name="port_scan", target="test.example.com",
                       duration=1.5, findings_count=0, step=1),
        SessionPlugin(name="sqli_basic", target="test.example.com",
                       duration=3.2, findings_count=1, step=3),
        SessionPlugin(name="xss_scanner", target="test.example.com",
                       duration=2.1, findings_count=1, step=5),
    ]
    s.step_history = [
        StepSnapshot(step=1, entities=5, relations=3, gaps=10, entities_gained=5),
        StepSnapshot(step=3, entities=15, relations=8, gaps=6, entities_gained=10),
        StepSnapshot(step=5, entities=20, relations=12, gaps=4, entities_gained=5),
        StepSnapshot(step=7, entities=21, relations=13, gaps=3, entities_gained=1),
        StepSnapshot(step=9, entities=22, relations=14, gaps=2, entities_gained=0),
    ]
    return s


class TestVizHintsPresent:
    """viz_hints dict is populated in the report model."""

    def test_viz_hints_present_in_report(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        assert isinstance(model.viz_hints, dict)
        assert "findings" in model.viz_hints
        assert "kg_growth" in model.viz_hints
        assert "attack_surface" in model.viz_hints
        assert "network_map" in model.viz_hints
        assert "plugin_perf" in model.viz_hints
        assert "decisions" in model.viz_hints


class TestTopHostsComputed:
    """findings.top_hosts has hosts sorted by finding count."""

    def test_top_hosts_computed(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        top_hosts = model.viz_hints["findings"]["top_hosts"]
        assert len(top_hosts) >= 1
        # test.example.com has 2 findings, api has 1
        assert top_hosts[0][0] == "test.example.com"
        assert top_hosts[0][1] == 2

    def test_top_hosts_sorted_descending(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        top_hosts = model.viz_hints["findings"]["top_hosts"]
        counts = [c for _, c in top_hosts]
        assert counts == sorted(counts, reverse=True)


class TestProtocolGroupsComputed:
    """network_map.protocol_groups has grouped service counts."""

    def test_protocol_groups_computed(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        groups = model.viz_hints["network_map"]["protocol_groups"]
        group_dict = dict(groups)
        # http + https = HTTP(1) + HTTPS(1), ssh = SSH(1)
        assert "HTTP" in group_dict or "HTTPS" in group_dict or "SSH" in group_dict
        total = sum(c for _, c in groups)
        assert total == 3  # 3 services total

    def test_protocol_groups_sorted_by_count(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        groups = model.viz_hints["network_map"]["protocol_groups"]
        counts = [c for _, c in groups]
        assert counts == sorted(counts, reverse=True)


class TestKgGrowthHints:
    """kg_growth has peak and saturation info."""

    def test_peak_gain_computed(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        kg = model.viz_hints["kg_growth"]
        assert kg["peak_gain"] == 10  # step 3 has entities_gained=10
        assert kg["peak_step"] == 1  # index 1 in step_history


class TestAttackSurfaceHints:
    """attack_surface has root/sub/examined counts."""

    def test_attack_surface_counts(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        asf = model.viz_hints["attack_surface"]
        assert asf["root_count"] == 1
        assert asf["subdomain_count"] == 1
        assert asf["examined_count"] == 2  # both have services/findings
        assert asf["examined_pct"] == 100.0


class TestPluginPerfHints:
    """plugin_perf has aggregated performance data."""

    def test_total_duration_computed(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        pp = model.viz_hints["plugin_perf"]
        assert abs(pp["total_duration"] - 6.8) < 0.01  # 1.5 + 3.2 + 2.1
        assert pp["total_findings"] == 2  # 0 + 1 + 1

    def test_top_cost_plugins_sorted(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        top = model.viz_hints["plugin_perf"]["top_cost_plugins"]
        durations = [d for _, d in top]
        assert durations == sorted(durations, reverse=True)


class TestDecisionHints:
    """decisions hint has productivity and gap type info."""

    def test_productive_count(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        dec = model.viz_hints["decisions"]
        assert dec["productive_count"] == 2
        assert dec["total_entities_gained"] == 6  # 5 + 1 + 0

    def test_gap_type_counts(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        gaps = model.viz_hints["decisions"]["gap_type_counts"]
        gap_dict = dict(gaps)
        # "No Services" from port_scan, "Vuln Testing" from sqli + xss
        assert "Vuln Testing" in gap_dict
        assert gap_dict["Vuln Testing"] == 2


class TestBackwardCompat:
    """Renderer handles missing viz_hints gracefully."""

    def test_backward_compat_no_hints(self):
        """Renderer works when viz_hints is empty (old reports)."""
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        data = model_to_data(model)
        # Remove viz_hints to simulate old report
        data["viz_hints"] = {}
        # Should not crash
        result = render_html(data, auto_refresh=False)
        assert "<!DOCTYPE html>" in result
        assert "test.example.com" in result

    def test_backward_compat_missing_key(self):
        """Renderer works when viz_hints key is completely absent."""
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        data = model_to_data(model)
        del data["viz_hints"]
        result = render_html(data, auto_refresh=False)
        assert "<!DOCTYPE html>" in result


class TestVizHintsInDataDict:
    """model_to_data passes viz_hints through."""

    def test_viz_hints_in_data(self):
        s = _session_with_data()
        model = ReportBuilder.from_session(s)
        data = model_to_data(model)
        assert "viz_hints" in data
        assert "findings" in data["viz_hints"]
