"""Tests for report renderer — HTML and JSON generation."""

from __future__ import annotations

import json

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
from basilisk.reporting.renderer import (
    _host_risk_score,
    _max_severity_for_host,
    _service_badge_class,
    model_to_data,
    render_html,
    render_json,
)


def _data_from_session(session: ScanSession) -> dict:
    """Build renderer-compatible data dict from a ScanSession."""
    model = ReportBuilder.from_session(session)
    return model_to_data(model)


def _sample_session() -> ScanSession:
    """Build a session with representative data."""
    s = ScanSession("test.example.com", max_steps=50)
    s.step = 10
    s.gap_count = 3

    # Add finding entities to the graph (source of truth for entity data)
    s.graph.add_entity(Entity.finding(
        host="test.example.com",
        title="SQL Injection in /login",
        severity="high",
        evidence="1' OR '1'='1 returned 200",
        description="Auth bypass via SQLi",
        tags=["sqli", "auth"],
        verified=True,
        step=5,
        confidence=0.92,
    ))
    s.graph.add_entity(Entity.finding(
        host="test.example.com",
        title="Missing HSTS Header",
        severity="info",
        step=2,
    ))

    # Add entities to match expected entity_counts (host=2, service=8, endpoint=15, tech=5)
    s.graph.add_entity(Entity.host("test.example.com"))
    s.graph.add_entity(Entity.host("sub.test.example.com"))
    for i in range(8):
        s.graph.add_entity(Entity.service("test.example.com", port=80 + i))
    for i in range(15):
        s.graph.add_entity(Entity.endpoint("test.example.com", f"/path{i}"))
    for i in range(5):
        s.graph.add_entity(Entity.technology("test.example.com", f"tech{i}"))

    s.decisions = [
        SessionDecision(step=1, plugin="port_scan", target="test.example.com", score=0.95,
                        reasoning="initial recon"),
        SessionDecision(step=5, plugin="sqli_basic", target="test.example.com", score=0.87,
                        reasoning="high priority gap", productive=True, new_entities=3),
    ]
    s.plugins = [
        SessionPlugin(name="port_scan", target="test.example.com", duration=1.5,
                      findings_count=0, step=1),
        SessionPlugin(name="sqli_basic", target="test.example.com", duration=3.2,
                      findings_count=1, step=5),
    ]
    s.step_history = [
        StepSnapshot(step=1, entities=10, relations=5, gaps=8, entities_gained=10),
        StepSnapshot(step=2, entities=18, relations=9, gaps=6, entities_gained=8),
        StepSnapshot(step=5, entities=42, relations=20, gaps=3, entities_gained=5),
    ]
    s.hypotheses_confirmed = 2
    s.hypotheses_rejected = 1
    s.beliefs_strengthened = 5
    s.beliefs_weakened = 1
    return s


class TestAssembleData:
    """Test model_to_data output structure."""

    def test_has_required_keys(self):
        s = _sample_session()
        data = _data_from_session(s)
        assert data["version"] == "4.0.0"
        assert data["target"] == "test.example.com"
        assert data["mode"] == "auto"
        assert data["status"] == "running"
        assert "summary" in data
        assert "findings" in data
        assert "decisions" in data
        assert "plugins" in data
        assert "step_history" in data
        assert "reasoning" in data
        assert "training" in data

    def test_summary_values(self):
        s = _sample_session()
        data = _data_from_session(s)
        sm = data["summary"]
        assert sm["steps"] == 10
        assert sm["max_steps"] == 50
        assert sm["total_entities"] == s.graph.entity_count
        assert sm["total_findings"] == 2
        assert sm["total_gaps"] == 3
        assert sm["entity_counts"]["host"] == 2
        assert sm["entity_counts"]["service"] == 8

    def test_findings_serialized(self):
        s = _sample_session()
        data = _data_from_session(s)
        assert len(data["findings"]) == 2
        # Findings are sorted by severity then title; HIGH comes before INFO
        high_findings = [f for f in data["findings"] if f["severity"] == "HIGH"]
        assert len(high_findings) == 1
        f = high_findings[0]
        assert f["title"] == "SQL Injection in /login"
        assert f["severity"] == "HIGH"
        assert f["verified"] is True

    def test_decisions_serialized(self):
        s = _sample_session()
        data = _data_from_session(s)
        assert len(data["decisions"]) == 2
        assert data["decisions"][1]["productive"] is True

    def test_reasoning_serialized(self):
        s = _sample_session()
        data = _data_from_session(s)
        r = data["reasoning"]
        assert r["hypotheses_confirmed"] == 2
        assert r["beliefs_strengthened"] == 5

    def test_training_none(self):
        s = _sample_session()
        data = _data_from_session(s)
        assert data["training"] is None

    def test_empty_session(self):
        s = ScanSession("empty.com")
        data = _data_from_session(s)
        assert data["summary"]["steps"] == 0
        assert len(data["findings"]) == 0
        assert data["training"] is None


class TestRenderJson:
    """Test JSON rendering."""

    def test_valid_json(self):
        s = _sample_session()
        data = _data_from_session(s)
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["target"] == "test.example.com"

    def test_empty_data(self):
        data = _data_from_session(ScanSession("empty.com"))
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["version"] == "4.0.0"


class TestRenderHtml:
    """Test HTML rendering."""

    def test_contains_doctype(self):
        data = _data_from_session(_sample_session())
        html = render_html(data)
        assert html.startswith("<!DOCTYPE html>")

    def test_contains_target(self):
        data = _data_from_session(_sample_session())
        html = render_html(data)
        assert "test.example.com" in html

    def test_auto_refresh_present(self):
        data = _data_from_session(_sample_session())
        html = render_html(data, auto_refresh=True)
        assert 'http-equiv="refresh"' in html

    def test_auto_refresh_absent(self):
        data = _data_from_session(_sample_session())
        html = render_html(data, auto_refresh=False)
        assert 'http-equiv="refresh"' not in html

    def test_contains_sections(self):
        data = _data_from_session(_sample_session())
        html = render_html(data)
        assert 'id="command-center"' in html
        assert 'id="kill-chain"' in html
        assert 'id="kg-growth"' in html
        assert 'id="findings"' in html
        assert 'id="decisions"' in html
        assert 'id="attack-surface"' in html
        assert 'id="plugins"' in html
        assert 'id="reasoning"' in html

    def test_findings_rendered(self):
        data = _data_from_session(_sample_session())
        html = render_html(data)
        assert "SQL Injection in /login" in html
        assert "sev-HIGH" in html
        assert "VERIFIED" in html

    def test_css_variables(self):
        data = _data_from_session(_sample_session())
        html = render_html(data)
        assert "--neon-green: #00ff6a" in html
        assert "--critical: #ff1744" in html
        assert "JetBrains Mono" in html

    def test_js_embedded(self):
        data = _data_from_session(_sample_session())
        html = render_html(data)
        assert "toggleFilter" in html
        assert "applyFilters" in html
        assert "IntersectionObserver" in html

    def test_data_embedded_as_json(self):
        data = _data_from_session(_sample_session())
        html = render_html(data)
        assert "const DATA =" in html

    def test_empty_findings(self):
        data = _data_from_session(ScanSession("empty.com"))
        html = render_html(data)
        assert "No findings yet" in html

    def test_empty_decisions(self):
        data = _data_from_session(ScanSession("empty.com"))
        html = render_html(data)
        assert "No decisions yet" in html

    def test_empty_growth(self):
        data = _data_from_session(ScanSession("empty.com"))
        html = render_html(data)
        assert "No data yet" in html

    def test_sidebar_risk_score(self):
        data = _data_from_session(_sample_session())
        html = render_html(data)
        assert "Risk Score" in html

    def test_kill_chain_phases(self):
        data = _data_from_session(_sample_session())
        html = render_html(data)
        assert "Recon" in html
        assert "Mapping" in html
        assert "Exploit" in html
        assert "Privesc" in html
        assert "Verify" in html

    def test_training_section_absent_when_none(self):
        data = _data_from_session(_sample_session())
        html = render_html(data)
        assert 'id="training"' not in html

    def test_training_section_present(self):
        s = _sample_session()
        s.training_data = {
            "profile_name": "test_app",
            "coverage": 0.85,
            "verification_rate": 0.7,
            "passed": True,
            "expected_findings": [
                {"title": "SQLi", "severity": "high",
                 "discovered": True, "verified": True, "discovery_step": 3},
            ],
        }
        data = _data_from_session(s)
        html = render_html(data)
        assert 'id="training"' in html
        assert "PASSED" in html
        assert "test_app" in html

    def test_remediation_rendered(self):
        s = ScanSession("test.com")
        s.graph.add_entity(Entity.finding(
            host="test.com", title="SQLi", severity="high",
            evidence="1=1", remediation="Use parameterized queries",
        ))
        data = _data_from_session(s)
        result = render_html(data)
        assert "Remediation:" in result
        assert "Use parameterized queries" in result

    def test_remediation_absent_when_empty(self):
        s = ScanSession("test.com")
        s.graph.add_entity(Entity.finding(
            host="test.com", title="Info", severity="info",
        ))
        data = _data_from_session(s)
        result = render_html(data)
        # CSS class definition exists, but no finding card uses it
        assert "<strong>Remediation:</strong>" not in result

    def test_vulnerabilities_section_rendered(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'id="vulnerabilities"' in result
        assert "Vulnerabilities (Deduplicated)" in result

    def test_attack_surface_stat_cards(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "surface-stat" in result
        assert "Hosts" in result
        assert "Services" in result
        assert "Endpoints" in result
        assert "Technologies" in result
        assert "Containers" in result

    def test_false_positive_risk_in_data(self):
        s = ScanSession("test.com")
        s.graph.add_entity(Entity.finding(
            host="test.com", title="Maybe XSS", severity="medium",
            false_positive_risk="high",
        ))
        data = _data_from_session(s)
        assert data["findings"][0]["false_positive_risk"] == "high"

    def test_vulnerabilities_in_data(self):
        data = _data_from_session(_sample_session())
        assert "vulnerabilities" in data
        assert isinstance(data["vulnerabilities"], list)

    def test_html_escaping(self):
        """Ensure special characters are escaped."""
        s = ScanSession("<script>alert(1)</script>")
        data = _data_from_session(s)
        html = render_html(data)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_execution_timeline_in_data(self):
        s = _sample_session()
        data = _data_from_session(s)
        assert "execution_timeline" in data
        assert isinstance(data["execution_timeline"], list)

    def test_decisions_show_duration(self):
        s = _sample_session()
        s.decisions[0] = SessionDecision(
            step=1, plugin="port_scan", target="test.example.com",
            score=0.95, reasoning="initial recon", duration=2.5,
        )
        data = _data_from_session(s)
        result = render_html(data)
        assert "2.50s" in result

    def test_decisions_show_new_entities(self):
        s = _sample_session()
        data = _data_from_session(s)
        result = render_html(data)
        # Decision at step 5 has new_entities=3
        assert "+3 entities" in result

    def test_reasoning_events_rendered(self):
        s = _sample_session()
        s.reasoning_events = [
            ReasoningEvent(
                event_type="hypothesis_confirmed",
                data={"hypothesis": "SQL injection present"},
                step=5,
            ),
        ]
        data = _data_from_session(s)
        result = render_html(data)
        assert "Events Timeline" in result
        assert "hypothesis_confirmed" in result

    def test_sidebar_has_vulnerabilities_link(self):
        data = _data_from_session(_sample_session())
        # sample_session has findings that produce vulnerabilities
        result = render_html(data)
        assert 'href="#vulnerabilities"' in result
        assert "Vulns" in result

    def test_sidebar_entity_counts(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "entity-breakdown" in result
        assert "entity-row" in result

    def test_hover_states_in_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".finding-card:hover" in result
        assert ".timeline-item:hover" in result
        assert ".surface-stat:hover" in result
        assert ".kc-phase:hover" in result
        assert ".metric-card:hover" in result

    def test_evidence_toggle_js(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "evidence-toggle" in result
        assert "Show more" in result

    def test_entrance_animation_in_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "fade-in-up" in result
        assert "animation-delay" in result

    def test_responsive_surface_stats_grid(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".surface-stats-grid" in result
        # Check responsive rule includes surface-stats-grid
        assert "surface-stats-grid" in result

    def test_copy_to_clipboard_js(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "evidence-copy" in result
        assert "navigator.clipboard.writeText" in result


def _session_with_topology() -> ScanSession:
    """Build a session with sample topology for network map tests."""
    s = _sample_session()

    # --- test.example.com topology ---
    # Host already exists from _sample_session; add_entity merges on collision
    host_e = Entity.host("test.example.com")
    s.graph.add_entity(host_e)  # merge with existing

    svc_https = Entity.service("test.example.com", port=443, protocol="tcp", service="https")
    s.graph.add_entity(svc_https)
    s.graph.add_relation(Relation(
        source_id=host_e.id, target_id=svc_https.id, type=RelationType.EXPOSES,
    ))

    svc_http = Entity.service("test.example.com", port=80, protocol="tcp", service="http")
    s.graph.add_entity(svc_http)
    s.graph.add_relation(Relation(
        source_id=host_e.id, target_id=svc_http.id, type=RelationType.EXPOSES,
    ))

    for path in ["/login", "/admin", "/api/v1"]:
        ep = Entity.endpoint("test.example.com", path)
        s.graph.add_entity(ep)
        s.graph.add_relation(Relation(
            source_id=svc_https.id, target_id=ep.id, type=RelationType.HAS_ENDPOINT,
        ))

    tech_nginx = Entity.technology("test.example.com", "nginx", version="1.21")
    s.graph.add_entity(tech_nginx)
    s.graph.add_relation(Relation(
        source_id=svc_https.id, target_id=tech_nginx.id, type=RelationType.RUNS,
    ))

    tech_react = Entity.technology("test.example.com", "React", version="18")
    s.graph.add_entity(tech_react)
    s.graph.add_relation(Relation(
        source_id=svc_https.id, target_id=tech_react.id, type=RelationType.RUNS,
    ))

    # --- api.test.example.com (subdomain) ---
    sub_host = Entity.host("api.test.example.com", type="subdomain",
                           parent="test.example.com")
    s.graph.add_entity(sub_host)
    s.graph.add_relation(Relation(
        source_id=host_e.id, target_id=sub_host.id, type=RelationType.PARENT_OF,
    ))

    svc_8080 = Entity.service("api.test.example.com", port=8080, protocol="tcp", service="http")
    s.graph.add_entity(svc_8080)
    s.graph.add_relation(Relation(
        source_id=sub_host.id, target_id=svc_8080.id, type=RelationType.EXPOSES,
    ))

    return s


class TestNetworkMap:
    """Test Network Map HTML section rendering."""

    def test_network_map_section_rendered(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert 'id="network-map"' in result
        assert "Network Map" in result

    def test_network_map_absent_when_empty(self):
        data = _data_from_session(ScanSession("empty.com"))
        result = render_html(data)
        assert 'id="network-map"' not in result

    def test_network_map_shows_host_services(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "443" in result
        assert "https" in result
        assert "nm-port" in result

    def test_network_map_shows_endpoints(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "/login" in result
        assert "/admin" in result
        assert "/api/v1" in result

    def test_network_map_shows_technologies(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-tech-chip" in result
        assert "nginx" in result
        assert "react" in result

    def test_sidebar_has_network_map_link(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert 'href="#network-map"' in result
        assert "Network Map" in result

    def test_host_card_hover_in_css(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".host-card:hover" in result

    def test_host_card_entrance_animation(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".nm-grid .host-card" in result

    def test_network_map_summary_stats(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-stats" in result
        assert "nm-stat-card" in result
        assert "nm-stat-value" in result

    def test_endpoints_expand_collapse_many(self):
        s = _session_with_topology()
        # Add 10 endpoints under test.example.com's https service
        svc_https = Entity.service("test.example.com", port=443, protocol="tcp", service="https")
        for i in range(10):
            ep = Entity.endpoint("test.example.com", f"/api/ep{i}")
            s.graph.add_entity(ep)
            s.graph.add_relation(Relation(
                source_id=svc_https.id, target_id=ep.id, type=RelationType.HAS_ENDPOINT,
            ))
        data = _data_from_session(s)
        result = render_html(data)
        assert "nm-endpoints-toggle" in result
        # Tree groups by /api/ segment
        assert "/api/ (1" in result  # at least 10+ endpoints under /api/

    def test_few_endpoints_no_toggle(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # test.example.com has only 3 endpoints → inline, no grouped toggle
        assert "nm-endpoints" in result

    def test_subdomain_has_css_class(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "host-card subdomain" in result

    def test_subdomain_ordered_after_parent(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        parent_idx = result.index("test.example.com")
        sub_idx = result.index("api.test.example.com")
        assert parent_idx < sub_idx

    def test_findings_count_per_host(self):
        s = _session_with_topology()
        # sample session has findings for test.example.com
        data = _data_from_session(s)
        result = render_html(data)
        assert "nm-findings-badge" in result

    def test_service_type_badges(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-svc-https" in result
        assert "nm-svc-http" in result

    def test_service_badge_class_helper(self):
        assert _service_badge_class("https") == "nm-svc-https"
        assert _service_badge_class("HTTP") == "nm-svc-http"
        assert _service_badge_class("  ssh ") == "nm-svc-ssh"
        assert _service_badge_class("postgresql") == "nm-svc-postgres"
        assert _service_badge_class("unknown") == ""

    def test_sidebar_network_map_host_count(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert 'class="cnt">3</span>' in result

    def test_responsive_nm_grid_in_css(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".nm-grid" in result

    def test_network_map_search_js(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "applyHostFilters" in result

    def test_network_map_search_input(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-search" in result
        assert 'placeholder=' in result

    def test_well_known_port_class(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "well-known" in result

    def test_high_port_class(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # api.test.example.com has port 8080
        assert "high-port" in result

    def test_data_host_attribute(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert 'data-host="test.example.com"' in result

    # --- Feature 1: Collapsible Host Cards ---

    def test_host_card_is_collapsible_details(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert '<details class="host-card' in result

    def test_host_card_starts_open(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert '<details class="host-card' in result
        assert "open" in result.split('<details class="host-card')[1][:30]

    def test_host_card_body_wrapper(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "host-card-body" in result

    # --- Feature 2: Host Card Severity Accent ---

    def test_host_card_severity_accent(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # test.example.com has HIGH finding → should have sev-accent-HIGH
        assert "sev-accent-HIGH" in result

    def test_severity_accent_only_on_hosts_with_findings(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # api.test.example.com has no findings → no sev-accent on that card
        # Split by api.test.example.com card
        idx = result.index('data-host="api.test.example.com"')
        # Look backwards to find the opening <details> tag for this card
        card_start = result.rfind("<details", 0, idx)
        card_tag = result[card_start:idx]
        assert "sev-accent" not in card_tag

    def test_severity_accent_css_classes(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".host-card.sev-accent-CRITICAL" in result
        assert ".host-card.sev-accent-HIGH" in result
        assert ".host-card.sev-accent-MEDIUM" in result
        assert ".host-card.sev-accent-LOW" in result
        assert ".host-card.sev-accent-INFO" in result

    def test_max_severity_for_host_helper(self):
        findings = [
            {"host": "a.com", "severity": "LOW"},
            {"host": "a.com", "severity": "HIGH"},
            {"host": "b.com", "severity": "CRITICAL"},
        ]
        assert _max_severity_for_host("a.com", findings) == "HIGH"
        assert _max_severity_for_host("b.com", findings) == "CRITICAL"
        assert _max_severity_for_host("c.com", findings) == ""

    # --- Feature 3: Copy Host Button ---

    def test_host_copy_button_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "host-copy" in result

    def test_host_copy_button_has_hostname(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "copyHost(this,'test.example.com')" in result

    def test_host_copy_css(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".host-copy" in result
        assert ".host-copy:hover" in result

    # --- Feature 4: Search Result Counter + Empty State ---

    def test_search_counter_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-search-status" in result
        assert "nm-visible" in result

    def test_search_counter_shows_total(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # 3 hosts in topology (test.example.com, sub.test.example.com,
        # api.test.example.com)
        assert "of 3 hosts" in result

    def test_no_matches_element_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-no-matches" in result
        assert "No hosts match your search" in result

    def test_filter_updates_counter_js(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "getElementById('nm-visible')" in result
        assert "getElementById('nm-no-matches')" in result

    # --- Feature 5: Port Distribution Mini-Bar ---

    def test_port_bar_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-port-bar" in result

    def test_port_bar_segments(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "well-known-seg" in result

    def test_port_bar_well_known_title(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # test.example.com has ports 443 and 80 (both well-known)
        assert 'well-known"' in result

    def test_port_bar_css(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".nm-port-bar" in result
        assert ".nm-port-seg" in result
        assert ".nm-port-seg.well-known-seg" in result
        assert ".nm-port-seg.high-port-seg" in result

    # --- Feature 6: Expand/Collapse All Toggle ---

    def test_expand_collapse_toggle_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-toggle-btn" in result
        assert "Collapse All" in result

    def test_toggle_network_cards_js(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "toggleNetworkCards" in result
        assert "Expand All" in result

    # --- Feature 7: Severity Filter Chips ---

    def test_severity_filter_chips_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-filter-bar" in result
        assert "toggleHostFilter" in result

    def test_severity_filter_chips_count(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # test.example.com has HIGH finding, api.test.example.com has NONE
        assert "HIGH (1)" in result

    def test_severity_filter_chips_only_existing(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # No CRITICAL findings → no CRITICAL chip in nm-filter-bar
        nm_section = result.split('id="network-map"')[1].split('class="section"')[0]
        assert 'data-sev="CRITICAL"' not in nm_section.split("nm-filter-bar")[1].split("</div>")[0]

    def test_host_card_data_sev_attribute(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert 'data-sev="HIGH"' in result
        assert 'data-sev="NONE"' in result

    def test_severity_filter_js_functions(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "function toggleHostFilter" in result
        assert "function applyHostFilters" in result

    def test_nm_filter_bar_css(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".nm-filter-bar" in result

    # --- Feature 8: Findings Inline Preview ---

    def test_findings_preview_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-findings-preview" in result

    def test_findings_preview_sev_dot(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-sev-dot" in result
        assert "dot-HIGH" in result

    def test_findings_preview_title_shown(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # The sample session has "SQL Injection in /login"
        assert "SQL Injection in /login" in result

    def test_findings_preview_absent_no_findings(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # api.test.example.com card should have no findings preview
        idx = result.index('data-host="api.test.example.com"')
        card_end = result.index("</details>", idx)
        card_html = result[idx:card_end]
        assert "nm-findings-preview" not in card_html

    def test_findings_preview_many_toggle(self):
        s = _session_with_topology()
        # Add 5 findings for test.example.com (already has 2 → total 7)
        for i in range(5):
            s.graph.add_entity(Entity.finding(
                host="test.example.com",
                title=f"Finding {i}",
                severity="medium",
                step=i + 10,
            ))
        data = _data_from_session(s)
        result = render_html(data)
        # Should have "N more" toggle for findings beyond 3
        assert " more</summary>" in result

    # --- Feature 9: Host Sort Controls ---

    def test_sort_buttons_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-sort-bar" in result
        assert "nm-sort-btn" in result
        assert "Severity" in result
        assert "Findings" in result
        assert "Name" in result

    def test_sort_bar_css(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".nm-sort-bar" in result
        assert ".nm-sort-btn" in result
        assert ".nm-sort-btn.active" in result

    def test_sort_js_function(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "function sortNetworkHosts" in result
        assert "sevRank" in result

    def test_host_card_data_findings_attribute(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert 'data-findings="2"' in result  # test.example.com has 2 findings
        assert 'data-findings="0"' in result  # api.test.example.com has 0

    # --- Feature 10: Service Protocol Summary Bar ---

    def test_proto_bar_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-proto-bar" in result

    def test_proto_bar_segments(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-proto-seg" in result

    def test_proto_bar_legend(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-proto-legend" in result
        assert "nm-proto-legend-item" in result

    def test_proto_bar_css(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".nm-proto-bar" in result
        assert ".nm-proto-seg" in result
        assert ".nm-proto-legend" in result

    def test_proto_bar_groups_known_services(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # Topology has https and http services
        assert "HTTPS" in result
        assert "HTTP" in result

    # --- Feature 11: Export Hosts Button ---

    def test_export_button_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "Export Hosts" in result

    def test_export_js_function(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "function exportVisibleHosts" in result

    def test_export_uses_clipboard(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "navigator.clipboard.writeText(hosts.join" in result

    # --- Feature 12: Host Risk Score Badge ---

    def test_risk_badge_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-risk-badge" in result

    def test_risk_badge_score_value(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # test.example.com has HIGH(5) + INFO(0) = 5
        assert 'data-risk="5"' in result

    def test_risk_badge_zero_for_no_findings(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # api.test.example.com has no findings → risk 0
        assert 'data-risk="0"' in result

    def test_host_risk_score_helper(self):
        findings = [
            {"host": "a.com", "severity": "CRITICAL"},
            {"host": "a.com", "severity": "HIGH"},
            {"host": "b.com", "severity": "LOW"},
        ]
        assert _host_risk_score("a.com", findings) == 15  # 10 + 5
        assert _host_risk_score("b.com", findings) == 1
        assert _host_risk_score("c.com", findings) == 0

    def test_risk_sort_button_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "sortNetworkHosts('risk')" in result or 'sortNetworkHosts(\\\'risk\\\')' in result

    # --- Feature 13: Service Count Badge ---

    def test_svc_count_badge_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-svc-count-badge" in result

    def test_svc_count_badge_value(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # test.example.com has 2 services
        assert "2 svcs" in result

    def test_svc_count_badge_css(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".nm-svc-count-badge" in result
        assert "rgba(0,229,255,0.15)" in result

    # --- Feature 14: Compact View Toggle ---

    def test_compact_table_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-compact-table" in result

    def test_compact_table_has_columns(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert 'scope="col">Host</th>' in result
        assert 'scope="col">Risk</th>' in result
        assert 'scope="col">Severity</th>' in result
        assert 'scope="col">Findings</th>' in result
        assert 'scope="col">Services</th>' in result
        assert 'scope="col">Technologies</th>' in result

    def test_compact_view_button_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-view-btn" in result
        assert "Compact" in result

    def test_compact_view_js_function(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "function toggleCompactView" in result

    # --- Feature 15: Keyboard Navigation ---

    def test_keyboard_hint_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-kb-hint" in result
        assert "<kbd>j</kbd>" in result
        assert "<kbd>k</kbd>" in result

    def test_nm_focused_css(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".nm-focused" in result
        assert "var(--neon-green) !important" in result

    def test_keyboard_js_handler(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nmVisibleCards" in result
        assert "nmSetFocus" in result

    def test_keyboard_navigation_keys(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "e.key === 'j'" in result
        assert "e.key === 'k'" in result
        assert "e.key === 'Enter'" in result
        assert "e.key === '/'" in result

    # --- Feature 16: Active Filter Indicator ---

    def test_filter_indicator_element_present(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "nm-filter-indicator" in result

    def test_filter_indicator_css(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert ".nm-filter-indicator" in result
        assert ".nm-filter-indicator a" in result

    def test_filter_indicator_updated_in_js(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "getElementById('nm-filter-indicator')" in result

    def test_clear_host_filters_js(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "function clearHostFilters" in result


# ---------------------------------------------------------------------------
# UX Quick Wins — Report Dashboard Polish
# ---------------------------------------------------------------------------


class TestTerminationReason:
    """Fix 1: termination_reason displayed in Command Center."""

    def test_termination_reason_displayed(self):
        s = _sample_session()
        s.termination_reason = "no_gaps"
        data = _data_from_session(s)
        result = render_html(data)
        assert "Termination: no_gaps" in result

    def test_termination_reason_absent_when_empty(self):
        s = _sample_session()
        data = _data_from_session(s)
        result = render_html(data)
        # Should show em-dash placeholder when empty
        assert "Termination: \u2014" in result


class TestHostCopyFeedback:
    """Fix 2: host copy button shows Copied! feedback."""

    def test_host_copy_feedback_js(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "function copyHost(btn, text)" in result
        assert "Copied!" in result
        assert "copyHost(this," in result


class TestSortDirectionArrows:
    """Fix 3: CSS rules for sort direction indicators."""

    def test_sort_direction_css_rules(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "th.sort-asc::after" in result
        assert "th.sort-desc::after" in result
        assert "\\25B2" in result  # ▲
        assert "\\25BC" in result  # ▼


class TestReducedMotion:
    """Fix 4: prefers-reduced-motion media query."""

    def test_prefers_reduced_motion_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "@media (prefers-reduced-motion: reduce)" in result
        assert "animation-duration: 0.01ms !important" in result
        assert "transition-duration: 0.01ms !important" in result


class TestReproductionSteps:
    """Fix 5: reproduction steps rendered in vulnerabilities table."""

    def test_reproduction_steps_rendered(self):
        data = _data_from_session(_sample_session())
        data["vulnerabilities"] = [
            {
                "vulnerability_id": "abc123",
                "vuln_type": "sqli",
                "severity": "HIGH",
                "affected_surfaces": ["/login"],
                "scenarios": ["sqli_basic"],
                "confidence_aggregate": 0.9,
                "proofs": ["payload returned 200"],
                "reproduction_steps": [
                    "Send POST to /login",
                    "Set param user=1' OR '1'='1",
                    "Observe 200 response",
                ],
            }
        ]
        result = render_html(data)
        assert "3 reproduction steps" in result
        assert "<ol>" in result
        assert "Send POST to /login" in result
        assert "repro-row" in result

    def test_reproduction_steps_absent_when_empty(self):
        data = _data_from_session(_sample_session())
        data["vulnerabilities"] = [
            {
                "vulnerability_id": "abc123",
                "vuln_type": "sqli",
                "severity": "HIGH",
                "affected_surfaces": ["/login"],
                "scenarios": ["sqli_basic"],
                "confidence_aggregate": 0.9,
                "proofs": ["payload returned 200"],
                "reproduction_steps": [],
            }
        ]
        result = render_html(data)
        assert 'class="repro-row"' not in result
        assert "reproduction steps" not in result


class TestFilterChipAccessibility:
    """Fix 6: filter chips use <button> instead of <span>."""

    def test_filter_chips_are_buttons(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert '<button class="filter-chip' in result
        # Should NOT have span filter-chip
        assert '<span class="filter-chip' not in result

    def test_expand_collapse_are_buttons(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "Expand All</button>" in result
        assert "Collapse All</button>" in result


class TestKillChainCoverage:
    """Fix 7: kill chain shows ratio and percentage."""

    def test_kill_chain_coverage_percentage(self):
        s = _sample_session()
        data = _data_from_session(s)
        result = render_html(data)
        assert "% coverage" in result

    def test_kill_chain_shows_ratio(self):
        s = _sample_session()
        data = _data_from_session(s)
        result = render_html(data)
        # Should contain ratio like "1/5" or "0/10"
        assert 'class="kc-label">' in result
        # At least one phase should show "N/M" format
        import re
        assert re.search(r'class="kc-label">\d+/\d+<', result)


class TestContrastReadability:
    """Fix 8: improved contrast and minimum text size."""

    def test_fg_dim_contrast_value(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "#6d7a94" in result
        assert "#5a6580" not in result

    def test_text_xs_minimum(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "--text-xs: 0.65rem" in result


# ===== UX Batch 2 tests =====


def _data_with_vulns_and_repro():
    """Data with vulns that have repro-rows for sort testing."""
    data = _data_from_session(_sample_session())
    data["vulnerabilities"] = [
        {
            "vulnerability_id": "v1",
            "vuln_type": "sqli",
            "severity": "HIGH",
            "affected_surfaces": ["/login"],
            "scenarios": ["sqli_basic"],
            "confidence_aggregate": 0.9,
            "proofs": ["payload returned 200"],
            "reproduction_steps": ["Open /login", "Enter payload", "Observe response"],
        },
        {
            "vulnerability_id": "v2",
            "vuln_type": "xss",
            "severity": "MEDIUM",
            "affected_surfaces": ["/search"],
            "scenarios": ["xss_basic"],
            "confidence_aggregate": 0.7,
            "proofs": ["<script>alert(1)</script>"],
            "reproduction_steps": [],
        },
    ]
    return data


def _data_with_many_decisions(count=15):
    """Data with many decisions for show-more testing."""
    data = _data_from_session(_sample_session())
    data["decisions"] = [
        {
            "step": i,
            "plugin": f"plugin_{i}",
            "target": "test.example.com",
            "score": 0.5 + i * 0.01,
            "reasoning": f"reason {i}",
            "productive": i % 3 == 0,
            "new_entities": i,
            "duration": 1.0 + i * 0.1,
        }
        for i in range(1, count + 1)
    ]
    return data


class TestSortReproRows:
    """Fix 0: sort JS keeps repro-rows grouped with parent."""

    def test_sort_js_handles_repro_rows(self):
        data = _data_with_vulns_and_repro()
        result = render_html(data)
        assert "repro-row" in result
        # JS must check for repro-row class during sort
        assert "classList.contains('repro-row')" in result

    def test_sort_js_uses_group_approach(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        # Should use group-based sort, not flat row sort
        assert "groups.sort" in result or "groups.push" in result
        assert "groups.forEach" in result


class TestPrintStylesheet:
    """Fix 1: print stylesheet hides controls and enables readability."""

    def test_print_hides_interactive_controls(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "@media print" in result
        assert ".filter-bar" in result
        assert ".search-box" in result
        assert ".export-json-btn" in result
        assert ".decisions-show-more" in result
        # Verify they are hidden in print
        assert "display: none !important" in result

    def test_print_page_break_avoid(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "page-break-inside: avoid" in result

    def test_print_evidence_no_max_height(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "max-height: none !important" in result
        assert "overflow: visible !important" in result


class TestFocusVisible:
    """Fix 2: global :focus-visible style."""

    def test_focus_visible_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "*:focus-visible" in result
        assert "outline: 2px solid var(--neon-green)" in result


class TestMainLandmark:
    """Fix 3: semantic <main> element."""

    def test_main_landmark_element(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert '<main class="main">' in result
        assert "</main>" in result

    def test_no_div_main(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert '<div class="main">' not in result


class TestSkipLink:
    """Fix 4: skip-to-content link."""

    def test_skip_link_present(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'class="skip-link"' in result
        assert 'href="#command-center"' in result
        assert "Skip to content" in result

    def test_skip_link_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".skip-link" in result
        assert ".skip-link:focus" in result


class TestSeverityBarTooltip:
    """Fix 5: severity bar segment tooltips."""

    def test_severity_bar_segment_tooltip(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        # Should have title attributes on severity bar segments
        assert 'class="seg" title="' in result


class TestProgressBarAria:
    """Fix 6: progress bar ARIA attributes."""

    def test_progress_bar_role(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'role="progressbar"' in result

    def test_progress_bar_aria_values(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'aria-valuenow="10"' in result
        assert 'aria-valuemax="50"' in result


class TestFilterChipAriaPressed:
    """Fix 7: filter chip aria-pressed attribute."""

    def test_filter_chip_aria_pressed(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'aria-pressed="true"' in result

    def test_toggle_filter_sets_aria_pressed(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "setAttribute('aria-pressed'" in result


class TestExportJsonButton:
    """Fix 8: export JSON button in footer."""

    def test_export_json_button_present(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'class="export-json-btn"' in result
        assert "Export JSON" in result

    def test_download_json_js(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "function downloadJson()" in result
        assert "basilisk-report.json" in result
        assert "JSON.stringify(DATA" in result


class TestDecisionsShowMore:
    """Fix 9: decisions timeline show-more pagination."""

    def test_decisions_show_more_absent_when_few(self):
        data = _data_from_session(_sample_session())
        # Default sample has only 2 decisions
        result = render_html(data)
        assert '<button class="decisions-show-more"' not in result
        assert 'id="decisions-overflow"' not in result

    def test_decisions_grouped_when_many(self):
        data = _data_with_many_decisions(15)
        result = render_html(data)
        # Productive/unproductive grouping replaces old overflow pagination
        assert 'id="decisions-unproductive"' in result
        assert "unproductive decision" in result

    def test_decisions_toggle_js(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "function toggleDecisions(btn)" in result


# ===== UX Batch 3 tests =====


class TestTableRowStriping:
    """Fix 1: table row striping CSS for scanability."""

    def test_table_row_striping_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".perf-table tbody tr:nth-child(even) td" in result
        assert ".training-table tbody tr:nth-child(even) td" in result
        assert ".nm-compact-table tbody tr:nth-child(even) td" in result
        assert "rgba(0,255,106,0.015)" in result


class TestSearchAriaLabel:
    """Fix 2: search inputs have aria-label."""

    def test_findings_search_aria_label(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'aria-label="Search findings"' in result

    def test_network_map_search_aria_label(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert 'aria-label="Filter hosts"' in result


class TestTableCaptionAndScope:
    """Fix 3: tables have <caption> and th scope=col."""

    def test_vuln_table_caption_and_scope(self):
        data = _data_from_session(_sample_session())
        # Ensure vulns table exists
        data["vulnerabilities"] = [
            {
                "vulnerability_id": "v1",
                "vuln_type": "sqli",
                "severity": "HIGH",
                "affected_surfaces": ["/login"],
                "scenarios": ["sqli_basic"],
                "confidence_aggregate": 0.9,
                "proofs": ["payload"],
                "reproduction_steps": [],
            }
        ]
        result = render_html(data)
        assert "<caption>Deduplicated vulnerabilities</caption>" in result
        assert 'scope="col"' in result

    def test_plugin_table_caption_and_scope(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "<caption>Plugin execution performance</caption>" in result
        # Check scope on plugin table headers
        assert 'scope="col">Plugin</th>' in result


class TestSidebarNavAriaLabel:
    """Fix 4: sidebar nav has aria-label."""

    def test_sidebar_nav_aria_label(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'aria-label="Report sections"' in result


class TestDeepLinkableFindings:
    """Fix 5: finding cards have id for deep linking."""

    def test_finding_card_has_id(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'id="finding-0"' in result

    def test_finding_ids_sequential(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        # Sample collector has 2 findings
        assert 'id="finding-0"' in result
        assert 'id="finding-1"' in result


class TestGrowthBarTitle:
    """Fix 6: KG growth bars have title attribute for screen readers."""

    def test_growth_bar_has_title(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'class="growth-bar"' in result
        # Check that growth bar has title attribute
        assert 'title="Step 1: +10 entities"' in result


class TestSurfaceBarFillTitle:
    """Fix 7: surface bar fills have title attribute."""

    def test_surface_bar_fill_has_title(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "surface-bar-fill" in result
        # Check that at least one surface-bar-fill has a title
        import re
        assert re.search(r'class="surface-bar-fill"[^>]*title="', result)


class TestObserverAriaCurrent:
    """Fix 8: IntersectionObserver sets aria-current on active sidebar link."""

    def test_observer_sets_aria_current(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "setAttribute('aria-current'" in result

    def test_observer_removes_aria_current(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "removeAttribute('aria-current')" in result


class TestEvidenceOverflowGradient:
    """Fix 9: evidence overflow gradient CSS cue."""

    def test_evidence_overflow_gradient_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".evidence-block.overflows:not(.expanded)::after" in result
        assert "linear-gradient(transparent, var(--bg))" in result


class TestTrainingTableCaptionAndScope:
    """Fix 3 cont: training table has caption and scope."""

    def test_training_table_caption(self):
        s = _sample_session()
        s.training_data = {
            "profile_name": "test_app",
            "coverage": 0.85,
            "verification_rate": 0.7,
            "passed": True,
            "expected_findings": [
                {"title": "SQLi", "severity": "high",
                 "discovered": True, "verified": True, "discovery_step": 3},
            ],
        }
        data = _data_from_session(s)
        result = render_html(data)
        assert "<caption>Expected findings validation</caption>" in result
        assert 'scope="col">Expected Finding</th>' in result


class TestCompactTableCaptionAndScope:
    """Fix 3 cont: compact network map table has caption and scope."""

    def test_compact_table_caption(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        assert "<caption>Network hosts (compact view)</caption>" in result
        assert 'scope="col">Host</th>' in result


class TestEndpointClickableLinks:
    """Endpoints rendered as clickable links with correct base URL."""

    def test_endpoints_are_links(self):
        data = _data_from_session(_session_with_topology())
        result = render_html(data)
        # /login should be a clickable link
        assert 'href="https://test.example.com/login"' in result
        assert 'target="_blank"' in result

    def test_endpoint_base_url_https(self):
        from basilisk.reporting.renderer import _endpoint_base_url
        svcs = [{"port": 443, "service": "https"}]
        assert _endpoint_base_url("host.com", svcs) == "https://host.com"

    def test_endpoint_base_url_http_nonstandard_port(self):
        from basilisk.reporting.renderer import _endpoint_base_url
        svcs = [{"port": 8080, "service": "http"}]
        assert _endpoint_base_url("host.com", svcs) == "http://host.com:8080"

    def test_endpoint_base_url_prefers_https(self):
        from basilisk.reporting.renderer import _endpoint_base_url
        svcs = [
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"},
        ]
        assert _endpoint_base_url("host.com", svcs) == "https://host.com"

    def test_endpoint_base_url_fallback(self):
        from basilisk.reporting.renderer import _endpoint_base_url
        assert _endpoint_base_url("host.com", []) == "https://host.com"

    def test_endpoint_base_url_https_alt_port(self):
        from basilisk.reporting.renderer import _endpoint_base_url
        svcs = [{"port": 8443, "service": "https-alt"}]
        assert _endpoint_base_url("host.com", svcs) == "https://host.com:8443"


class TestEndpointTree:
    """Endpoints grouped into collapsible tree by path prefix."""

    def test_grouped_by_prefix(self):
        from basilisk.reporting.renderer import _endpoint_tree_html
        eps = ["/api/v1/users", "/api/v1/orders", "/api/v2/items",
               "/api/v2/carts", "/login"]
        result = _endpoint_tree_html(eps, "https://host.com")
        assert "/api/ (4)" in result
        assert "nm-endpoints-toggle" in result

    def test_interesting_group_auto_expanded(self):
        from basilisk.reporting.renderer import _endpoint_tree_html
        eps = ["/api/v1/a", "/api/v1/b", "/api/v1/c", "/api/v1/d",
               "/static/a", "/static/b", "/static/c", "/static/d"]
        result = _endpoint_tree_html(eps, "https://host.com")
        # api is interesting → open
        assert '<details class="nm-endpoints-toggle" open>' in result
        # static is not interesting → not open
        assert '/static/ (4)</summary>' in result

    def test_is_interesting_endpoint(self):
        from basilisk.reporting.renderer import _is_interesting_endpoint
        assert _is_interesting_endpoint("/api/v1/users") is True
        assert _is_interesting_endpoint("/swagger.json") is True
        assert _is_interesting_endpoint("/.env") is True
        assert _is_interesting_endpoint("/admin/dashboard") is True
        assert _is_interesting_endpoint("/static/logo.png") is False


# ===== UX Batch 4 tests =====


class TestScrollToTopFab:
    """Fix 1: scroll-to-top floating action button."""

    def test_scroll_top_button_present(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'class="scroll-top"' in result
        assert 'aria-label="Scroll to top"' in result

    def test_scroll_top_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".scroll-top {" in result
        assert ".scroll-top.show" in result

    def test_scroll_top_js(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "scroll-top" in result
        assert "scrollY > 300" in result

    def test_scroll_top_hidden_in_print(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".scroll-top" in result
        # scroll-top in print hidden list
        assert "scroll-top {" in result


class TestFindingsSortControls:
    """Fix 2: findings sort dropdown and data attributes."""

    def test_sort_select_present(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'class="sort-select"' in result
        assert 'aria-label="Sort findings"' in result

    def test_sort_options(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "Discovery Order" in result
        assert "Severity" in result
        assert "Confidence" in result
        assert "Host" in result

    def test_finding_card_data_attributes(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'data-conf="' in result
        assert 'data-host="' in result
        assert 'data-step="' in result

    def test_sort_findings_js(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "function sortFindings(criteria)" in result

    def test_sort_by_severity_logic_in_js(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "criteria === 'severity'" in result
        assert "criteria === 'confidence'" in result
        assert "criteria === 'host'" in result


class TestFindingsVisibleCounter:
    """Fix 3: visible findings counter in filter bar."""

    def test_findings_stats_present(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert 'class="findings-stats"' in result
        assert 'id="findings-visible"' in result

    def test_counter_shows_total(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        total = len(data["findings"])
        assert f"of {total}</span>" in result

    def test_apply_filters_updates_counter(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "getElementById('findings-visible')" in result
        assert "counter.textContent = visible" in result


class TestNetworkMapEmptyHosts:
    """Fix 4: hide empty hosts in collapsed section."""

    def test_empty_hosts_collapsed(self):
        s = _sample_session()
        data = _data_from_session(s)
        data["topology"] = {
            "rich.example.com": {
                "services": [{"port": 80, "service": "http", "protocol": "tcp"}],
                "endpoints": [],
                "technologies": [],
            },
            "empty1.example.com": {
                "services": [],
                "endpoints": [],
                "technologies": [],
            },
            "empty2.example.com": {
                "services": [],
                "endpoints": [],
                "technologies": [],
                "is_subdomain": True,
                "parent": "rich.example.com",
            },
        }
        result = render_html(data)
        assert "nm-empty-section" in result
        assert "nm-empty-chip" in result
        assert "2 hosts with no data" in result

    def test_rich_hosts_in_grid(self):
        s = _sample_session()
        data = _data_from_session(s)
        data["topology"] = {
            "rich.example.com": {
                "services": [{"port": 443, "service": "https", "protocol": "tcp"}],
                "endpoints": ["/api"],
                "technologies": [{"name": "nginx"}],
            },
        }
        result = render_html(data)
        assert "nm-grid" in result
        assert "rich.example.com" in result
        # No empty section element when all hosts are rich
        assert '<details class="nm-empty-section">' not in result

    def test_empty_hosts_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".nm-empty-section" in result
        assert ".nm-empty-grid" in result
        assert ".nm-empty-chip" in result


class TestDecisionsGrouping:
    """Fix 5: productive/unproductive decision grouping."""

    def test_productive_shown_first(self):
        data = _data_with_many_decisions(6)
        result = render_html(data)
        # Productive decisions should appear before unproductive section
        prod_pos = result.find("timeline-item productive")
        unprod_section = result.find('id="decisions-unproductive"')
        assert prod_pos < unprod_section

    def test_unproductive_in_details(self):
        data = _data_with_many_decisions(6)
        result = render_html(data)
        assert 'id="decisions-unproductive"' in result
        assert "unproductive decision" in result

    def test_productive_green_border_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".timeline-item.productive {" in result
        assert "border-left: 3px solid var(--neon-green)" in result

    def test_unproductive_dimmed_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".timeline-item.unproductive {" in result
        assert "opacity: 0.75" in result

    def test_no_grouping_when_empty(self):
        data = _data_from_session(ScanSession("empty.com"))
        result = render_html(data)
        assert "No decisions yet" in result
        assert "decisions-unproductive" not in result


class TestStickyFilterBar:
    """Fix 6: sticky findings filter bar."""

    def test_sticky_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "position: sticky" in result
        assert "z-index: 50" in result


class TestEvidenceHeaderHighlighting:
    """Fix 7: HTTP header highlighting in evidence blocks."""

    def test_ev_status_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".ev-status" in result
        assert ".ev-header-name" in result

    def test_header_highlight_js(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "ev-status" in result
        assert "ev-header-name" in result
        # JS regex uses escaped slash
        assert "HTTP\\/" in result


class TestKgGrowthBarAnimation:
    """Fix 8: KG growth bar CSS animation."""

    def test_bar_grow_keyframes(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "@keyframes bar-grow" in result
        assert "scaleY(0)" in result

    def test_growth_bar_animation_applied(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "animation: bar-grow" in result

    def test_growth_bar_staggered_delay(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".growth-bar:nth-child(2)" in result
        assert "animation-delay: 0.03s" in result


# ---------------------------------------------------------------------------
# Information Enrichment Batch Tests
# ---------------------------------------------------------------------------


def _enriched_session() -> ScanSession:
    """Build session with rich data for enrichment tests."""
    s = ScanSession("app.example.com", max_steps=50)
    s.step = 20
    s.gap_count = 15

    # Findings
    s.graph.add_entity(Entity.finding(
        host="app.example.com", title="SQL Injection", severity="high",
        step=5, evidence="payload", confidence=0.9, verified=True,
    ))
    s.graph.add_entity(Entity.finding(
        host="app.example.com", title="XSS Reflected", severity="medium",
        step=8, confidence=0.7,
    ))
    s.graph.add_entity(Entity.finding(
        host="api.example.com", title="Open Redirect", severity="low",
        step=12, confidence=0.6,
    ))
    s.graph.add_entity(Entity.finding(
        host="api.example.com", title="Missing HSTS", severity="info",
        step=3,
    ))
    s.graph.add_entity(Entity.finding(
        host="admin.example.com", title="CSRF Token Missing", severity="high",
        step=15, evidence="no token", confidence=0.85,
    ))

    # Entities for counts (host=10, service=30, endpoint=120, technology=20)
    for i in range(10):
        s.graph.add_entity(Entity.host(f"host{i}.example.com"))
    for i in range(30):
        s.graph.add_entity(Entity.service(f"host{i % 10}.example.com", port=80 + i))
    for i in range(120):
        s.graph.add_entity(Entity.endpoint(f"host{i % 10}.example.com", f"/p{i}"))
    for i in range(20):
        s.graph.add_entity(Entity.technology(f"host{i % 10}.example.com", f"tech{i}"))

    s.decisions = [
        SessionDecision(
            step=1, plugin="port_scan", target="app.example.com",
            score=0.95, reasoning="initial", duration=1.5,
        ),
        SessionDecision(
            step=5, plugin="sqli_basic", target="app.example.com",
            score=0.87, reasoning="gap fill", productive=True,
            new_entities=10, duration=3.2,
        ),
        SessionDecision(
            step=8, plugin="xss_scanner", target="app.example.com",
            score=0.75, reasoning="vuln scan", productive=True,
            new_entities=5, duration=2.1,
        ),
        SessionDecision(
            step=12, plugin="redirect_check", target="api.example.com",
            score=0.6, reasoning="low priority", productive=True,
            new_entities=2, duration=0.8,
        ),
    ]
    s.plugins = [
        SessionPlugin(name="port_scan", target="app.example.com",
                      duration=1.5, findings_count=0, step=1),
        SessionPlugin(name="sqli_basic", target="app.example.com",
                      duration=3.2, findings_count=2, step=5),
        SessionPlugin(name="xss_scanner", target="app.example.com",
                      duration=2.1, findings_count=1, step=8),
        SessionPlugin(name="redirect_check", target="api.example.com",
                      duration=0.8, findings_count=1, step=12),
    ]
    s.step_history = [
        StepSnapshot(step=1, entities=20, relations=10, gaps=25, entities_gained=20),
        StepSnapshot(step=5, entities=100, relations=80, gaps=30, entities_gained=40),
        StepSnapshot(step=10, entities=300, relations=250, gaps=20, entities_gained=30),
        StepSnapshot(step=15, entities=420, relations=350, gaps=18, entities_gained=15),
        StepSnapshot(step=20, entities=500, relations=400, gaps=15, entities_gained=8),
    ]
    s.hypotheses_confirmed = 5
    s.hypotheses_rejected = 1
    s.beliefs_strengthened = 8
    s.beliefs_weakened = 2
    s.reasoning_events = [
        ReasoningEvent(
            event_type="hypothesis_confirmed",
            data={"hypothesis": "Target likely uses django"},
            step=7,
        ),
        ReasoningEvent(
            event_type="hypothesis_rejected",
            data={"hypothesis": "WAF is CloudFlare", "reason": "no cf headers"},
            step=10,
        ),
        ReasoningEvent(
            event_type="belief_strengthened",
            data={"hypothesis": "SQL injection present in auth"},
            step=12,
        ),
    ]
    return s


class TestImp5RiskScoreCommandCenter:
    """Imp 5: Risk score card in command center."""

    def test_risk_score_in_metrics_grid(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "Risk Score" in result
        # enriched session has 2 HIGH + 1 MEDIUM + 1 LOW + 1 INFO
        # = 2*2.5 + 1*1.0 + 1*0.3 + 1*0.0 = 6.3
        assert "6.3" in result

    def test_risk_color_high(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        # 6.3 → risk-high (6-8 range)
        assert "risk-high" in result

    def test_risk_color_low(self):
        s = ScanSession("safe.com")
        # No findings → risk 0.0
        data = _data_from_session(s)
        result = render_html(data)
        assert "risk-low" in result

    def test_risk_color_critical(self):
        s = ScanSession("danger.com")
        # 4 CRITICAL findings → 4*4.0 = 16 → capped at 10.0 → risk-critical
        for i in range(4):
            s.graph.add_entity(Entity.finding(
                host="danger.com", title=f"Crit{i}", severity="critical",
            ))
        data = _data_from_session(s)
        result = render_html(data)
        assert "risk-critical" in result

    def test_risk_css_classes_present(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert ".risk-low" in result
        assert ".risk-medium" in result
        assert ".risk-high" in result
        assert ".risk-critical" in result


class TestImp8StepHistorySummary:
    """Imp 8: Step history multi-metric summary text."""

    def test_growth_summary_present(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "growth-summary" in result

    def test_summary_shows_entity_progression(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "20 entities" in result  # first step
        assert "500 entities" in result  # last step
        assert "+480" in result  # delta

    def test_summary_shows_relations_and_gaps(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "Relations:" in result
        assert "Remaining gaps:" in result


class TestImp1GapTrajectory:
    """Imp 1: Gap trajectory SVG overlay in KG Growth."""

    def test_gap_trajectory_svg(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "growth-gap-line" in result
        assert "<polyline" in result
        assert 'stroke="var(--neon-orange)"' in result

    def test_gap_label_shows_count(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "gap-label" in result
        assert "15 remaining" in result

    def test_gap_css_present(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert ".growth-gap-line" in result
        assert ".gap-label" in result


class TestImp2DecisionStatsBanner:
    """Imp 2: Decision summary stats banner."""

    def test_decision_stats_present(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "decision-stats" in result

    def test_productive_percentage(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        # 3 out of 4 productive = 75%
        assert "75%" in result

    def test_avg_score_shown(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "Avg Score" in result

    def test_entities_gained_total(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "Entities Gained" in result

    def test_total_duration_shown(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "Total Duration" in result

    def test_top_plugin_shown(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "Top Plugin" in result

    def test_no_stats_when_empty(self):
        data = _data_from_session(ScanSession("empty.com"))
        result = render_html(data)
        # CSS definition exists, but no HTML metrics-grid with decision-stats
        assert 'class="metrics-grid decision-stats"' not in result


class TestImp3PluginEfficiency:
    """Imp 3: Plugin efficiency column and summary row."""

    def test_efficiency_column_header(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "Eff." in result

    def test_efficiency_values(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        # sqli_basic: 2 findings / (3.2s / 60) = 37.5 findings/min
        assert "37.5" in result

    def test_summary_row_present(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "perf-summary" in result
        assert "Total" in result

    def test_top_producer_highlighted(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "perf-top" in result


class TestImp7ReasoningHypothesisDetail:
    """Imp 7: Hypothesis text shown in reasoning events."""

    def test_hypothesis_text_displayed(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "Target likely uses django" in result

    def test_hypothesis_css_class(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "re-hypothesis" in result

    def test_rejected_hypothesis_shown(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "WAF is CloudFlare" in result

    def test_extra_data_still_shown(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        # "reason: no cf headers" should be in detail
        assert "no cf headers" in result


class TestImp4FindingsByHost:
    """Imp 4: Findings-by-host top 5 horizontal bars."""

    def test_host_bar_section(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "findings-host-bar" in result
        assert "fhb-title" in result

    def test_top_hosts_shown(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "app.example.com" in result
        assert "api.example.com" in result

    def test_host_counts_shown(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "fhb-count" in result

    def test_filter_by_host_js(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "filterByHost" in result

    def test_no_host_bar_when_empty(self):
        data = _data_from_session(ScanSession("empty.com"))
        result = render_html(data)
        assert 'class="findings-host-bar"' not in result


class TestImp6SeverityTimeline:
    """Imp 6: Severity discovery timeline dots."""

    def test_severity_timeline_present(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "sev-timeline" in result

    def test_severity_dots(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "sev-dot" in result

    def test_timeline_label(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "Severity Timeline" in result

    def test_no_timeline_when_empty(self):
        data = _data_from_session(ScanSession("empty.com"))
        result = render_html(data)
        assert 'class="sev-timeline"' not in result

    def test_dot_colors_use_severity_vars(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        assert "var(--high)" in result
        assert "var(--medium)" in result


# ---------------------------------------------------------------------------
# Batch 2 enrichment test fixture
# ---------------------------------------------------------------------------

def _batch2_session() -> ScanSession:
    """Build session with rich data for batch 2 enrichment tests."""
    s = ScanSession("app.example.com", max_steps=50)
    s.step = 20
    s.gap_count = 15

    # Findings
    s.graph.add_entity(Entity.finding(
        host="app.example.com", title="SQL Injection", severity="high",
        step=5, evidence="payload", confidence=0.9, verified=True,
    ))
    s.graph.add_entity(Entity.finding(
        host="app.example.com", title="XSS Reflected", severity="medium",
        step=8, confidence=0.7,
    ))
    s.graph.add_entity(Entity.finding(
        host="api.example.com", title="Open Redirect", severity="low",
        step=12, confidence=0.6,
    ))
    s.graph.add_entity(Entity.finding(
        host="api.example.com", title="Missing HSTS", severity="info",
        step=3,
    ))
    s.graph.add_entity(Entity.finding(
        host="admin.example.com", title="CSRF Token Missing", severity="high",
        step=15, evidence="no token", confidence=0.85,
    ))

    # Topology: hosts with services and subdomain relations
    host_app = Entity.host("app.example.com")
    s.graph.add_entity(host_app)
    svc_app = Entity.service("app.example.com", port=443, protocol="tcp", service="https")
    s.graph.add_entity(svc_app)
    s.graph.add_relation(Relation(
        source_id=host_app.id, target_id=svc_app.id, type=RelationType.EXPOSES,
    ))

    host_api = Entity.host("api.example.com", type="subdomain",
                           parent="app.example.com")
    s.graph.add_entity(host_api)
    s.graph.add_relation(Relation(
        source_id=host_app.id, target_id=host_api.id, type=RelationType.PARENT_OF,
    ))
    svc_api = Entity.service("api.example.com", port=443, protocol="tcp", service="https")
    s.graph.add_entity(svc_api)
    s.graph.add_relation(Relation(
        source_id=host_api.id, target_id=svc_api.id, type=RelationType.EXPOSES,
    ))

    host_admin = Entity.host("admin.example.com", type="subdomain",
                             parent="app.example.com")
    s.graph.add_entity(host_admin)
    s.graph.add_relation(Relation(
        source_id=host_app.id, target_id=host_admin.id, type=RelationType.PARENT_OF,
    ))

    host_empty = Entity.host("empty.example.com", type="subdomain",
                             parent="app.example.com")
    s.graph.add_entity(host_empty)
    s.graph.add_relation(Relation(
        source_id=host_app.id, target_id=host_empty.id, type=RelationType.PARENT_OF,
    ))

    # Additional entities for richer counts (spread across existing hosts)
    hosts = ["app.example.com", "api.example.com", "admin.example.com",
             "empty.example.com"]
    for i in range(30):
        s.graph.add_entity(Entity.service(hosts[i % 4], port=80 + i))
    for i in range(120):
        s.graph.add_entity(Entity.endpoint(hosts[i % 4], f"/p{i}"))
    for i in range(20):
        s.graph.add_entity(Entity.technology(hosts[i % 4], f"tech{i}"))

    s.decisions = [
        SessionDecision(
            step=1, plugin="port_scan", target="app.example.com",
            score=0.95,
            reasoning="Gap: Host app.example.com has no known services. Selected port_scan",
            duration=1.5,
        ),
        SessionDecision(
            step=5, plugin="sqli_basic", target="app.example.com",
            score=0.87,
            reasoning="Gap: Host app.example.com has no vulnerability testing. "
                      "Selected sqli_basic",
            productive=True, new_entities=10, duration=3.2,
        ),
        SessionDecision(
            step=8, plugin="xss_scanner", target="app.example.com",
            score=0.75,
            reasoning="Gap: Host app.example.com has no endpoints. Selected xss_scanner",
            productive=True, new_entities=5, duration=2.1,
        ),
        SessionDecision(
            step=12, plugin="redirect_check", target="api.example.com",
            score=0.6,
            reasoning="Gap: Host api.example.com has no known services. "
                      "Selected redirect_check",
            productive=True, new_entities=2, duration=0.8,
        ),
    ]
    s.plugins = [
        SessionPlugin(name="port_scan", target="app.example.com",
                      duration=1.5, findings_count=0, step=1),
        SessionPlugin(name="sqli_basic", target="app.example.com",
                      duration=3.2, findings_count=2, step=5),
        SessionPlugin(name="xss_scanner", target="app.example.com",
                      duration=2.1, findings_count=1, step=8),
        SessionPlugin(name="redirect_check", target="api.example.com",
                      duration=0.8, findings_count=1, step=12),
        SessionPlugin(name="shodan_lookup", target="app.example.com",
                      duration=120.0, findings_count=0, step=2),
    ]
    s.step_history = [
        StepSnapshot(step=1, entities=20, relations=10, gaps=25, entities_gained=20),
        StepSnapshot(step=5, entities=100, relations=80, gaps=30, entities_gained=40),
        StepSnapshot(step=10, entities=300, relations=250, gaps=20, entities_gained=30),
        StepSnapshot(step=15, entities=420, relations=350, gaps=18, entities_gained=15),
        StepSnapshot(step=20, entities=500, relations=400, gaps=15, entities_gained=1),
    ]
    s.hypotheses_confirmed = 5
    s.hypotheses_rejected = 1
    s.beliefs_strengthened = 8
    s.beliefs_weakened = 2
    s.reasoning_events = [
        ReasoningEvent(
            event_type="hypothesis_confirmed",
            data={"hypothesis": "Target likely uses django"},
            step=7,
        ),
        ReasoningEvent(
            event_type="hypothesis_rejected",
            data={"hypothesis": "WAF is CloudFlare", "reason": "no cf headers"},
            step=10,
        ),
        ReasoningEvent(
            event_type="belief_strengthened",
            data={"statement": "SQL injection present in auth"},
            step=12,
        ),
        ReasoningEvent(
            event_type="hypothesis_confirmed",
            data={"statement": "Shodan reveals open redis port",
                   "hypothesis_id": "hyp-123"},
            step=14,
        ),
    ]
    return s


# ---------------------------------------------------------------------------
# Batch 2: Bugfix — Hypothesis key fallback
# ---------------------------------------------------------------------------

class TestBugfixHypothesisKeyFallback:
    """Bugfix: hypothesis key fallback to statement."""

    def test_statement_key_displayed(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "SQL injection present in auth" in result

    def test_hypothesis_id_excluded(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        # hypothesis_id should not appear as visible detail text in reasoning events
        assert "hypothesis_id: hyp-123" not in result

    def test_both_keys_work(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        # "hypothesis" key event
        assert "Target likely uses django" in result
        # "statement" key event
        assert "Shodan reveals open redis port" in result


# ---------------------------------------------------------------------------
# Batch 2 Imp 1: Cumulative Findings Curve
# ---------------------------------------------------------------------------

class TestB2Imp1CumFindings:
    """Imp 1: Cumulative findings curve SVG."""

    def test_cum_findings_present(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "cum-findings" in result

    def test_cum_findings_svg_lines(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "<line" in result

    def test_cum_findings_dots(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        # Circle dots at discovery points
        assert 'class="cum-findings"' in result
        # SVG circles
        assert "<circle" in result

    def test_cum_label_shows_total(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "Cumulative Findings (5 total)" in result

    def test_no_cum_findings_when_empty(self):
        data = _data_from_session(ScanSession("empty.com"))
        result = render_html(data)
        assert 'class="cum-findings"' not in result

    def test_cum_findings_css(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert ".cum-findings" in result
        assert ".cum-label" in result


# ---------------------------------------------------------------------------
# Batch 2 Imp 2: Kill Chain Plugin Drill-down
# ---------------------------------------------------------------------------

class TestB2Imp2KillChainDrilldown:
    """Imp 2: Kill chain phase details with plugin list."""

    def test_kc_phase_is_details(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert '<details class="kc-phase' in result

    def test_kc_plugins_listed(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "kc-plugins" in result

    def test_kc_plugin_executed_class(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert 'kc-plugin executed' in result

    def test_kc_plugin_skipped_class(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert 'kc-plugin skipped' in result

    def test_kc_plugins_css(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert ".kc-plugins" in result
        assert ".kc-plugin.executed" in result
        assert ".kc-plugin.skipped" in result


# ---------------------------------------------------------------------------
# Batch 2 Imp 3: Decision Gap Type Distribution
# ---------------------------------------------------------------------------

class TestB2Imp3GapDistribution:
    """Imp 3: Gap type distribution bars in decisions."""

    def test_gap_dist_present(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "gap-dist" in result

    def test_gap_dist_shows_types(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "No Services" in result

    def test_gap_dist_bar_rows(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "gap-bar-row" in result
        assert "gap-bar-fill" in result

    def test_gap_dist_title(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "Gap type distribution" in result

    def test_no_gap_dist_when_no_gap_reasoning(self):
        data = _data_from_session(_enriched_session())
        result = render_html(data)
        # enriched session has non-Gap reasoning, so no gap distribution section
        assert "Gap type distribution</div>" not in result

    def test_gap_dist_css(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert ".gap-dist" in result
        assert ".gap-bar-row" in result
        assert ".gap-bar-count" in result


# ---------------------------------------------------------------------------
# Batch 2 Imp 4: Plugin Findings by Severity
# ---------------------------------------------------------------------------

class TestB2Imp4PluginSeverity:
    """Imp 4: Severity column in plugin performance table."""

    def test_sev_column_header(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert ">Sev.<" in result

    def test_sev_badges_present(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        # sqli_basic at step=5 produces 2 findings (HIGH + MEDIUM via step match)
        assert "psev-dot" in result

    def test_psev_high_badge(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "psev-HIGH" in result

    def test_plugin_sev_cell_class(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "plugin-sev-cell" in result

    def test_psev_css(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert ".psev-dot" in result
        assert ".psev-dot.psev-HIGH" in result


# ---------------------------------------------------------------------------
# Batch 2 Imp 5: Entity Gain Velocity SVG
# ---------------------------------------------------------------------------

class TestB2Imp5GainVelocity:
    """Imp 5: Entity gain velocity SVG with markers."""

    def test_gain_velocity_present(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "gain-velocity" in result

    def test_gain_velocity_polyline(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        # Two polylines total — gap + velocity
        assert 'stroke="var(--neon-cyan)"' in result

    def test_peak_marker_present(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        # Peak is step 5 with 40 gained
        assert 'fill="var(--neon-green)"' in result

    def test_saturation_marker_present(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert 'fill="var(--neon-orange)"' in result

    def test_gain_label_peak_value(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "peak: +40" in result

    def test_gain_velocity_css(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert ".gain-velocity" in result
        assert ".gain-label" in result


# ---------------------------------------------------------------------------
# Batch 2 Imp 6: Subdomain Discovery Stats
# ---------------------------------------------------------------------------

class TestB2Imp6SubdomainStats:
    """Imp 6: Subdomain discovery stats in attack surface."""

    def test_subdomain_summary_present(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "subdomain-summary" in result

    def test_root_count(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        # 1 root (app.example.com)
        assert ">1</span> root hosts" in result

    def test_subdomain_count(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        # 3 subdomains
        assert ">3</span> subdomains" in result

    def test_examined_percentage(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "examined" in result
        assert "sub-explored" in result

    def test_no_subdomain_without_topology(self):
        data = _data_from_session(ScanSession("empty.com"))
        result = render_html(data)
        assert 'class="subdomain-summary"' not in result

    def test_subdomain_css(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert ".subdomain-summary" in result
        assert ".sub-stat" in result


# ---------------------------------------------------------------------------
# Batch 2 Imp 7: Hypothesis Category Breakdown
# ---------------------------------------------------------------------------

class TestB2Imp7HypothesisCategories:
    """Imp 7: Hypothesis category groups in reasoning."""

    def test_hyp_categories_present(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "hyp-categories" in result

    def test_framework_detection_group(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "Framework Detection" in result

    def test_external_intelligence_group(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "External Intelligence" in result

    def test_confirmed_class(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert 'hyp-cat-item confirmed' in result

    def test_rejected_class(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert 'hyp-cat-item rejected' in result

    def test_cat_count_badge(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "hyp-cat-count" in result

    def test_hyp_categories_css(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert ".hyp-categories" in result
        assert ".hyp-cat-group" in result
        assert ".hyp-cat-item.confirmed" in result
        assert ".hyp-cat-item.rejected" in result


# ---------------------------------------------------------------------------
# Batch 2 Imp 8: Execution Cost Distribution
# ---------------------------------------------------------------------------

class TestB2Imp8CostDistribution:
    """Imp 8: Execution cost distribution stacked bar."""

    def test_cost_dist_present(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "cost-dist" in result

    def test_cost_dist_bar(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "cost-dist-bar" in result
        assert "cost-seg" in result

    def test_cost_dist_legend(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "cost-dist-legend" in result
        assert "cost-legend-item" in result

    def test_cost_dist_title(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "Runtime cost distribution" in result

    def test_cost_outlier_warning(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        # shodan_lookup is 120s out of ~127.6s total → >50%
        assert "cost-outlier" in result
        assert "shodan_lookup" in result

    def test_cost_dist_css(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert ".cost-dist" in result
        assert ".cost-seg" in result
        assert ".cost-outlier" in result


# ---------------------------------------------------------------------------
# Design Polish Batch 3
# ---------------------------------------------------------------------------


def _batch3_training_session() -> ScanSession:
    """Build session with training data for batch 3 tests."""
    s = ScanSession("train.example.com", max_steps=30)
    s.step = 10

    s.graph.add_entity(Entity.finding(
        host="train.example.com", title="SQLi in /api", severity="high",
        step=5, evidence="1=1", confidence=0.9, verified=True,
    ))

    s.step_history = [
        StepSnapshot(step=1, entities=10, relations=5, gaps=8, entities_gained=10),
        StepSnapshot(step=5, entities=30, relations=15, gaps=4, entities_gained=15),
        StepSnapshot(step=10, entities=50, relations=25, gaps=2, entities_gained=5),
    ]
    s.training_data = {
        "profile_name": "webapp_basic",
        "coverage": 0.80,
        "verification_rate": 0.60,
        "passed": True,
        "expected_findings": [
            {"title": "SQL Injection", "severity": "HIGH",
             "discovered": True, "verified": True, "discovery_step": 5},
            {"title": "XSS Reflected", "severity": "MEDIUM",
             "discovered": False, "verified": False, "discovery_step": None},
            {"title": "Open Redirect", "severity": "LOW",
             "discovered": True, "verified": False, "discovery_step": 8},
        ],
    }
    return s


class TestUnifiedCardHover:
    """Imp 1: Consistent card hover effects."""

    def test_unified_transition_rule(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".metric-card, .surface-stat, .reasoning-stat, .kc-phase" in result

    def test_hover_translatey(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "translateY(-2px)" in result

    def test_reasoning_stat_hover(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".reasoning-stat:hover" in result


class TestTrainingTablePolish:
    """Imp 2: Training table row classes and step badges."""

    def test_row_class_yes(self):
        data = _data_from_session(_batch3_training_session())
        result = render_html(data)
        assert "training-row-yes" in result

    def test_row_class_no(self):
        data = _data_from_session(_batch3_training_session())
        result = render_html(data)
        assert "training-row-no" in result

    def test_step_badge_present(self):
        data = _data_from_session(_batch3_training_session())
        result = render_html(data)
        assert "step-badge" in result

    def test_training_hover_css(self):
        data = _data_from_session(_batch3_training_session())
        result = render_html(data)
        assert ".training-table tbody tr:hover td" in result


class TestVulnSeverityBar:
    """Imp 3: Vulnerability severity mini-bar."""

    def test_vuln_sev_bar_present(self):
        data = _data_from_session(_sample_session())
        data["vulnerabilities"] = [
            {"vulnerability_id": "v1", "vuln_type": "sqli", "severity": "HIGH",
             "affected_surfaces": ["/login"], "scenarios": ["sqli_basic"],
             "confidence_aggregate": 0.9, "proofs": ["proof"], "reproduction_steps": []},
            {"vulnerability_id": "v2", "vuln_type": "xss", "severity": "MEDIUM",
             "affected_surfaces": ["/search"], "scenarios": ["xss_scan"],
             "confidence_aggregate": 0.7, "proofs": [], "reproduction_steps": []},
        ]
        result = render_html(data)
        assert "vuln-sev-bar" in result

    def test_vuln_sev_bar_segments_match(self):
        data = _data_from_session(_sample_session())
        data["vulnerabilities"] = [
            {"vulnerability_id": "v1", "vuln_type": "sqli", "severity": "HIGH",
             "affected_surfaces": [], "scenarios": [],
             "confidence_aggregate": 0.9, "proofs": [], "reproduction_steps": []},
            {"vulnerability_id": "v2", "vuln_type": "xss", "severity": "HIGH",
             "affected_surfaces": [], "scenarios": [],
             "confidence_aggregate": 0.7, "proofs": [], "reproduction_steps": []},
            {"vulnerability_id": "v3", "vuln_type": "redirect", "severity": "LOW",
             "affected_surfaces": [], "scenarios": [],
             "confidence_aggregate": 0.5, "proofs": [], "reproduction_steps": []},
        ]
        result = render_html(data)
        assert 'title="HIGH: 2"' in result
        assert 'title="LOW: 1"' in result

    def test_vuln_sev_bar_absent_no_vulns(self):
        data = _data_from_session(_sample_session())
        data["vulnerabilities"] = []
        result = render_html(data)
        # HTML element should not appear (CSS class def still present)
        assert 'class="severity-bar vuln-sev-bar"' not in result


class TestFilterChipAnimation:
    """Imp 4: Filter chip hover/active micro-interactions."""

    def test_filter_chip_hover_translatey(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".filter-chip:hover" in result
        assert "translateY(-1px)" in result

    def test_filter_chip_active_scale(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".filter-chip:active" in result
        assert "scale(0.95)" in result

    def test_filter_chip_transition_exists(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "transition: all 0.15s" in result


class TestScanLineEffect:
    """Imp 5: Scan-line cyberpunk effect on .main."""

    def test_scan_line_applied(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".main::after" in result
        assert "scan-line" in result

    def test_scan_line_hidden_in_print(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".main::after { display: none" in result

    def test_reduced_motion_covers_after(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "*, *::before, *::after" in result


class TestFooterEnrichment:
    """Imp 6: Footer with findings count, risk score, entities."""

    def test_footer_findings_count(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "Findings:" in result
        assert "footer-stats" in result

    def test_footer_risk_score_color(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "risk-" in result

    def test_footer_entities_count(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert "Entities:" in result

    def test_footer_flex_layout_css(self):
        data = _data_from_session(_sample_session())
        result = render_html(data)
        assert ".footer-stats" in result
        assert ".footer-meta" in result


class TestSvgAccessibility:
    """Imp 7: SVG charts have role=img and <title>."""

    def test_gap_trajectory_accessible(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "Gap trajectory chart" in result
        assert 'role="img"' in result

    def test_entity_velocity_accessible(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "Entity gain velocity chart" in result

    def test_cumulative_findings_accessible(self):
        data = _data_from_session(_batch2_session())
        result = render_html(data)
        assert "Cumulative findings chart" in result


class TestConfidenceGauge:
    """Imp 8: Inline SVG confidence gauge in vulnerabilities."""

    def test_conf_gauge_present(self):
        data = _data_from_session(_sample_session())
        data["vulnerabilities"] = [
            {"vulnerability_id": "v1", "vuln_type": "sqli", "severity": "HIGH",
             "affected_surfaces": [], "scenarios": [],
             "confidence_aggregate": 0.9, "proofs": [], "reproduction_steps": []},
        ]
        result = render_html(data)
        assert "conf-gauge" in result

    def test_conf_gauge_high_color(self):
        data = _data_from_session(_sample_session())
        data["vulnerabilities"] = [
            {"vulnerability_id": "v1", "vuln_type": "sqli", "severity": "HIGH",
             "affected_surfaces": [], "scenarios": [],
             "confidence_aggregate": 0.9, "proofs": [], "reproduction_steps": []},
        ]
        result = render_html(data)
        assert "var(--neon-green)" in result

    def test_conf_gauge_medium_color(self):
        data = _data_from_session(_sample_session())
        data["vulnerabilities"] = [
            {"vulnerability_id": "v1", "vuln_type": "sqli", "severity": "HIGH",
             "affected_surfaces": [], "scenarios": [],
             "confidence_aggregate": 0.6, "proofs": [], "reproduction_steps": []},
        ]
        result = render_html(data)
        assert "var(--medium)" in result

    def test_conf_gauge_low_color(self):
        data = _data_from_session(_sample_session())
        data["vulnerabilities"] = [
            {"vulnerability_id": "v1", "vuln_type": "sqli", "severity": "HIGH",
             "affected_surfaces": [], "scenarios": [],
             "confidence_aggregate": 0.3, "proofs": [], "reproduction_steps": []},
        ]
        result = render_html(data)
        # Low confidence (<0.5) uses critical color
        assert "var(--critical)" in result
