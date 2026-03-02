"""Tests for report renderer — HTML and JSON generation."""

from __future__ import annotations

import json

from basilisk.reporting.collector import (
    HostTopology,
    ReportCollector,
    ReportDecision,
    ReportFinding,
    ReportPlugin,
    StepSnapshot,
)
from basilisk.reporting.renderer import (
    _host_risk_score,
    _max_severity_for_host,
    _service_badge_class,
    assemble_data,
    render_html,
    render_json,
)


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
        StepSnapshot(step=2, entities=18, relations=9, gaps=6, entities_gained=8),
        StepSnapshot(step=5, entities=42, relations=20, gaps=3, entities_gained=5),
    ]
    c.hypotheses_confirmed = 2
    c.hypotheses_rejected = 1
    c.beliefs_strengthened = 5
    c.beliefs_weakened = 1
    return c


class TestAssembleData:
    """Test assemble_data output structure."""

    def test_has_required_keys(self):
        c = _sample_collector()
        data = assemble_data(c)
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
        c = _sample_collector()
        data = assemble_data(c)
        s = data["summary"]
        assert s["steps"] == 10
        assert s["max_steps"] == 50
        assert s["total_entities"] == 42
        assert s["total_findings"] == 2
        assert s["total_gaps"] == 3
        assert s["entity_counts"]["host"] == 2
        assert s["entity_counts"]["service"] == 8

    def test_findings_serialized(self):
        c = _sample_collector()
        data = assemble_data(c)
        assert len(data["findings"]) == 2
        f = data["findings"][0]
        assert f["title"] == "SQL Injection in /login"
        assert f["severity"] == "HIGH"
        assert f["verified"] is True
        assert f["confidence"] == 0.92

    def test_decisions_serialized(self):
        c = _sample_collector()
        data = assemble_data(c)
        assert len(data["decisions"]) == 2
        assert data["decisions"][1]["productive"] is True

    def test_reasoning_serialized(self):
        c = _sample_collector()
        data = assemble_data(c)
        r = data["reasoning"]
        assert r["hypotheses_confirmed"] == 2
        assert r["beliefs_strengthened"] == 5

    def test_training_none(self):
        c = _sample_collector()
        data = assemble_data(c)
        assert data["training"] is None

    def test_empty_collector(self):
        c = ReportCollector()
        data = assemble_data(c)
        assert data["summary"]["steps"] == 0
        assert len(data["findings"]) == 0
        assert data["training"] is None


class TestRenderJson:
    """Test JSON rendering."""

    def test_valid_json(self):
        c = _sample_collector()
        data = assemble_data(c)
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["target"] == "test.example.com"

    def test_empty_data(self):
        data = assemble_data(ReportCollector())
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["version"] == "4.0.0"


class TestRenderHtml:
    """Test HTML rendering."""

    def test_contains_doctype(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert html.startswith("<!DOCTYPE html>")

    def test_contains_target(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "test.example.com" in html

    def test_auto_refresh_present(self):
        data = assemble_data(_sample_collector())
        html = render_html(data, auto_refresh=True)
        assert 'http-equiv="refresh"' in html

    def test_auto_refresh_absent(self):
        data = assemble_data(_sample_collector())
        html = render_html(data, auto_refresh=False)
        assert 'http-equiv="refresh"' not in html

    def test_contains_sections(self):
        data = assemble_data(_sample_collector())
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
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "SQL Injection in /login" in html
        assert "sev-HIGH" in html
        assert "VERIFIED" in html

    def test_css_variables(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "--neon-green: #00ff6a" in html
        assert "--critical: #ff1744" in html
        assert "JetBrains Mono" in html

    def test_js_embedded(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "toggleFilter" in html
        assert "applyFilters" in html
        assert "IntersectionObserver" in html

    def test_data_embedded_as_json(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "const DATA =" in html

    def test_empty_findings(self):
        data = assemble_data(ReportCollector())
        html = render_html(data)
        assert "No findings yet" in html

    def test_empty_decisions(self):
        data = assemble_data(ReportCollector())
        html = render_html(data)
        assert "No decisions yet" in html

    def test_empty_growth(self):
        data = assemble_data(ReportCollector())
        html = render_html(data)
        assert "No data yet" in html

    def test_sidebar_risk_score(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "Risk Score" in html

    def test_kill_chain_phases(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert "Recon" in html
        assert "Mapping" in html
        assert "Exploit" in html
        assert "Privesc" in html
        assert "Verify" in html

    def test_training_section_absent_when_none(self):
        data = assemble_data(_sample_collector())
        html = render_html(data)
        assert 'id="training"' not in html

    def test_training_section_present(self):
        c = _sample_collector()
        c.training = {
            "profile_name": "test_app",
            "coverage": 0.85,
            "verification_rate": 0.7,
            "passed": True,
            "expected_findings": [
                {"title": "SQLi", "severity": "high",
                 "discovered": True, "verified": True, "discovery_step": 3},
            ],
        }
        data = assemble_data(c)
        html = render_html(data)
        assert 'id="training"' in html
        assert "PASSED" in html
        assert "test_app" in html

    def test_remediation_rendered(self):
        c = ReportCollector(target="test.com")
        c.findings = [
            ReportFinding(
                title="SQLi", severity="high", host="test.com",
                evidence="1=1", remediation="Use parameterized queries",
            ),
        ]
        data = assemble_data(c)
        result = render_html(data)
        assert "Remediation:" in result
        assert "Use parameterized queries" in result

    def test_remediation_absent_when_empty(self):
        c = ReportCollector(target="test.com")
        c.findings = [
            ReportFinding(title="Info", severity="info", host="test.com"),
        ]
        data = assemble_data(c)
        result = render_html(data)
        # CSS class definition exists, but no finding card uses it
        assert "<strong>Remediation:</strong>" not in result

    def test_vulnerabilities_section_rendered(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert 'id="vulnerabilities"' in result
        assert "Vulnerabilities (Deduplicated)" in result

    def test_attack_surface_stat_cards(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert "surface-stat" in result
        assert "Hosts" in result
        assert "Services" in result
        assert "Endpoints" in result
        assert "Technologies" in result
        assert "Containers" in result

    def test_false_positive_risk_in_data(self):
        c = ReportCollector(target="test.com")
        c.findings = [
            ReportFinding(
                title="Maybe XSS", severity="medium", host="test.com",
                false_positive_risk="high",
            ),
        ]
        data = assemble_data(c)
        assert data["findings"][0]["false_positive_risk"] == "high"

    def test_vulnerabilities_in_data(self):
        data = assemble_data(_sample_collector())
        assert "vulnerabilities" in data
        assert isinstance(data["vulnerabilities"], list)

    def test_html_escaping(self):
        """Ensure special characters are escaped."""
        c = ReportCollector(target="<script>alert(1)</script>")
        data = assemble_data(c)
        html = render_html(data)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_execution_timeline_in_data(self):
        c = _sample_collector()
        data = assemble_data(c)
        assert "execution_timeline" in data
        assert isinstance(data["execution_timeline"], list)

    def test_decisions_show_duration(self):
        c = _sample_collector()
        c.decisions[0] = ReportDecision(
            step=1, plugin="port_scan", target="test.example.com",
            score=0.95, reasoning="initial recon", duration=2.5,
        )
        data = assemble_data(c)
        result = render_html(data)
        assert "2.50s" in result

    def test_decisions_show_new_entities(self):
        c = _sample_collector()
        data = assemble_data(c)
        result = render_html(data)
        # Decision at step 5 has new_entities=3
        assert "+3 entities" in result

    def test_reasoning_events_rendered(self):
        from basilisk.reporting.collector import ReasoningEvent

        c = _sample_collector()
        c.reasoning_events = [
            ReasoningEvent(
                event_type="hypothesis_confirmed",
                data={"hypothesis": "SQL injection present"},
                step=5,
            ),
        ]
        data = assemble_data(c)
        result = render_html(data)
        assert "Events Timeline" in result
        assert "hypothesis_confirmed" in result

    def test_sidebar_has_vulnerabilities_link(self):
        data = assemble_data(_sample_collector())
        # sample_collector has findings that produce vulnerabilities
        result = render_html(data)
        assert 'href="#vulnerabilities"' in result
        assert "Vulns" in result

    def test_sidebar_entity_counts(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert "entity-breakdown" in result
        assert "entity-row" in result

    def test_hover_states_in_css(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert ".finding-card:hover" in result
        assert ".timeline-item:hover" in result
        assert ".surface-stat:hover" in result
        assert ".kc-phase:hover" in result
        assert ".metric-card:hover" in result

    def test_evidence_toggle_js(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert "evidence-toggle" in result
        assert "Show more" in result

    def test_entrance_animation_in_css(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert "fade-in-up" in result
        assert "animation-delay" in result

    def test_responsive_surface_stats_grid(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert ".surface-stats-grid" in result
        # Check responsive rule includes surface-stats-grid
        assert "surface-stats-grid" in result

    def test_copy_to_clipboard_js(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert "evidence-copy" in result
        assert "navigator.clipboard.writeText" in result


def _collector_with_topology() -> ReportCollector:
    """Build a collector with sample topology for network map tests."""
    c = _sample_collector()
    c.topology["test.example.com"] = HostTopology(
        services=[
            {"port": 443, "protocol": "tcp", "service": "https"},
            {"port": 80, "protocol": "tcp", "service": "http"},
        ],
        endpoints=["/login", "/admin", "/api/v1"],
        technologies=[
            {"name": "nginx", "version": "1.21"},
            {"name": "React", "version": "18"},
        ],
    )
    c.topology["api.test.example.com"] = HostTopology(
        services=[{"port": 8080, "protocol": "tcp", "service": "http"}],
        is_subdomain=True,
        parent="test.example.com",
    )
    return c


class TestNetworkMap:
    """Test Network Map HTML section rendering."""

    def test_network_map_section_rendered(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert 'id="network-map"' in result
        assert "Network Map" in result

    def test_network_map_absent_when_empty(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert 'id="network-map"' not in result

    def test_network_map_shows_host_services(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "443" in result
        assert "https" in result
        assert "nm-port" in result

    def test_network_map_shows_endpoints(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "/login" in result
        assert "/admin" in result
        assert "/api/v1" in result

    def test_network_map_shows_technologies(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-tech-chip" in result
        assert "nginx" in result
        assert "React" in result

    def test_sidebar_has_network_map_link(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert 'href="#network-map"' in result
        assert "Network Map" in result

    def test_host_card_hover_in_css(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".host-card:hover" in result

    def test_host_card_entrance_animation(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".nm-grid .host-card" in result

    def test_network_map_summary_stats(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-stats" in result
        assert "nm-stat-card" in result
        assert "nm-stat-value" in result

    def test_endpoints_expand_collapse_many(self):
        c = _collector_with_topology()
        c.topology["test.example.com"] = HostTopology(
            services=[{"port": 443, "protocol": "tcp", "service": "https"}],
            endpoints=["/ep" + str(i) for i in range(10)],
        )
        data = assemble_data(c)
        result = render_html(data)
        assert "nm-endpoints-toggle" in result
        assert "more endpoint" in result

    def test_few_endpoints_no_toggle(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # test.example.com has only 3 endpoints → no <details> toggle element
        assert '<details class="nm-endpoints-toggle">' not in result

    def test_subdomain_has_css_class(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "host-card subdomain" in result

    def test_subdomain_ordered_after_parent(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        parent_idx = result.index("test.example.com")
        sub_idx = result.index("api.test.example.com")
        assert parent_idx < sub_idx

    def test_findings_count_per_host(self):
        c = _collector_with_topology()
        # sample collector has findings for test.example.com
        data = assemble_data(c)
        result = render_html(data)
        assert "nm-findings-badge" in result

    def test_service_type_badges(self):
        data = assemble_data(_collector_with_topology())
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
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert 'class="cnt">2</span>' in result

    def test_responsive_nm_grid_in_css(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".nm-grid" in result

    def test_network_map_search_js(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "applyHostFilters" in result

    def test_network_map_search_input(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-search" in result
        assert 'placeholder=' in result

    def test_well_known_port_class(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "well-known" in result

    def test_high_port_class(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # api.test.example.com has port 8080
        assert "high-port" in result

    def test_data_host_attribute(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert 'data-host="test.example.com"' in result

    # --- Feature 1: Collapsible Host Cards ---

    def test_host_card_is_collapsible_details(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert '<details class="host-card' in result

    def test_host_card_starts_open(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert '<details class="host-card' in result
        assert "open" in result.split('<details class="host-card')[1][:30]

    def test_host_card_body_wrapper(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "host-card-body" in result

    # --- Feature 2: Host Card Severity Accent ---

    def test_host_card_severity_accent(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # test.example.com has HIGH finding → should have sev-accent-HIGH
        assert "sev-accent-HIGH" in result

    def test_severity_accent_only_on_hosts_with_findings(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # api.test.example.com has no findings → no sev-accent on that card
        # Split by api.test.example.com card
        idx = result.index('data-host="api.test.example.com"')
        # Look backwards to find the opening <details> tag for this card
        card_start = result.rfind("<details", 0, idx)
        card_tag = result[card_start:idx]
        assert "sev-accent" not in card_tag

    def test_severity_accent_css_classes(self):
        data = assemble_data(_collector_with_topology())
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
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "host-copy" in result

    def test_host_copy_button_has_hostname(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "copyHost(this,'test.example.com')" in result

    def test_host_copy_css(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".host-copy" in result
        assert ".host-copy:hover" in result

    # --- Feature 4: Search Result Counter + Empty State ---

    def test_search_counter_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-search-status" in result
        assert "nm-visible" in result

    def test_search_counter_shows_total(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # 2 hosts in topology
        assert "of 2 hosts" in result

    def test_no_matches_element_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-no-matches" in result
        assert "No hosts match your search" in result

    def test_filter_updates_counter_js(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "getElementById('nm-visible')" in result
        assert "getElementById('nm-no-matches')" in result

    # --- Feature 5: Port Distribution Mini-Bar ---

    def test_port_bar_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-port-bar" in result

    def test_port_bar_segments(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "well-known-seg" in result

    def test_port_bar_well_known_title(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # test.example.com has ports 443 and 80 (both well-known)
        assert 'well-known"' in result

    def test_port_bar_css(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".nm-port-bar" in result
        assert ".nm-port-seg" in result
        assert ".nm-port-seg.well-known-seg" in result
        assert ".nm-port-seg.high-port-seg" in result

    # --- Feature 6: Expand/Collapse All Toggle ---

    def test_expand_collapse_toggle_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-toggle-btn" in result
        assert "Collapse All" in result

    def test_toggle_network_cards_js(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "toggleNetworkCards" in result
        assert "Expand All" in result

    # --- Feature 7: Severity Filter Chips ---

    def test_severity_filter_chips_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-filter-bar" in result
        assert "toggleHostFilter" in result

    def test_severity_filter_chips_count(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # test.example.com has HIGH finding, api.test.example.com has NONE
        assert "HIGH (1)" in result

    def test_severity_filter_chips_only_existing(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # No CRITICAL findings → no CRITICAL chip in nm-filter-bar
        nm_section = result.split('id="network-map"')[1].split('class="section"')[0]
        assert 'data-sev="CRITICAL"' not in nm_section.split("nm-filter-bar")[1].split("</div>")[0]

    def test_host_card_data_sev_attribute(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert 'data-sev="HIGH"' in result
        assert 'data-sev="NONE"' in result

    def test_severity_filter_js_functions(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "function toggleHostFilter" in result
        assert "function applyHostFilters" in result

    def test_nm_filter_bar_css(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".nm-filter-bar" in result

    # --- Feature 8: Findings Inline Preview ---

    def test_findings_preview_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-findings-preview" in result

    def test_findings_preview_sev_dot(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-sev-dot" in result
        assert "dot-HIGH" in result

    def test_findings_preview_title_shown(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # The sample collector has "SQL Injection in /login"
        assert "SQL Injection in /login" in result

    def test_findings_preview_absent_no_findings(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # api.test.example.com card should have no findings preview
        idx = result.index('data-host="api.test.example.com"')
        card_end = result.index("</details>", idx)
        card_html = result[idx:card_end]
        assert "nm-findings-preview" not in card_html

    def test_findings_preview_many_toggle(self):
        c = _collector_with_topology()
        from basilisk.reporting.collector import ReportFinding
        # Add 5 findings for test.example.com (already has 2 → total 7)
        for i in range(5):
            c.findings.append(
                ReportFinding(
                    title=f"Finding {i}",
                    severity="medium",
                    host="test.example.com",
                    step=i + 10,
                )
            )
        data = assemble_data(c)
        result = render_html(data)
        # Should have "N more" toggle for findings beyond 3
        assert " more</summary>" in result

    # --- Feature 9: Host Sort Controls ---

    def test_sort_buttons_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-sort-bar" in result
        assert "nm-sort-btn" in result
        assert "Severity" in result
        assert "Findings" in result
        assert "Name" in result

    def test_sort_bar_css(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".nm-sort-bar" in result
        assert ".nm-sort-btn" in result
        assert ".nm-sort-btn.active" in result

    def test_sort_js_function(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "function sortNetworkHosts" in result
        assert "sevRank" in result

    def test_host_card_data_findings_attribute(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert 'data-findings="2"' in result  # test.example.com has 2 findings
        assert 'data-findings="0"' in result  # api.test.example.com has 0

    # --- Feature 10: Service Protocol Summary Bar ---

    def test_proto_bar_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-proto-bar" in result

    def test_proto_bar_segments(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-proto-seg" in result

    def test_proto_bar_legend(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-proto-legend" in result
        assert "nm-proto-legend-item" in result

    def test_proto_bar_css(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".nm-proto-bar" in result
        assert ".nm-proto-seg" in result
        assert ".nm-proto-legend" in result

    def test_proto_bar_groups_known_services(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # Topology has https and http services
        assert "HTTPS" in result
        assert "HTTP" in result

    # --- Feature 11: Export Hosts Button ---

    def test_export_button_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "Export Hosts" in result

    def test_export_js_function(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "function exportVisibleHosts" in result

    def test_export_uses_clipboard(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "navigator.clipboard.writeText(hosts.join" in result

    # --- Feature 12: Host Risk Score Badge ---

    def test_risk_badge_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-risk-badge" in result

    def test_risk_badge_score_value(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # test.example.com has HIGH(5) + INFO(0) = 5
        assert 'data-risk="5"' in result

    def test_risk_badge_zero_for_no_findings(self):
        data = assemble_data(_collector_with_topology())
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
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "sortNetworkHosts('risk')" in result or 'sortNetworkHosts(\\\'risk\\\')' in result

    # --- Feature 13: Service Count Badge ---

    def test_svc_count_badge_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-svc-count-badge" in result

    def test_svc_count_badge_value(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        # test.example.com has 2 services
        assert "2 svcs" in result

    def test_svc_count_badge_css(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".nm-svc-count-badge" in result
        assert "rgba(0,229,255,0.15)" in result

    # --- Feature 14: Compact View Toggle ---

    def test_compact_table_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-compact-table" in result

    def test_compact_table_has_columns(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "<th>Host</th>" in result
        assert "<th>Risk</th>" in result
        assert "<th>Severity</th>" in result
        assert "<th>Findings</th>" in result
        assert "<th>Services</th>" in result
        assert "<th>Technologies</th>" in result

    def test_compact_view_button_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-view-btn" in result
        assert "Compact" in result

    def test_compact_view_js_function(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "function toggleCompactView" in result

    # --- Feature 15: Keyboard Navigation ---

    def test_keyboard_hint_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-kb-hint" in result
        assert "<kbd>j</kbd>" in result
        assert "<kbd>k</kbd>" in result

    def test_nm_focused_css(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".nm-focused" in result
        assert "var(--neon-green) !important" in result

    def test_keyboard_js_handler(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nmVisibleCards" in result
        assert "nmSetFocus" in result

    def test_keyboard_navigation_keys(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "e.key === 'j'" in result
        assert "e.key === 'k'" in result
        assert "e.key === 'Enter'" in result
        assert "e.key === '/'" in result

    # --- Feature 16: Active Filter Indicator ---

    def test_filter_indicator_element_present(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "nm-filter-indicator" in result

    def test_filter_indicator_css(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert ".nm-filter-indicator" in result
        assert ".nm-filter-indicator a" in result

    def test_filter_indicator_updated_in_js(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "getElementById('nm-filter-indicator')" in result

    def test_clear_host_filters_js(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "function clearHostFilters" in result


# ---------------------------------------------------------------------------
# UX Quick Wins — Report Dashboard Polish
# ---------------------------------------------------------------------------


class TestTerminationReason:
    """Fix 1: termination_reason displayed in Command Center."""

    def test_termination_reason_displayed(self):
        c = _sample_collector()
        c.termination_reason = "no_gaps"
        data = assemble_data(c)
        result = render_html(data)
        assert "Termination: no_gaps" in result

    def test_termination_reason_absent_when_empty(self):
        c = _sample_collector()
        data = assemble_data(c)
        result = render_html(data)
        # Should show em-dash placeholder when empty
        assert "Termination: \u2014" in result


class TestHostCopyFeedback:
    """Fix 2: host copy button shows Copied! feedback."""

    def test_host_copy_feedback_js(self):
        data = assemble_data(_collector_with_topology())
        result = render_html(data)
        assert "function copyHost(btn, text)" in result
        assert "Copied!" in result
        assert "copyHost(this," in result


class TestSortDirectionArrows:
    """Fix 3: CSS rules for sort direction indicators."""

    def test_sort_direction_css_rules(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert "th.sort-asc::after" in result
        assert "th.sort-desc::after" in result
        assert "\\25B2" in result  # ▲
        assert "\\25BC" in result  # ▼


class TestReducedMotion:
    """Fix 4: prefers-reduced-motion media query."""

    def test_prefers_reduced_motion_css(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert "@media (prefers-reduced-motion: reduce)" in result
        assert "animation-duration: 0.01ms !important" in result
        assert "transition-duration: 0.01ms !important" in result


class TestReproductionSteps:
    """Fix 5: reproduction steps rendered in vulnerabilities table."""

    def test_reproduction_steps_rendered(self):
        data = assemble_data(_sample_collector())
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
        data = assemble_data(_sample_collector())
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
        assert "repro-row" not in result
        assert "reproduction steps" not in result


class TestFilterChipAccessibility:
    """Fix 6: filter chips use <button> instead of <span>."""

    def test_filter_chips_are_buttons(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert '<button class="filter-chip' in result
        # Should NOT have span filter-chip
        assert '<span class="filter-chip' not in result

    def test_expand_collapse_are_buttons(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert "Expand All</button>" in result
        assert "Collapse All</button>" in result


class TestKillChainCoverage:
    """Fix 7: kill chain shows ratio and percentage."""

    def test_kill_chain_coverage_percentage(self):
        c = _sample_collector()
        data = assemble_data(c)
        result = render_html(data)
        assert "% coverage" in result

    def test_kill_chain_shows_ratio(self):
        c = _sample_collector()
        data = assemble_data(c)
        result = render_html(data)
        # Should contain ratio like "1/5" or "0/10"
        assert 'class="kc-label">' in result
        # At least one phase should show "N/M" format
        import re
        assert re.search(r'class="kc-label">\d+/\d+<', result)


class TestContrastReadability:
    """Fix 8: improved contrast and minimum text size."""

    def test_fg_dim_contrast_value(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert "#6d7a94" in result
        assert "#5a6580" not in result

    def test_text_xs_minimum(self):
        data = assemble_data(_sample_collector())
        result = render_html(data)
        assert "--text-xs: 0.65rem" in result
