"""Tests for the unified report data builder."""

from __future__ import annotations

from basilisk.core.pipeline import PipelineState
from basilisk.models.result import Finding, PluginResult
from basilisk.reporting.data import build_report_data


def _make_state() -> PipelineState:
    state = PipelineState()
    state.status = "completed"
    state.total_findings = 3
    state.results = [
        PluginResult.success(
            "ssl_check", "example.com",
            findings=[
                Finding.high("Expired SSL", evidence="cert expired"),
                Finding.medium("Missing HSTS"),
            ],
            duration=1.5,
        ),
        PluginResult.success(
            "http_headers", "api.example.com",
            findings=[Finding.low("Server header exposed", evidence="Server: nginx")],
            duration=0.8,
        ),
    ]
    return state


class TestBuildReportData:
    def test_returns_dict(self):
        data = build_report_data(_make_state())
        assert isinstance(data, dict)

    def test_has_required_keys(self):
        data = build_report_data(_make_state())
        required = [
            "title", "timestamp", "status", "severity_counts",
            "phases", "findings", "aggregated_findings",
            "risk_score", "risk_label", "noise_count",
            "targets_scanned", "plugins_run", "duration",
            "attack_surface", "plugin_stats", "ssl_details",
            "dns_details", "whois_details", "timeline",
            "vuln_categories", "radar_points", "exploit_chains",
            "site_tree", "plugin_matrix", "js_intelligence",
            "port_findings", "remediation_priority", "quality_metrics",
            "skipped_plugins", "host_schemes",
        ]
        for key in required:
            assert key in data, f"Missing key: {key}"

    def test_severity_counts(self):
        data = build_report_data(_make_state())
        assert data["severity_counts"]["HIGH"] == 1
        assert data["severity_counts"]["MEDIUM"] == 1
        assert data["severity_counts"]["LOW"] == 1

    def test_risk_label(self):
        data = build_report_data(_make_state())
        assert data["risk_label"] == "HIGH"

    def test_targets_scanned(self):
        data = build_report_data(_make_state())
        assert data["targets_scanned"] == 2

    def test_plugins_run(self):
        data = build_report_data(_make_state())
        assert data["plugins_run"] == 2

    def test_empty_state(self):
        state = PipelineState()
        data = build_report_data(state)
        assert data["total_findings"] == 0
        assert data["findings"] == []
        assert data["risk_label"] == "LOW"

    def test_host_schemes_default_https(self):
        data = build_report_data(_make_state())
        assert data["host_schemes"]["example.com"] == "https"
        assert data["host_schemes"]["api.example.com"] == "https"
