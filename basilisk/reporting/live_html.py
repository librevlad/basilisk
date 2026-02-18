"""Unified live report engine — writes HTML + JSON on each progress event.

Replaces the separate LiveHtmlRenderer + final ReportEngine pattern.
Both files are created at audit start and rewritten on every progress callback,
so the report is always up-to-date (auto-refreshing HTML while running,
final static report when complete).
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from basilisk.core.pipeline import PipelineState
from basilisk.models.result import Severity
from basilisk.reporting.aggregation import (
    aggregate_findings,
    build_timeline,
    detect_exploit_chains,
)
from basilisk.reporting.analysis import (
    categorize_findings,
    compute_quality_metrics,
    compute_radar_points,
    compute_remediation_priority,
)
from basilisk.reporting.extraction import (
    extract_attack_surface,
    extract_dns_details,
    extract_js_intelligence,
    extract_plugin_stats,
    extract_ssl_details,
    extract_whois_details,
)
from basilisk.reporting.filtering import is_noise
from basilisk.reporting.rendering import (
    build_plugin_matrix,
    build_port_findings,
    build_site_tree,
    filesize,
)

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Backward-compat aliases (imported by tests)
_is_noise = is_noise
_extract_attack_surface = extract_attack_surface
_build_site_tree = build_site_tree
_build_plugin_matrix = build_plugin_matrix


class LiveReportEngine:
    """Writes both HTML and JSON reports on each pipeline progress event.

    Usage in CLI:
        engine = LiveReportEngine(scan_dir)
        audit_builder = audit_builder.on_progress(engine.update)
        state = await audit_builder.run()
        # Reports are already written — engine.html_path / engine.json_path
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.html_path = output_dir / "report.html"
        self.json_path = output_dir / "report.json"
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        self._env.filters["filesize"] = filesize
        self._start_time = time.monotonic()

    def update(self, state: PipelineState) -> None:
        """Called from on_progress callback — rewrite both HTML and JSON."""
        self._write_html(state)
        self._write_json(state)

    def _prepare_findings(self, state: PipelineState) -> tuple:
        """Extract and process findings from state. Returns common data."""
        severity_counts = {s.label: 0 for s in Severity}
        all_findings = []
        for result in state.results:
            for finding in result.findings:
                severity_counts[finding.severity.label] += 1
                all_findings.append({
                    "severity": finding.severity.label,
                    "severity_color": finding.severity.color,
                    "target": result.target,
                    "plugin": result.plugin,
                    "title": finding.title,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "tags": finding.tags,
                    "confidence": getattr(finding, "confidence", None),
                    "verified": getattr(finding, "verified", None),
                })

        all_findings.sort(
            key=lambda x: Severity[x["severity"]].value, reverse=True,
        )

        actionable_findings = [f for f in all_findings if not is_noise(f)]
        noise_count = len(all_findings) - len(actionable_findings)
        aggregated_findings = aggregate_findings(actionable_findings)

        top_findings = [
            f for f in aggregated_findings if f["severity"] in ("CRITICAL", "HIGH")
        ][:5]

        risk_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}
        risk_score = sum(
            risk_weights.get(f["severity"], 0) * f["count"]
            for f in aggregated_findings
        )
        risk_score = min(round(risk_score), 100)
        if severity_counts.get("CRITICAL", 0) > 0:
            risk_label = "CRITICAL"
        elif severity_counts.get("HIGH", 0) > 0:
            risk_label = "HIGH"
        elif severity_counts.get("MEDIUM", 0) > 0:
            risk_label = "MEDIUM"
        else:
            risk_label = "LOW"

        return (
            severity_counts, actionable_findings, noise_count,
            aggregated_findings, top_findings, risk_score, risk_label,
        )

    def _write_html(self, state: PipelineState) -> None:
        """Write the HTML report file."""
        template = self._env.get_template("report.html.j2")

        (
            severity_counts, actionable_findings, noise_count,
            aggregated_findings, top_findings, risk_score, risk_label,
        ) = self._prepare_findings(state)

        phases = []
        for name, phase in state.phases.items():
            phases.append({
                "name": name,
                "status": phase.status,
                "total": phase.total,
                "completed": phase.completed,
                "pct": round(phase.progress_pct, 1),
                "elapsed": round(phase.elapsed, 1),
            })

        elapsed_total = time.monotonic() - self._start_time
        targets = {r.target for r in state.results}
        plugins = {r.plugin for r in state.results}
        total_duration = sum(r.duration for r in state.results)

        attack_surface = extract_attack_surface(state.results)
        plugin_stats = extract_plugin_stats(state.results)
        site_tree = build_site_tree(attack_surface)
        plugin_matrix = build_plugin_matrix(state.results)
        ssl_details = extract_ssl_details(state.results)
        dns_details = extract_dns_details(state.results)
        whois_details = extract_whois_details(state.results)
        timeline = build_timeline(actionable_findings, state.results)
        vuln_categories = categorize_findings(actionable_findings)
        radar_points = compute_radar_points(vuln_categories)
        exploit_chains = detect_exploit_chains(aggregated_findings)
        js_intelligence = extract_js_intelligence(state.results)
        port_findings = build_port_findings(state.results)
        remediation_priority = compute_remediation_priority(aggregated_findings)
        quality_metrics = compute_quality_metrics(state.results)

        is_running = state.status not in ("completed", "done", "error")

        html = template.render(
            title="Basilisk Security Audit Report",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status=state.status,
            is_running=is_running,
            refresh_interval=3 if is_running else None,
            total_findings=state.total_findings,
            severity_counts=severity_counts,
            phases=phases,
            findings=actionable_findings,
            aggregated_findings=aggregated_findings,
            total_aggregated_count=len(aggregated_findings),
            total_raw_count=len(actionable_findings),
            top_findings=top_findings,
            risk_score=risk_score,
            risk_label=risk_label,
            noise_count=noise_count,
            elapsed_total=round(elapsed_total, 1),
            targets_scanned=len(targets),
            plugins_run=len(plugins),
            duration=round(total_duration, 1),
            attack_surface=attack_surface,
            plugin_stats=plugin_stats,
            ssl_details=ssl_details,
            dns_details=dns_details,
            whois_details=whois_details,
            timeline=timeline,
            vuln_categories=vuln_categories,
            radar_points=radar_points,
            exploit_chains=exploit_chains,
            site_tree=site_tree,
            plugin_matrix=plugin_matrix,
            js_intelligence=js_intelligence,
            port_findings=port_findings,
            remediation_priority=remediation_priority,
            quality_metrics=quality_metrics,
        )

        self.html_path.write_text(html, encoding="utf-8")

    def _write_json(self, state: PipelineState) -> None:
        """Write the JSON report file."""
        data = {
            "status": state.status,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": state.total_findings,
            "phases": {
                name: {
                    "status": phase.status,
                    "total": phase.total,
                    "completed": phase.completed,
                    "elapsed": round(phase.elapsed, 2),
                }
                for name, phase in state.phases.items()
            },
            "results": [
                {
                    "plugin": r.plugin,
                    "target": r.target,
                    "status": r.status,
                    "duration": round(r.duration, 3),
                    "findings": [
                        {
                            "severity": f.severity.label,
                            "title": f.title,
                            "description": f.description,
                            "evidence": f.evidence,
                            "remediation": f.remediation,
                            "tags": f.tags,
                        }
                        for f in r.findings
                    ],
                    "data": r.data if r.data else {},
                    "error": r.error,
                }
                for r in state.results
            ],
        }

        from basilisk.storage.repo import _SafeEncoder

        self.json_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, cls=_SafeEncoder),
            encoding="utf-8",
        )


# Keep LiveHtmlRenderer as backward-compat alias
class LiveHtmlRenderer(LiveReportEngine):
    """Backward-compatible alias. Use LiveReportEngine instead."""

    def __init__(self, output_path: Path, refresh_interval: int = 3) -> None:
        output_dir = output_path.parent
        super().__init__(output_dir)
        self.html_path = output_path

    def update(self, state: PipelineState) -> None:
        self._write_html(state)
