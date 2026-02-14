"""Live HTML renderer — auto-refreshing report updated during audit."""

from __future__ import annotations

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
from basilisk.reporting.analysis import categorize_findings, compute_radar_points
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

# Backward-compat aliases (imported by html.py and tests)
_is_noise = is_noise
_extract_attack_surface = extract_attack_surface
_build_site_tree = build_site_tree
_build_plugin_matrix = build_plugin_matrix


class LiveHtmlRenderer:
    """Writes an auto-refreshing HTML report on each pipeline progress event."""

    def __init__(self, output_path: Path, refresh_interval: int = 3) -> None:
        self.output_path = output_path
        self.refresh_interval = refresh_interval
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        self._env.filters["filesize"] = filesize
        self._start_time = time.monotonic()

    def update(self, state: PipelineState) -> None:
        """Called from on_progress callback — rewrite the HTML file."""
        template = self._env.get_template("live_report.html.j2")

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
                })

        all_findings.sort(
            key=lambda x: Severity[x["severity"]].value, reverse=True
        )

        # Filter noise
        actionable_findings = [f for f in all_findings if not is_noise(f)]
        noise_count = len(all_findings) - len(actionable_findings)

        # Aggregate
        aggregated_findings = aggregate_findings(actionable_findings)
        top_findings = [
            f for f in aggregated_findings if f["severity"] in ("CRITICAL", "HIGH")
        ][:5]

        # Risk score
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
        is_running = state.status in ("running", "idle")

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

        html = template.render(
            title="Basilisk Live Audit Report",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status=state.status,
            total_findings=state.total_findings,
            severity_counts=severity_counts,
            phases=phases,
            findings=actionable_findings,
            aggregated_findings=aggregated_findings,
            top_findings=top_findings,
            risk_score=risk_score,
            risk_label=risk_label,
            noise_count=noise_count,
            refresh_interval=self.refresh_interval if is_running else 0,
            elapsed_total=round(elapsed_total, 1),
            is_running=is_running,
            targets_scanned=len(targets),
            plugins_run=len(plugins),
            duration=round(total_duration, 1),
            attack_surface=attack_surface,
            plugin_stats=plugin_stats,
            site_tree=site_tree,
            plugin_matrix=plugin_matrix,
            ssl_details=ssl_details,
            dns_details=dns_details,
            whois_details=whois_details,
            timeline=timeline,
            vuln_categories=vuln_categories,
            radar_points=radar_points,
            exploit_chains=exploit_chains,
            js_intelligence=js_intelligence,
            port_findings=port_findings,
        )

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(html, encoding="utf-8")
