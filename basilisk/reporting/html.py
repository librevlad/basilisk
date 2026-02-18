"""HTML report renderer using Jinja2."""

from __future__ import annotations

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
)

TEMPLATES_DIR = Path(__file__).parent / "templates"


class HtmlRenderer:
    """Renders audit results as a styled HTML report."""

    def render(self, state: PipelineState, output_dir: Path) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"report_{timestamp}.html"

        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        template = env.get_template("report.html.j2")

        # Prepare data
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
                    "confidence": finding.confidence,
                    "verified": finding.verified,
                    "false_positive_risk": finding.false_positive_risk,
                })

        all_findings.sort(
            key=lambda x: Severity[x["severity"]].value, reverse=True
        )

        # Filter noise
        actionable_findings = [f for f in all_findings if not is_noise(f)]
        noise_count = len(all_findings) - len(actionable_findings)

        # Aggregate findings
        aggregated_findings = aggregate_findings(actionable_findings)

        # Top critical/high for executive summary
        top_findings = [
            f for f in aggregated_findings if f["severity"] in ("CRITICAL", "HIGH")
        ][:5]

        # Risk score: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=0.5, INFO=0
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

        # Compute extra stats
        targets = {r.target for r in state.results}
        plugins = {r.plugin for r in state.results}
        total_duration = sum(r.duration for r in state.results)

        attack_surface = extract_attack_surface(state.results)
        site_tree = build_site_tree(attack_surface)

        plugin_stats = extract_plugin_stats(state.results)
        ssl_details = extract_ssl_details(state.results)
        dns_details = extract_dns_details(state.results)
        whois_details = extract_whois_details(state.results)
        timeline = build_timeline(actionable_findings, state.results)
        vuln_categories = categorize_findings(actionable_findings)
        radar_points = compute_radar_points(vuln_categories)
        exploit_chains = detect_exploit_chains(aggregated_findings)
        plugin_matrix = build_plugin_matrix(state.results)
        js_intelligence = extract_js_intelligence(state.results)
        port_findings = build_port_findings(state.results)
        remediation_priority = compute_remediation_priority(aggregated_findings)
        quality_metrics = compute_quality_metrics(state.results)

        # Phase stats
        phase_list = []
        for name, phase in state.phases.items():
            phase_list.append({
                "name": name,
                "status": phase.status,
                "total": phase.total,
                "completed": phase.completed,
                "pct": round(phase.progress_pct, 1),
                "elapsed": round(phase.elapsed, 1),
            })

        html = template.render(
            title="Basilisk Security Audit Report",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status=state.status,
            total_findings=state.total_findings,
            severity_counts=severity_counts,
            phases=phase_list,
            findings=actionable_findings,
            aggregated_findings=aggregated_findings,
            total_aggregated_count=len(aggregated_findings),
            total_raw_count=len(actionable_findings),
            top_findings=top_findings,
            risk_score=risk_score,
            risk_label=risk_label,
            noise_count=noise_count,
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
            skipped_plugins=state.skipped_plugins,
        )

        output_path.write_text(html, encoding="utf-8")
        return output_path
