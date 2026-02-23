"""Unified report data assembly — single source of truth for template variables."""

from __future__ import annotations

from datetime import datetime

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


def build_report_data(state: PipelineState) -> dict:
    """Build all template variables from PipelineState.

    Returns a dict ready for ``template.render(**data)``.
    Both HtmlRenderer and LiveReportEngine call this instead of
    duplicating the extraction/analysis/rendering pipeline.
    """
    # 1. Flatten findings into dicts
    severity_counts = {s.label: 0 for s in Severity}
    all_findings: list[dict] = []
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
        key=lambda x: Severity[x["severity"]].value, reverse=True,
    )

    # 2. Filter noise, aggregate, top findings
    actionable_findings = [f for f in all_findings if not is_noise(f)]
    noise_count = len(all_findings) - len(actionable_findings)
    aggregated_findings = aggregate_findings(actionable_findings)

    top_findings = [
        f for f in aggregated_findings if f["severity"] in ("CRITICAL", "HIGH")
    ][:5]

    # 3. Risk score
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

    # 4. Stats
    targets = {r.target for r in state.results}
    plugins = {r.plugin for r in state.results}
    total_duration = sum(r.duration for r in state.results)

    # 5. Extraction / analysis / rendering
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

    # 6. Phase stats
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

    # 7. Host → scheme map for correct link generation
    host_schemes = dict(state.http_schemes) if state.http_schemes else {}
    tls_ports = {443, 8443, 9443, 4443}
    for t in targets:
        if t not in host_schemes or host_schemes[t] is None:
            if ":" in t:
                try:
                    port = int(t.rsplit(":", 1)[1])
                    host_schemes[t] = "https" if port in tls_ports else "http"
                except ValueError:
                    host_schemes[t] = "https"
            else:
                host_schemes[t] = "https"

    return {
        "title": "Basilisk Security Audit Report",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": state.status,
        "total_findings": state.total_findings,
        "severity_counts": severity_counts,
        "phases": phases,
        "findings": actionable_findings,
        "aggregated_findings": aggregated_findings,
        "total_aggregated_count": len(aggregated_findings),
        "total_raw_count": len(actionable_findings),
        "top_findings": top_findings,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "noise_count": noise_count,
        "targets_scanned": len(targets),
        "plugins_run": len(plugins),
        "duration": round(total_duration, 1),
        "attack_surface": attack_surface,
        "plugin_stats": plugin_stats,
        "ssl_details": ssl_details,
        "dns_details": dns_details,
        "whois_details": whois_details,
        "timeline": timeline,
        "vuln_categories": vuln_categories,
        "radar_points": radar_points,
        "exploit_chains": exploit_chains,
        "site_tree": site_tree,
        "plugin_matrix": plugin_matrix,
        "js_intelligence": js_intelligence,
        "port_findings": port_findings,
        "remediation_priority": remediation_priority,
        "quality_metrics": quality_metrics,
        "skipped_plugins": state.skipped_plugins,
        "host_schemes": host_schemes,
    }
