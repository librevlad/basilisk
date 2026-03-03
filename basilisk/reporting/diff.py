"""Historical report diff — compare two ReportModel instances."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from basilisk.reporting.model import ReportModel


@dataclass
class ReportDiff:
    """Result of comparing two reports."""

    new_vulnerabilities: list[str] = field(default_factory=list)
    resolved_vulnerabilities: list[str] = field(default_factory=list)
    severity_changes: list[dict[str, str]] = field(default_factory=list)
    confidence_changes: list[dict[str, Any]] = field(default_factory=list)
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    new_services: int = 0
    removed_services: int = 0
    coverage_delta: float = 0.0
    new_endpoints: list[str] = field(default_factory=list)
    removed_endpoints: list[str] = field(default_factory=list)


def compare_reports(report_a: ReportModel, report_b: ReportModel) -> ReportDiff:
    """Diff two reports by comparing vulnerability IDs, topology, and severity.

    report_a is the baseline (older), report_b is the new (current).
    """
    diff = ReportDiff()

    # --- Vulnerability diff ---
    vulns_a = {v.vulnerability_id: v for v in report_a.vulnerabilities}
    vulns_b = {v.vulnerability_id: v for v in report_b.vulnerabilities}

    ids_a = set(vulns_a.keys())
    ids_b = set(vulns_b.keys())

    diff.new_vulnerabilities = sorted(ids_b - ids_a)
    diff.resolved_vulnerabilities = sorted(ids_a - ids_b)

    # Check for severity and confidence changes in shared vulns
    for vid in sorted(ids_a & ids_b):
        va = vulns_a[vid]
        vb = vulns_b[vid]

        if va.severity != vb.severity:
            diff.severity_changes.append({
                "id": vid,
                "old_severity": va.severity,
                "new_severity": vb.severity,
            })

        if abs(va.confidence_aggregate - vb.confidence_aggregate) > 0.001:
            diff.confidence_changes.append({
                "id": vid,
                "old_confidence": va.confidence_aggregate,
                "new_confidence": vb.confidence_aggregate,
            })

    # --- Topology diff ---
    hosts_a = set(report_a.topology.keys())
    hosts_b = set(report_b.topology.keys())

    diff.new_hosts = sorted(hosts_b - hosts_a)
    diff.removed_hosts = sorted(hosts_a - hosts_b)

    # Service count diff
    services_a = sum(
        len(topo.get("services", [])) for topo in report_a.topology.values()
    )
    services_b = sum(
        len(topo.get("services", [])) for topo in report_b.topology.values()
    )
    diff.new_services = max(0, services_b - services_a)
    diff.removed_services = max(0, services_a - services_b)

    # --- Coverage delta (risk score change) ---
    diff.coverage_delta = round(
        report_b.statistics.risk_score - report_a.statistics.risk_score, 2,
    )

    # --- Endpoint diff ---
    endpoints_a: set[str] = set()
    endpoints_b: set[str] = set()
    for host, topo in report_a.topology.items():
        for ep in topo.get("endpoints", []):
            endpoints_a.add(f"{host}{ep}")
    for host, topo in report_b.topology.items():
        for ep in topo.get("endpoints", []):
            endpoints_b.add(f"{host}{ep}")
    diff.new_endpoints = sorted(endpoints_b - endpoints_a)
    diff.removed_endpoints = sorted(endpoints_a - endpoints_b)

    return diff
