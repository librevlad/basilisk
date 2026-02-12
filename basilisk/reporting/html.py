"""HTML report renderer using Jinja2."""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from basilisk.core.pipeline import PipelineState
from basilisk.models.result import Severity
from basilisk.reporting.live_html import _extract_attack_surface, _is_noise

TEMPLATES_DIR = Path(__file__).parent / "templates"

# OWASP-like vulnerability categories for the threat radar
VULN_CATEGORY_MAP: dict[str, list[str]] = {
    "injection": [
        "sqli", "sql injection", "xss", "cross-site scripting", "command injection",
        "ssti", "template injection", "xxe", "xml", "nosql", "ldap injection",
        "crlf", "header injection", "lfi", "local file", "rfi", "remote file",
        "deserialization", "prototype pollution",
    ],
    "auth": [
        "authentication", "password", "credential", "login", "session",
        "jwt", "token", "oauth", "brute", "default cred", "weak password",
        "password reset",
    ],
    "config": [
        "misconfiguration", "config", "cors", "csp", "header", "hsts",
        "x-frame", "server header", "directory listing", "debug", "verbose",
        "admin panel", "actuator", "default page", "http method",
    ],
    "crypto": [
        "ssl", "tls", "certificate", "cipher", "crypto", "encryption",
        "expired", "self-signed", "weak key", "protocol",
    ],
    "disclosure": [
        "information", "disclosure", "exposed", "sensitive", "backup",
        "git", ".env", "stack trace", "error", "version", "banner",
        "email", "comment", "source code", "api key",
    ],
    "access": [
        "access control", "idor", "privilege", "authorization", "forbidden",
        "open redirect", "ssrf", "server-side request", "path traversal",
        "takeover", "subdomain", "cache poison", "smuggling", "race condition",
    ],
}


def _categorize_findings(findings: list[dict]) -> dict[str, int]:
    """Categorize findings into OWASP-like threat categories for the radar."""
    cats: dict[str, int] = {k: 0 for k in VULN_CATEGORY_MAP}
    for f in findings:
        text = f"{f['title']} {f.get('description', '')}".lower()
        tags = " ".join(f.get("tags", []))
        combined = f"{text} {tags}"
        for cat, keywords in VULN_CATEGORY_MAP.items():
            if any(kw in combined for kw in keywords):
                weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                cats[cat] += weight.get(f["severity"], 0)
    return cats


def _compute_radar_points(vuln_categories: dict[str, int]) -> list[dict]:
    """Pre-compute SVG radar chart points for Jinja2 (no trig in templates)."""
    cats = list(vuln_categories.keys())
    n = len(cats)
    if n == 0:
        return []

    max_val = max(vuln_categories.values()) or 1
    cx, cy, r = 140, 140, 110
    points = []
    for idx, cat in enumerate(cats):
        angle = -math.pi / 2 + idx * 2 * math.pi / n
        val = vuln_categories[cat] / max_val
        # Axis endpoint (for grid lines)
        ax = round(cx + r * math.cos(angle), 1)
        ay = round(cy + r * math.sin(angle), 1)
        # Data point
        dx = round(cx + r * val * math.cos(angle), 1)
        dy = round(cy + r * val * math.sin(angle), 1)
        # Label position (slightly beyond axis)
        lx = round(cx + (r + 14) * math.cos(angle), 1)
        ly = round(cy + (r + 14) * math.sin(angle), 1)
        points.append({
            "cat": cat, "val": vuln_categories[cat],
            "ax": ax, "ay": ay, "dx": dx, "dy": dy, "lx": lx, "ly": ly,
        })
    return points


def _extract_plugin_stats(results: list) -> list[dict]:
    """Extract per-plugin performance stats."""
    stats: dict[str, dict] = {}
    for r in results:
        if r.plugin not in stats:
            stats[r.plugin] = {
                "name": r.plugin,
                "targets": 0,
                "findings": 0,
                "duration": 0.0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "errors": 0,
                "status": r.status,
            }
        s = stats[r.plugin]
        s["targets"] += 1
        s["duration"] += r.duration
        s["findings"] += len(r.findings)
        if r.status == "error":
            s["errors"] += 1
        for finding in r.findings:
            sev = finding.severity.label.lower()
            if sev in s:
                s[sev] += 1
    return sorted(stats.values(), key=lambda x: x["findings"], reverse=True)


def _extract_ssl_details(results: list) -> list[dict]:
    """Extract SSL/TLS details from ssl_check plugin results."""
    details = []
    for r in results:
        if r.plugin != "ssl_check" or not r.data:
            continue
        d = r.data
        entry = {"target": r.target}
        if "subject" in d:
            entry["subject"] = d["subject"]
        if "issuer" in d:
            entry["issuer"] = d["issuer"]
        if "not_before" in d:
            entry["not_before"] = d["not_before"]
        if "not_after" in d:
            entry["not_after"] = d["not_after"]
        if "serial" in d:
            entry["serial"] = d["serial"]
        if "san" in d:
            entry["san"] = d["san"]
        if "chain" in d:
            entry["chain"] = d["chain"]
        if "protocols" in d:
            entry["protocols"] = d["protocols"]
        if "ciphers" in d:
            entry["ciphers"] = d["ciphers"]
        if "grade" in d:
            entry["grade"] = d["grade"]
        if entry.keys() - {"target"}:
            details.append(entry)
    return details


def _extract_dns_details(results: list) -> list[dict]:
    """Extract DNS details from dns_enum plugin results."""
    details = []
    for r in results:
        if r.plugin != "dns_enum" or not r.data:
            continue
        entry = {"target": r.target, "records": r.data.get("records", [])}
        if "nameservers" in r.data:
            entry["nameservers"] = r.data["nameservers"]
        if "mx" in r.data:
            entry["mx"] = r.data["mx"]
        details.append(entry)
    return details


def _extract_whois_details(results: list) -> dict[str, dict]:
    """Extract WHOIS info from whois plugin results."""
    info: dict[str, dict] = {}
    for r in results:
        if r.plugin != "whois_lookup" or not r.data:
            continue
        info[r.target] = r.data
    return info


def _build_timeline(all_findings: list[dict], results: list) -> list[dict]:
    """Build a timeline of findings ordered by plugin execution order."""
    timeline: list[dict] = []
    cumulative_duration = 0.0
    for r in results:
        cumulative_duration += r.duration
        for finding in r.findings:
            timeline.append({
                "time_offset": round(cumulative_duration, 1),
                "plugin": r.plugin,
                "target": r.target,
                "severity": finding.severity.label,
                "title": finding.title,
            })
    return timeline


def _detect_exploit_chains(aggregated_findings: list[dict]) -> list[dict]:
    """Detect potential exploit chains from finding combinations."""
    chains: list[dict] = []

    # Pattern: Information Disclosure + Injection = Data Breach path
    disclosures = [f for f in aggregated_findings if f["severity"] in ("LOW", "MEDIUM")
                   and any(k in f["title"].lower() for k in ("exposed", "disclosure", "version",
                           "backup", "git", "debug", "server header", "error"))]
    injections = [f for f in aggregated_findings if f["severity"] in ("HIGH", "CRITICAL")
                  and any(k in f["title"].lower() for k in ("injection", "sqli", "xss",
                          "ssti", "xxe", "command", "lfi", "rfi", "deserialization"))]

    if disclosures and injections:
        chains.append({
            "name": "Recon-to-Exploit",
            "risk": "CRITICAL",
            "steps": [
                {"label": "Information Disclosure", "count": len(disclosures),
                 "detail": disclosures[0]["title"]},
                {"label": "Vulnerability Exploitation", "count": len(injections),
                 "detail": injections[0]["title"]},
                {"label": "Potential Data Breach", "count": 0,
                 "detail": "Impact assessment needed"},
            ],
        })

    # Pattern: Misconfig + Auth issues = Account Takeover
    misconfigs = [f for f in aggregated_findings
                  if any(k in f["title"].lower() for k in ("cors", "csp", "header", "hsts",
                         "cookie", "http method"))]
    auth_issues = [f for f in aggregated_findings
                   if any(k in f["title"].lower() for k in ("auth", "password", "session",
                          "jwt", "token", "credential", "brute", "csrf", "idor"))]

    if misconfigs and auth_issues:
        chains.append({
            "name": "Misconfig-to-Takeover",
            "risk": "HIGH",
            "steps": [
                {"label": "Security Misconfiguration", "count": len(misconfigs),
                 "detail": misconfigs[0]["title"]},
                {"label": "Auth/Session Weakness", "count": len(auth_issues),
                 "detail": auth_issues[0]["title"]},
                {"label": "Account Takeover Risk", "count": 0,
                 "detail": "Manual verification needed"},
            ],
        })

    # Pattern: SSRF / Open Redirect chains
    ssrf_or_redirect = [f for f in aggregated_findings
                        if any(k in f["title"].lower() for k in ("ssrf", "redirect", "smuggling"))]
    sensitive_endpoints = [f for f in aggregated_findings
                          if any(k in f["title"].lower() for k in ("admin", "api", "internal",
                                 "actuator", "metadata", "cloud"))]

    if ssrf_or_redirect and sensitive_endpoints:
        chains.append({
            "name": "SSRF-to-Internal",
            "risk": "CRITICAL",
            "steps": [
                {"label": "Request Manipulation", "count": len(ssrf_or_redirect),
                 "detail": ssrf_or_redirect[0]["title"]},
                {"label": "Internal Service Access", "count": len(sensitive_endpoints),
                 "detail": sensitive_endpoints[0]["title"]},
                {"label": "Infrastructure Compromise", "count": 0,
                 "detail": "Cloud metadata / internal APIs at risk"},
            ],
        })

    return chains


def _aggregate_findings(findings: list[dict]) -> list[dict]:
    """Aggregate duplicate findings across targets.

    Groups by (title, plugin, severity) and merges affected targets.
    Returns a list of aggregated finding dicts with extra fields:
    ``affected_targets``, ``count``, ``is_aggregated``.
    """
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for f in findings:
        key = (f["title"], f["plugin"], f["severity"])
        groups[key].append(f)

    aggregated: list[dict] = []
    for (_title, _plugin, _severity), group in groups.items():
        base = dict(group[0])
        targets = list(dict.fromkeys(f["target"] for f in group))
        base["affected_targets"] = targets
        base["count"] = len(group)
        base["is_aggregated"] = len(group) > 1
        aggregated.append(base)

    aggregated.sort(key=lambda x: Severity[x["severity"]].value, reverse=True)
    return aggregated


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
                })

        all_findings.sort(
            key=lambda x: Severity[x["severity"]].value, reverse=True
        )

        # Filter noise
        actionable_findings = [f for f in all_findings if not _is_noise(f)]
        noise_count = len(all_findings) - len(actionable_findings)

        # Aggregate findings
        aggregated_findings = _aggregate_findings(actionable_findings)

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

        attack_surface = _extract_attack_surface(state.results)

        # New data for War Room template
        plugin_stats = _extract_plugin_stats(state.results)
        ssl_details = _extract_ssl_details(state.results)
        dns_details = _extract_dns_details(state.results)
        whois_details = _extract_whois_details(state.results)
        timeline = _build_timeline(actionable_findings, state.results)
        vuln_categories = _categorize_findings(actionable_findings)
        radar_points = _compute_radar_points(vuln_categories)
        exploit_chains = _detect_exploit_chains(aggregated_findings)

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
        )

        output_path.write_text(html, encoding="utf-8")
        return output_path
