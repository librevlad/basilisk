"""Vulnerability analysis — categorisation, radar chart, quality metrics, remediation."""

from __future__ import annotations

import math

# ---------------------------------------------------------------------------
# Vulnerability categorisation (OWASP-like) + radar chart
# ---------------------------------------------------------------------------
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


def categorize_findings(findings: list[dict]) -> dict[str, int]:
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


def compute_radar_points(vuln_categories: dict[str, int]) -> list[dict]:
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
        ax = round(cx + r * math.cos(angle), 1)
        ay = round(cy + r * math.sin(angle), 1)
        dx = round(cx + r * val * math.cos(angle), 1)
        dy = round(cy + r * val * math.sin(angle), 1)
        lx = round(cx + (r + 14) * math.cos(angle), 1)
        ly = round(cy + (r + 14) * math.sin(angle), 1)
        points.append({
            "cat": cat, "val": vuln_categories[cat],
            "ax": ax, "ay": ay, "dx": dx, "dy": dy, "lx": lx, "ly": ly,
        })
    return points


# ---------------------------------------------------------------------------
# Remediation priority scoring
# ---------------------------------------------------------------------------
_FIX_EFFORT_TAGS: dict[str, int] = {
    "headers": 1, "cors": 1, "csp": 1, "hsts": 1,
    "secrets": 1, "source-map": 1, "takeover": 1, "dns": 1,
    "open-redirect": 2, "cookie": 2, "config": 2,
    "injection": 3, "sqli": 3, "xss": 3, "ssti": 3,
    "cmdi": 3, "ssrf": 3, "xxe": 3, "deserialization": 3,
    "crypto": 3, "tls": 3, "ssl": 3,
    "auth": 4, "jwt": 4, "session": 4,
}


def compute_remediation_priority(aggregated_findings: list[dict]) -> list[dict]:
    """Score findings by exploitability x impact / fix_effort.

    Returns the top-10 findings sorted by descending priority score.
    """
    scored: list[dict] = []
    for f in aggregated_findings:
        sev = f.get("severity", "INFO")
        confidence = f.get("confidence", 1.0)
        if isinstance(confidence, str):
            try:
                confidence = float(confidence)
            except (ValueError, TypeError):
                confidence = 1.0

        # Exploitability: severity × confidence
        sev_weight = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0}
        exploitability = sev_weight.get(sev, 0) * confidence

        if exploitability == 0:
            continue

        # Fix effort: scan tags for the lowest-effort match
        tags = " ".join(f.get("tags", []))
        title_lower = f.get("title", "").lower()
        combined = f"{tags} {title_lower}"
        effort = 3  # default medium
        for keyword, eff in _FIX_EFFORT_TAGS.items():
            if keyword in combined:
                effort = min(effort, eff)

        effort_label = {1: "Easy", 2: "Moderate", 3: "Hard", 4: "Complex"}.get(effort, "Hard")
        priority = round(exploitability * (4 / effort), 1)
        count = f.get("count", 1)

        scored.append({
            "title": f["title"],
            "severity": sev,
            "confidence": confidence,
            "exploitability": round(exploitability, 1),
            "fix_effort": effort_label,
            "priority": priority,
            "count": count,
            "plugin": f.get("plugin", ""),
            "remediation": f.get("remediation", ""),
        })

    scored.sort(key=lambda x: x["priority"], reverse=True)
    return scored[:10]


# ---------------------------------------------------------------------------
# Scan quality metrics
# ---------------------------------------------------------------------------
def compute_quality_metrics(results: list) -> dict:
    """Compute scan quality metrics from plugin results.

    Returns dict with evidence coverage, confidence distribution,
    error rates, and plugin coverage.
    """
    total_findings = 0
    no_evidence = 0
    low_confidence = 0
    unverified_high = 0
    with_evidence = 0
    high_confidence_high_sev = 0
    total_high_sev = 0
    total_plugins = 0
    successful_plugins = 0
    errored_plugins = 0
    timed_out_plugins = 0
    total_duration = 0.0

    from basilisk.models.result import Severity

    seen_plugins: set[str] = set()

    for r in results:
        total_duration += r.duration

        if r.plugin not in seen_plugins:
            seen_plugins.add(r.plugin)
            total_plugins += 1
            if r.status == "success":
                successful_plugins += 1
            elif r.status == "error":
                errored_plugins += 1
            elif r.status == "timeout":
                timed_out_plugins += 1

        for f in r.findings:
            total_findings += 1
            has_evidence = bool(f.evidence and f.evidence.strip())

            if has_evidence:
                with_evidence += 1
            if f.severity >= Severity.MEDIUM and not has_evidence:
                no_evidence += 1
            if f.confidence < 0.7:
                low_confidence += 1
            if f.severity >= Severity.HIGH:
                total_high_sev += 1
                if not f.verified:
                    unverified_high += 1
                if f.confidence >= 0.8:
                    high_confidence_high_sev += 1

    evidence_pct = round(with_evidence / total_findings * 100, 1) if total_findings else 0
    high_conf_pct = (
        round(high_confidence_high_sev / total_high_sev * 100, 1) if total_high_sev else 0
    )
    plugin_success_pct = (
        round(successful_plugins / total_plugins * 100, 1) if total_plugins else 0
    )

    return {
        "total_findings": total_findings,
        "with_evidence": with_evidence,
        "evidence_pct": evidence_pct,
        "no_evidence_medium_plus": no_evidence,
        "low_confidence": low_confidence,
        "unverified_high": unverified_high,
        "total_high_sev": total_high_sev,
        "high_confidence_high_sev": high_confidence_high_sev,
        "high_conf_pct": high_conf_pct,
        "total_plugins": total_plugins,
        "successful_plugins": successful_plugins,
        "errored_plugins": errored_plugins,
        "timed_out_plugins": timed_out_plugins,
        "plugin_success_pct": plugin_success_pct,
        "total_duration": round(total_duration, 1),
    }
