"""Finding aggregation, deduplication, exploit chain detection, and timeline."""

from __future__ import annotations

from collections import defaultdict

# ---------------------------------------------------------------------------
# Finding aggregation
# ---------------------------------------------------------------------------
# Overlapping plugin groups — findings from the same group on the same
# target with the same severity are semantically the same vulnerability.
# We keep the finding with the longest evidence to preserve detail.
OVERLAP_GROUPS: dict[str, set[str]] = {
    "cors": {"cors_scan", "cors_exploit"},
    "csp": {"http_headers", "csp_analyzer"},
    "path_traversal": {"lfi_check", "path_traversal"},
    "tls": {"ssl_check", "tls_cipher_scan"},
    "asn": {"asn_lookup", "whois_lookup"},
    "xss": {"xss_basic", "xss_advanced"},
}

# Reverse lookup: plugin → group name
_PLUGIN_TO_GROUP: dict[str, str] = {
    plugin: group
    for group, plugins in OVERLAP_GROUPS.items()
    for plugin in plugins
}


def _dedup_key(f: dict) -> str:
    """Canonical key for cross-plugin dedup: group|target|severity|normalised_title."""
    group = _PLUGIN_TO_GROUP.get(f["plugin"], f["plugin"])
    # Normalise title: strip plugin-specific prefixes for comparison
    title = f["title"].lower().strip()
    return f"{group}|{f['target']}|{f['severity']}|{title}"


def aggregate_findings(findings: list[dict]) -> list[dict]:
    """Aggregate duplicate findings across targets.

    Groups by (title, plugin, severity) and merges affected targets.
    Then deduplicates semantically similar findings from overlapping plugins.
    """
    from basilisk.models.result import Severity

    # Phase 1: standard grouping by (title, plugin, severity)
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

    # Phase 2: cross-plugin dedup within overlap groups.
    # For each (group, target, severity) keep the finding with the richest evidence.
    seen: dict[str, int] = {}  # dedup_key → index in final list
    final: list[dict] = []
    for f in aggregated:
        group = _PLUGIN_TO_GROUP.get(f["plugin"])
        if group is None:
            # Plugin not in any overlap group — keep as-is
            final.append(f)
            continue

        dk = f"{group}|{f['severity']}"
        # Build per-target dedup keys
        targets_to_dedup = f.get("affected_targets", [f["target"]])
        is_duplicate = True
        for t in targets_to_dedup:
            key = f"{dk}|{t}"
            if key not in seen:
                is_duplicate = False
                break

        if not is_duplicate:
            idx = len(final)
            for t in targets_to_dedup:
                key = f"{dk}|{t}"
                seen[key] = idx
            final.append(f)
        else:
            # Merge into existing — keep the one with longer evidence
            first_target = targets_to_dedup[0]
            existing_idx = seen.get(f"{dk}|{first_target}")
            if existing_idx is not None and existing_idx < len(final):
                existing = final[existing_idx]
                if len(f.get("evidence", "")) > len(existing.get("evidence", "")):
                    # Swap — new finding has richer evidence
                    f["count"] = existing["count"] + f["count"]
                    merged_targets = list(dict.fromkeys(
                        existing.get("affected_targets", [existing["target"]])
                        + targets_to_dedup
                    ))
                    f["affected_targets"] = merged_targets
                    f["is_aggregated"] = len(merged_targets) > 1
                    final[existing_idx] = f
                else:
                    existing["count"] = existing["count"] + f["count"]
                    merged_targets = list(dict.fromkeys(
                        existing.get("affected_targets", [existing["target"]])
                        + targets_to_dedup
                    ))
                    existing["affected_targets"] = merged_targets
                    existing["is_aggregated"] = len(merged_targets) > 1

    final.sort(key=lambda x: Severity[x["severity"]].value, reverse=True)
    return final


# ---------------------------------------------------------------------------
# Exploit chain detection
# ---------------------------------------------------------------------------
def detect_exploit_chains(aggregated_findings: list[dict]) -> list[dict]:
    """Detect potential exploit chains from finding combinations."""
    chains: list[dict] = []

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


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------
def build_timeline(all_findings: list[dict], results: list) -> list[dict]:
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
