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
    "tls": {"ssl_check", "ssl_protocols", "ssl_compliance", "ssl_vulns", "tls_cipher_scan"},
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
    """Detect exploit chains via attack graph analysis.

    Reconstructs minimal ``PluginResult`` objects from aggregated finding dicts,
    builds an :class:`~basilisk.core.attack_graph.AttackGraph`, and returns
    paths in the ``{"name", "risk", "steps"}`` format the report templates expect.
    """
    from basilisk.core.attack_graph import AttackGraph
    from basilisk.models.result import Finding, PluginResult, Severity

    # Group aggregated finding dicts by (plugin, target) → PluginResult
    sev_map = {s.label: s for s in Severity}
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    data_by_plugin: dict[str, dict] = defaultdict(dict)

    for f in aggregated_findings:
        plugin = f.get("plugin", "")
        fallback = f.get("affected_targets", [""])[0] if "affected_targets" in f else ""
        target = f.get("target", fallback)
        sev = sev_map.get(f.get("severity", "INFO"), Severity.INFO)
        tags = f.get("tags", [])
        groups[(plugin, target)].append(Finding(
            severity=sev,
            title=f.get("title", ""),
            evidence=f.get("evidence", ""),
            tags=tags if isinstance(tags, list) else [],
        ))
        if f.get("data"):
            data_by_plugin[plugin].update(f["data"])

    results: list[PluginResult] = []
    for (plugin, target), findings in groups.items():
        results.append(PluginResult.success(
            plugin=plugin,
            target=target,
            findings=findings,
            data=data_by_plugin.get(plugin, {}),
        ))

    graph = AttackGraph.from_results(results)
    return graph.to_report_chains()


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
