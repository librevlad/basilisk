"""Shared reporting utilities — used by html.py and live_html.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from basilisk.models.result import PluginResult


def extract_plugin_stats(results: list[PluginResult]) -> list[dict]:
    """Extract per-plugin performance stats from a list of results.

    Returns a list of dicts sorted by finding count (descending).
    """
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
