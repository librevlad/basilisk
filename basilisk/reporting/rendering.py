"""Rendering helpers for report generation — site tree, plugin matrix, port map."""

from __future__ import annotations

from collections import defaultdict


# ---------------------------------------------------------------------------
# Site tree (Burp-style)
# ---------------------------------------------------------------------------
def build_site_tree(attack_surface: dict) -> dict:
    """Build a Burp-style hierarchical site tree from all discovered paths.

    Returns ``{host: {"root": node, "total": int}}`` where each node is
    ``{"children": {segment: node}, "entries": [entry_dict]}``.
    """
    tree: dict = {}

    for host, info in attack_surface.get("hosts", {}).items():
        all_entries: list[dict] = []

        for entry in info.get("paths", []):
            if isinstance(entry, dict) and "path" in entry:
                all_entries.append(entry)

        for entry in info.get("admin_panels", []):
            if isinstance(entry, dict) and "path" in entry:
                e = dict(entry)
                e.setdefault("source", "admin")
                all_entries.append(e)

        for entry in info.get("exposed_files", []):
            if isinstance(entry, dict) and "path" in entry:
                e = dict(entry)
                e.setdefault("source", "exposed")
                e.setdefault("status", 200)
                all_entries.append(e)

        for entry in info.get("backup_files", []):
            if isinstance(entry, dict) and "path" in entry:
                e = dict(entry)
                e.setdefault("source", "backup")
                e.setdefault("status", 200)
                all_entries.append(e)

        for entry in info.get("api_endpoints", []):
            if isinstance(entry, dict) and "path" in entry:
                e = dict(entry)
                e.setdefault("source", "api")
                all_entries.append(e)

        if not all_entries:
            continue

        # Deduplicate by path
        seen_paths: set[str] = set()
        unique_entries: list[dict] = []
        for entry in all_entries:
            p = entry["path"]
            if p not in seen_paths:
                seen_paths.add(p)
                unique_entries.append(entry)

        # Build trie
        root: dict = {"children": {}, "entries": []}
        for entry in unique_entries:
            path = entry["path"].strip("/")
            parts = path.split("/") if path else []
            node = root
            for part in parts[:-1]:
                if part not in node["children"]:
                    node["children"][part] = {"children": {}, "entries": []}
                node = node["children"][part]
            if parts:
                leaf = parts[-1]
                if leaf not in node["children"]:
                    node["children"][leaf] = {"children": {}, "entries": []}
                node["children"][leaf]["entries"].append(entry)
            else:
                node["entries"].append(entry)

        tree[host] = {"root": root, "total": len(unique_entries)}

    return tree


# ---------------------------------------------------------------------------
# Plugin execution matrix
# ---------------------------------------------------------------------------
def build_plugin_matrix(results: list) -> dict:
    """Build host x plugin execution matrix.

    Returns ``{"hosts": [...], "plugins": [...], "cells": {host: {plugin: info}}}``.
    """
    hosts_set: set[str] = set()
    plugins_set: set[str] = set()
    cells: dict[str, dict[str, dict]] = defaultdict(dict)

    for r in results:
        hosts_set.add(r.target)
        plugins_set.add(r.plugin)
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in r.findings:
            key = f.severity.label.lower()
            if key in sev_counts:
                sev_counts[key] += 1

        cells[r.target][r.plugin] = {
            "status": r.status,
            "findings": len(r.findings),
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "duration": round(r.duration, 2),
        }

    host_findings = {
        h: sum(c.get("findings", 0) for c in cells.get(h, {}).values())
        for h in hosts_set
    }
    hosts = sorted(hosts_set, key=lambda h: host_findings.get(h, 0), reverse=True)
    plugins = sorted(plugins_set)

    return {"hosts": hosts, "plugins": plugins, "cells": cells}


# ---------------------------------------------------------------------------
# Port → findings correlation
# ---------------------------------------------------------------------------
_PORT_PLUGIN_MAP: dict[str, list[int]] = {
    "ssl": [443, 8443],
    "tls": [443, 8443],
    "cipher": [443, 8443],
    "cert": [443, 8443],
    "ftp": [21],
    "ssh": [22],
    "smtp": [25, 587],
    "dns": [53],
    "mysql": [3306],
    "postgres": [5432],
    "redis": [6379],
    "mongo": [27017],
}


def build_port_findings(results: list) -> dict[str, dict[int, dict]]:
    """Build port -> severity counts mapping per host."""
    pf: dict[str, dict[int, dict]] = defaultdict(lambda: defaultdict(
        lambda: {"critical": 0, "high": 0, "medium": 0},
    ))

    for r in results:
        if not r.findings:
            continue

        ports: list[int] = []
        plugin_lower = r.plugin.lower()
        for keyword, port_list in _PORT_PLUGIN_MAP.items():
            if keyword in plugin_lower:
                ports.extend(port_list)
                break

        if not ports:
            ports = [80, 443]

        for f in r.findings:
            sev = f.severity.label.lower()
            if sev not in ("critical", "high", "medium"):
                continue
            for port in ports:
                pf[r.target][port][sev] += 1

    return {h: dict(ports) for h, ports in pf.items()}


# ---------------------------------------------------------------------------
# File size formatting
# ---------------------------------------------------------------------------
def filesize(value: int | float | None) -> str:
    """Format bytes as human-readable file size."""
    if not value:
        return ""
    v = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024:
            return f"{v:.1f} {unit}" if v >= 10 else f"{v:.2f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"
