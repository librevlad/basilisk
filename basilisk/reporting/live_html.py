"""Live HTML renderer — auto-refreshing report updated during audit."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader

from basilisk.core.pipeline import PipelineState
from basilisk.models.result import Severity

TEMPLATES_DIR = Path(__file__).parent / "templates"

# INFO findings matching these patterns are noise (hidden by default)
NOISE_PATTERNS = (
    "no ", "not detected", "not found", "not vulnerable",
    "not reachable", "host not", "no issues",
    "connection refused", "timed out", "no response",
    "host unreachable", "dns resolution failed",
    "paths checked", "hosts checked",
)


def _is_noise(finding: dict) -> bool:
    """Check if a finding is informational noise."""
    if finding["severity"] != "INFO":
        return False
    title = finding["title"].lower()
    return any(p in title for p in NOISE_PATTERNS)


def _url_to_path(url: str, host: str) -> str | None:
    """Extract the path component from a URL, ignoring external hosts."""
    if url.startswith("/"):
        return url.split("?")[0].split("#")[0]
    try:
        parsed = urlparse(url)
        if parsed.hostname and parsed.hostname != host and not parsed.hostname.endswith(f".{host}"):
            return None
        return parsed.path or "/"
    except Exception:
        return None


def _extract_attack_surface(results: list) -> dict:
    """Extract attack surface data from plugin results for the map."""
    surface: dict = {
        "hosts": {},  # host -> {ports, services, tech, paths, ...}
        "subdomains": [],
        "emails": [],
    }

    all_subdomains: set[str] = set()

    for result in results:
        host = result.target
        data = result.data

        if host not in surface["hosts"]:
            surface["hosts"][host] = {
                "ports": [],
                "services": [],
                "tech": [],
                "paths": [],
                "admin_panels": [],
                "exposed_files": [],
                "backup_files": [],
                "api_endpoints": [],
                "methods": [],
                "waf": [],
                "cms": [],
                "cloud": [],
                "dns_records": [],
            }

        h = surface["hosts"][host]

        # Ports & services
        if data.get("open_ports"):
            for p in data["open_ports"]:
                if isinstance(p, dict) and p not in h["ports"]:
                    h["ports"].append(p)
        if data.get("services"):
            for s in data["services"]:
                if isinstance(s, dict) and s not in h["services"]:
                    h["services"].append(s)

        # Technologies
        if data.get("technologies"):
            for t in data["technologies"]:
                if t not in h["tech"]:
                    h["tech"].append(t)

        # CMS
        if data.get("cms"):
            for c in data["cms"]:
                if isinstance(c, dict) and c not in h["cms"]:
                    h["cms"].append(c)

        # Paths (dir_brute)
        if data.get("found_paths"):
            for p in data["found_paths"]:
                if isinstance(p, dict):
                    entry = dict(p)
                    entry.setdefault("source", "brute")
                    if entry not in h["paths"]:
                        h["paths"].append(entry)

        # Crawled URLs (web_crawler)
        if data.get("crawled_urls"):
            for url in data["crawled_urls"]:
                path = _url_to_path(url, host)
                if path:
                    entry = {"path": path, "status": 200, "source": "crawler"}
                    if entry not in h["paths"]:
                        h["paths"].append(entry)

        # Disallowed paths (robots_parser)
        if data.get("disallow_paths"):
            for dp in data["disallow_paths"]:
                path = dp if isinstance(dp, str) else str(dp)
                entry = {"path": path, "status": 0, "source": "robots"}
                if entry not in h["paths"]:
                    h["paths"].append(entry)

        # Sitemap URLs (sitemap_parser)
        if data.get("urls") and result.plugin in ("sitemap_parser", "sitemap"):
            for url in data["urls"]:
                path = _url_to_path(url, host)
                if path:
                    entry = {"path": path, "status": 200, "source": "sitemap"}
                    if entry not in h["paths"]:
                        h["paths"].append(entry)

        # Internal links (link_extractor)
        if data.get("internal_links"):
            for url in data["internal_links"]:
                path = _url_to_path(url, host)
                if path:
                    entry = {"path": path, "status": 0, "source": "links"}
                    if entry not in h["paths"]:
                        h["paths"].append(entry)

        # Admin panels
        if data.get("admin_panels"):
            for a in data["admin_panels"]:
                if isinstance(a, dict) and a not in h["admin_panels"]:
                    h["admin_panels"].append(a)

        # Git / sensitive files
        for data_key in ("exposed_files", "sensitive_files"):
            if data.get(data_key):
                for f in data[data_key]:
                    entry = f if isinstance(f, dict) else {"path": f}
                    if entry not in h["exposed_files"]:
                        h["exposed_files"].append(entry)

        # Backups
        if data.get("backup_files"):
            for b in data["backup_files"]:
                if isinstance(b, dict) and b not in h["backup_files"]:
                    h["backup_files"].append(b)

        # API endpoints
        if data.get("api_endpoints"):
            for e in data["api_endpoints"]:
                entry = e if isinstance(e, dict) else {"path": e, "status": 200}
                if entry not in h["api_endpoints"]:
                    h["api_endpoints"].append(entry)

        # HTTP methods
        if data.get("methods"):
            for m in data["methods"]:
                if m not in h["methods"]:
                    h["methods"].append(m)

        # WAF
        if data.get("waf"):
            for w in data["waf"]:
                if w not in h["waf"]:
                    h["waf"].append(w)

        # Cloud
        if data.get("cloud_providers"):
            for c in data["cloud_providers"]:
                if c not in h["cloud"]:
                    h["cloud"].append(c)

        # DNS
        if data.get("records"):
            for r in data["records"]:
                if isinstance(r, dict) and r not in h["dns_records"]:
                    h["dns_records"].append(r)

        # Subdomains
        if data.get("subdomains"):
            for s in data["subdomains"]:
                all_subdomains.add(s)

        # Emails
        for key in ("domain_emails", "other_emails"):
            if data.get(key):
                for e in data[key]:
                    if e not in surface["emails"]:
                        surface["emails"].append(e)

    surface["subdomains"] = sorted(all_subdomains)
    return surface


def _build_site_tree(attack_surface: dict) -> dict:
    """Build a Burp-style hierarchical site tree from all discovered paths.

    Returns ``{host: {"root": node, "total": int}}`` where each node is
    ``{"children": {segment: node}, "entries": [entry_dict]}``.
    """
    tree: dict = {}

    for host, info in attack_surface.get("hosts", {}).items():
        all_entries: list[dict] = []

        # Gather from all path-like collections
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
            # Leaf: last segment (or root for "/")
            if parts:
                leaf = parts[-1]
                if leaf not in node["children"]:
                    node["children"][leaf] = {"children": {}, "entries": []}
                node["children"][leaf]["entries"].append(entry)
            else:
                node["entries"].append(entry)

        tree[host] = {"root": root, "total": len(unique_entries)}

    return tree


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


def _filesize(value: int | float | None) -> str:
    """Format bytes as human-readable file size."""
    if not value:
        return ""
    v = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024:
            return f"{v:.1f} {unit}" if v >= 10 else f"{v:.2f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"


class LiveHtmlRenderer:
    """Writes an auto-refreshing HTML report on each pipeline progress event."""

    def __init__(self, output_path: Path, refresh_interval: int = 3) -> None:
        self.output_path = output_path
        self.refresh_interval = refresh_interval
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        self._env.filters["filesize"] = _filesize
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
        actionable_findings = [f for f in all_findings if not _is_noise(f)]
        noise_count = len(all_findings) - len(actionable_findings)

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

        attack_surface = _extract_attack_surface(state.results)
        plugin_stats = _extract_plugin_stats(state.results)
        site_tree = _build_site_tree(attack_surface)

        html = template.render(
            title="Basilisk Live Audit Report",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status=state.status,
            total_findings=state.total_findings,
            severity_counts=severity_counts,
            phases=phases,
            findings=actionable_findings,
            noise_count=noise_count,
            refresh_interval=self.refresh_interval if is_running else 0,
            elapsed_total=round(elapsed_total, 1),
            is_running=is_running,
            targets_scanned=len(targets),
            plugins_run=len(plugins),
            attack_surface=attack_surface,
            plugin_stats=plugin_stats,
            site_tree=site_tree,
        )

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(html, encoding="utf-8")
