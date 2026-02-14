"""Shared reporting utilities — used by html.py and live_html.py."""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from typing import TYPE_CHECKING
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from basilisk.models.result import PluginResult

# ---------------------------------------------------------------------------
# Noise filtering
# ---------------------------------------------------------------------------
NOISE_PATTERNS = (
    "no ", "not detected", "not found", "not vulnerable",
    "not reachable", "host not", "no issues",
    "connection refused", "timed out", "no response",
    "host unreachable", "dns resolution failed",
    "paths checked", "hosts checked",
)


def is_noise(finding: dict) -> bool:
    """Check if a finding is informational noise."""
    if finding["severity"] != "INFO":
        return False
    title = finding["title"].lower()
    return any(p in title for p in NOISE_PATTERNS)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------
def url_to_path(url: str, host: str) -> str | None:
    """Extract the path component from a URL, ignoring external hosts."""
    if url.startswith("/"):
        return url.split("?")[0].split("#")[0]
    try:
        parsed = urlparse(url)
        if parsed.hostname and parsed.hostname != host and not parsed.hostname.endswith(
            f".{host}",
        ):
            return None
        return parsed.path or "/"
    except Exception as e:
        logger.debug("url_to_path failed for %r: %s", url, e)
        return None


# ---------------------------------------------------------------------------
# Plugin stats
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Attack surface extraction
# ---------------------------------------------------------------------------
def extract_attack_surface(results: list) -> dict:
    """Extract attack surface data from plugin results for the map."""
    surface: dict = {
        "hosts": {},
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
                "forms": [],
                "internal_ips": [],
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
                path = url_to_path(url, host)
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
                path = url_to_path(url, host)
                if path:
                    entry = {"path": path, "status": 200, "source": "sitemap"}
                    if entry not in h["paths"]:
                        h["paths"].append(entry)

        # Internal links (link_extractor)
        if data.get("internal_links"):
            for url in data["internal_links"]:
                path = url_to_path(url, host)
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

        # Forms (js_api_extract, form_analyzer)
        if data.get("forms"):
            for form in data["forms"]:
                if isinstance(form, dict) and form not in h["forms"]:
                    h["forms"].append(form)

        # Internal IPs (js_api_extract)
        if data.get("internal_ips"):
            for ip in data["internal_ips"]:
                if ip not in h["internal_ips"]:
                    h["internal_ips"].append(ip)

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
# SSL / DNS / WHOIS detail extraction
# ---------------------------------------------------------------------------
def _format_ssl_name(name_dict: dict) -> str:
    """Format SSL subject/issuer dict to readable string."""
    if not name_dict:
        return ""
    cn = name_dict.get("commonName", name_dict.get("CN", ""))
    org = name_dict.get("organizationName", name_dict.get("O", ""))
    if cn and org:
        return f"{cn} ({org})"
    return cn or org or str(next(iter(name_dict.values()), ""))


def extract_ssl_details(results: list) -> list[dict]:
    """Extract SSL/TLS details from ssl_check plugin results."""
    details = []
    for r in results:
        if r.plugin != "ssl_check" or not r.data:
            continue
        d = r.data
        if not d.get("ssl_available", False):
            continue
        # ssl_check stores cert info inside "ssl_info" sub-dict
        ssl_info = d.get("ssl_info", {})
        entry = {"target": r.target}
        # Format subject/issuer as readable strings
        if ssl_info.get("subject"):
            entry["subject"] = _format_ssl_name(ssl_info["subject"])
        if ssl_info.get("issuer"):
            entry["issuer"] = _format_ssl_name(ssl_info["issuer"])
        # Pull scalar fields from ssl_info
        for key in ("not_before", "not_after", "serial_number",
                     "san", "protocol", "cipher", "key_size",
                     "is_expired", "is_self_signed", "days_until_expiry"):
            val = ssl_info.get(key)
            if val is not None and val != "" and val != 0 and val != []:
                entry[key] = val
        # Pull from top-level data
        for key in ("chain", "protocols", "ciphers", "grade"):
            if key in d:
                entry[key] = d[key]
        if entry.keys() - {"target"}:
            details.append(entry)
    return details


def extract_dns_details(results: list) -> list[dict]:
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


def extract_whois_details(results: list) -> dict[str, dict]:
    """Extract WHOIS info from whois plugin results."""
    info: dict[str, dict] = {}
    for r in results:
        if r.plugin != "whois_lookup" or not r.data:
            continue
        info[r.target] = r.data
    return info


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
# JS intelligence aggregation
# ---------------------------------------------------------------------------
def extract_js_intelligence(results: list) -> dict:
    """Aggregate all JS-related discoveries across hosts."""
    api_paths_by_host: dict[str, list[str]] = {}
    secrets_by_host: dict[str, list[str]] = {}
    forms_by_host: dict[str, list[dict]] = {}
    internal_ips_by_host: dict[str, list[str]] = {}
    source_maps: list[str] = []
    graphql_endpoints: list[str] = []
    websocket_urls: list[str] = []
    total_js_files = 0
    total_paths = 0
    total_secrets = 0
    total_pages = 0
    total_forms = 0

    for r in results:
        if r.plugin != "js_api_extract" or not r.data:
            continue
        d = r.data
        paths = d.get("api_paths", [])
        if paths:
            api_paths_by_host[r.target] = paths
            total_paths += len(paths)

        sc = d.get("secrets_count", 0)
        if sc > 0:
            total_secrets += sc
            secret_names = [
                f.title.split(" found in JS")[0]
                for f in r.findings
                if "found in JS" in f.title
            ]
            if secret_names:
                secrets_by_host[r.target] = secret_names

        forms = d.get("forms", [])
        if forms:
            forms_by_host[r.target] = forms
            total_forms += len(forms)

        ips = d.get("internal_ips", [])
        if ips:
            internal_ips_by_host[r.target] = ips

        for sm in d.get("source_maps", []):
            if sm not in source_maps:
                source_maps.append(sm)

        for ep in d.get("graphql_endpoints", []):
            if ep not in graphql_endpoints:
                graphql_endpoints.append(ep)

        for ws in d.get("websocket_urls", []):
            if ws not in websocket_urls:
                websocket_urls.append(ws)

        total_js_files += d.get("js_files_scanned", 0)
        total_pages += d.get("pages_scanned", 0)

    return {
        "api_paths_by_host": api_paths_by_host,
        "secrets_by_host": secrets_by_host,
        "forms_by_host": forms_by_host,
        "internal_ips_by_host": internal_ips_by_host,
        "source_maps": source_maps,
        "graphql_endpoints": graphql_endpoints,
        "websocket_urls": websocket_urls,
        "total_js_files": total_js_files,
        "total_paths": total_paths,
        "total_secrets": total_secrets,
        "total_pages": total_pages,
        "total_forms": total_forms,
    }


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
