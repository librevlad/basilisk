"""Data extraction from plugin results for report generation."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from basilisk.reporting.filtering import url_to_path

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from basilisk.models.result import PluginResult


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

    # Enrich from ssl_protocols plugin results
    details_by_target: dict[str, dict] = {d["target"]: d for d in details}
    for r in results:
        if r.plugin != "ssl_protocols" or not r.data:
            continue
        if r.target in details_by_target:
            for key in ("protocols", "ciphers", "curves"):
                if key in r.data:
                    details_by_target[r.target][key] = r.data[key]

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
