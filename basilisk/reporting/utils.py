"""Shared reporting utilities — facade re-exporting from focused submodules.

All public symbols are available here for backward compatibility.
Prefer importing from the specific submodule for new code.
"""

from __future__ import annotations

from basilisk.reporting.aggregation import (
    _PLUGIN_TO_GROUP,
    OVERLAP_GROUPS,
    _dedup_key,
    aggregate_findings,
    build_timeline,
    detect_exploit_chains,
)
from basilisk.reporting.analysis import (
    _FIX_EFFORT_TAGS,
    VULN_CATEGORY_MAP,
    categorize_findings,
    compute_quality_metrics,
    compute_radar_points,
    compute_remediation_priority,
)
from basilisk.reporting.extraction import (
    _format_ssl_name,
    extract_attack_surface,
    extract_dns_details,
    extract_js_intelligence,
    extract_plugin_stats,
    extract_ssl_details,
    extract_whois_details,
)
from basilisk.reporting.filtering import (
    NOISE_PATTERNS,
    is_noise,
    url_to_path,
)
from basilisk.reporting.rendering import (
    _PORT_PLUGIN_MAP,
    build_plugin_matrix,
    build_port_findings,
    build_site_tree,
    filesize,
)

__all__ = [
    # filtering
    "NOISE_PATTERNS",
    "is_noise",
    "url_to_path",
    # extraction
    "_format_ssl_name",
    "extract_attack_surface",
    "extract_dns_details",
    "extract_js_intelligence",
    "extract_plugin_stats",
    "extract_ssl_details",
    "extract_whois_details",
    # rendering
    "_PORT_PLUGIN_MAP",
    "build_plugin_matrix",
    "build_port_findings",
    "build_site_tree",
    "filesize",
    # aggregation
    "OVERLAP_GROUPS",
    "_PLUGIN_TO_GROUP",
    "_dedup_key",
    "aggregate_findings",
    "build_timeline",
    "detect_exploit_chains",
    # analysis
    "VULN_CATEGORY_MAP",
    "_FIX_EFFORT_TAGS",
    "categorize_findings",
    "compute_quality_metrics",
    "compute_radar_points",
    "compute_remediation_priority",
]
