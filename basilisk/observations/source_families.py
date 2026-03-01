"""Source family mapping — classifies plugins into independence groups.

Used by knowledge.state and reasoning.belief for evidence aggregation.
Placed in observations/ to avoid a knowledge→reasoning circular dependency.
"""

from __future__ import annotations

# Map plugin names to source families for independence weighting
SOURCE_FAMILIES: dict[str, str] = {
    # DNS
    "dns_enum": "dns",
    "dns_zone_transfer": "dns",
    "whois": "dns",
    "reverse_ip": "dns",
    "asn_lookup": "dns",
    # Network scanning
    "port_scan": "network_scan",
    "service_detect": "network_scan",
    "shodan_lookup": "network_scan",
    # HTTP probing
    "tech_detect": "http_probe",
    "waf_detect": "http_probe",
    "http_headers": "http_probe",
    "cms_detect": "http_probe",
    "favicon_hash": "http_probe",
    "web_crawler": "http_probe",
    "robots_parser": "http_probe",
    "sitemap_parser": "http_probe",
    "cors_scan": "http_probe",
    "cdn_detect": "http_probe",
    "csp_analyzer": "http_probe",
    # Exploitation
    "sqli_basic": "exploit",
    "sqli_advanced": "exploit",
    "xss_basic": "exploit",
    "xss_advanced": "exploit",
    "xss_dom": "exploit",
    "ssrf_check": "exploit",
    "ssti_basic": "exploit",
    "ssti_advanced": "exploit",
    "command_injection": "exploit",
    "lfi_check": "exploit",
    "jwt_attack": "exploit",
    # Config / leak
    "git_exposure": "config_leak",
    "sensitive_files": "config_leak",
    "js_secret_scan": "config_leak",
    "default_creds": "config_leak",
    "container_config_audit": "config_leak",
    # Verification
    "ssti_verify": "verification",
    "nosqli_verify": "verification",
    "container_verification": "verification",
    "cors_exploit": "verification",
    # Additional exploit/verification plugins
    "ssrf_advanced": "exploit",
    "sqli_extract": "exploit",
    "lfi_harvest": "exploit",
    "file_upload_bypass": "exploit",
    "version_detect": "http_probe",
    "waf_bypass": "exploit",
    "graphql_exploit": "exploit",
    "pp_exploit": "exploit",
    "idor_exploit": "exploit",
}


def get_source_family(plugin_name: str) -> str:
    """Get the source family for a plugin, defaulting to 'general'."""
    return SOURCE_FAMILIES.get(plugin_name, "general")
