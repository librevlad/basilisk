"""Plugin -> Capability mapping for all registered plugins.

Declarative mapping table derived from PluginMeta. Plugins not explicitly
listed get auto-inferred defaults.
"""

from __future__ import annotations

from basilisk.capabilities.capability import ActionType, Capability
from basilisk.core.registry import PluginRegistry

# Explicit capability map: plugin_name -> {requires, produces, cost, noise}
# requires: entity types needed in the graph (e.g. "Host", "Service:http")
# produces: entity types this plugin creates/enriches
CAPABILITY_MAP: dict[str, dict] = {
    # -- Recon -------------------------------------------------------
    "dns_enum": {
        "requires": ["Host"], "produces": ["Host:dns_data"],
        "cost": 1, "noise": 1, "risk_domain": "recon",
    },
    "dns_zone_transfer": {
        "requires": ["Host"], "produces": ["Host:zone_data"],
        "cost": 1, "noise": 2,
    },
    "whois": {
        "requires": ["Host"], "produces": ["Host:whois_data"],
        "cost": 1, "noise": 1,
    },
    "asn_lookup": {
        "requires": ["Host"], "produces": ["Host:asn_data"],
        "cost": 1, "noise": 1,
    },
    "reverse_ip": {
        "requires": ["Host"], "produces": ["Host"],
        "cost": 1, "noise": 1,
    },
    "shodan_lookup": {
        "requires": ["Host"],
        "produces": ["Service", "Technology"],
        "cost": 1, "noise": 1,
    },
    "subdomain_crtsh": {
        "requires": ["Host"], "produces": ["Host:subdomain"],
        "cost": 2, "noise": 1,
    },
    "subdomain_alienvault": {
        "requires": ["Host"], "produces": ["Host:subdomain"],
        "cost": 2, "noise": 1,
    },
    "subdomain_anubis": {
        "requires": ["Host"], "produces": ["Host:subdomain"],
        "cost": 2, "noise": 1,
    },
    "subdomain_bruteforce": {
        "requires": ["Host"], "produces": ["Host:subdomain"],
        "cost": 6, "noise": 3,
    },
    "subdomain_certspotter": {
        "requires": ["Host"], "produces": ["Host:subdomain"],
        "cost": 2, "noise": 1,
    },
    "subdomain_dnsdumpster": {
        "requires": ["Host"], "produces": ["Host:subdomain"],
        "cost": 2, "noise": 1,
    },
    "subdomain_hackertarget": {
        "requires": ["Host"], "produces": ["Host:subdomain"],
        "cost": 2, "noise": 1,
    },
    "subdomain_rapiddns": {
        "requires": ["Host"], "produces": ["Host:subdomain"],
        "cost": 2, "noise": 1,
    },
    "subdomain_virustotal": {
        "requires": ["Host"], "produces": ["Host:subdomain"],
        "cost": 2, "noise": 1,
    },
    "subdomain_wayback": {
        "requires": ["Host"],
        "produces": ["Host:subdomain", "Endpoint"],
        "cost": 2, "noise": 1,
    },
    "web_crawler": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint"],
        "cost": 3, "noise": 2,
    },
    "robots_parser": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint"],
        "cost": 1, "noise": 1,
    },
    "sitemap_parser": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint"],
        "cost": 1, "noise": 1,
    },
    "email_harvest": {
        "requires": ["Host"], "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "github_dorking": {
        "requires": ["Host"], "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "s3_bucket_finder": {
        "requires": ["Host"], "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "cloud_bucket_enum": {
        "requires": ["Host"], "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    # -- Scanning ----------------------------------------------------
    "port_scan": {
        "requires": ["Host"], "produces": ["Service"],
        "cost": 3, "noise": 4, "risk_domain": "network",
    },
    "service_detect": {
        "requires": ["Service"], "produces": ["Technology"],
        "cost": 2, "noise": 2,
    },
    "ssl_check": {
        "requires": ["Service:https"],
        "produces": ["Technology:ssl"],
        "cost": 2, "noise": 1,
    },
    "ssl_compliance": {
        "requires": ["Service:https"],
        "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "ssl_protocols": {
        "requires": ["Service:https"],
        "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "ssl_vulns": {
        "requires": ["Service:https"],
        "produces": ["Vulnerability"],
        "cost": 2, "noise": 1,
    },
    "ssl_cert_chain": {
        "requires": ["Service:https"],
        "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "tls_cipher_scan": {
        "requires": ["Service:https"],
        "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "cors_scan": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "graphql_detect": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint:graphql"],
        "cost": 1, "noise": 2,
    },
    "websocket_detect": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint:websocket"],
        "cost": 1, "noise": 1,
    },
    "cdn_detect": {
        "requires": ["Host"], "produces": ["Technology:cdn"],
        "cost": 1, "noise": 1,
    },
    "cookie_scan": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 1, "noise": 1,
    },
    "dnssec_check": {
        "requires": ["Host"], "produces": ["Finding"],
        "cost": 1, "noise": 1,
    },
    "http_methods_scan": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "ipv6_scan": {
        "requires": ["Host"], "produces": ["Finding"],
        "cost": 1, "noise": 1,
    },
    "redirect_chain": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 1, "noise": 1,
    },
    # -- Analysis ----------------------------------------------------
    "tech_detect": {
        "requires": ["Host", "Service:http"],
        "produces": ["Technology"],
        "cost": 1, "noise": 1, "risk_domain": "web",
    },
    "waf_detect": {
        "requires": ["Host", "Service:http"],
        "produces": ["Technology:waf"],
        "cost": 1, "noise": 2,
    },
    "waf_bypass": {
        "requires": ["Technology:waf"],
        "produces": ["Finding"],
        "cost": 3, "noise": 3,
    },
    "http_headers": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 1, "noise": 1,
    },
    "csp_analyzer": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 1, "noise": 1,
    },
    "cms_detect": {
        "requires": ["Host", "Service:http"],
        "produces": ["Technology:cms"],
        "cost": 1, "noise": 1,
    },
    "version_detect": {
        "requires": ["Technology"],
        "produces": ["Vulnerability"],
        "cost": 1, "noise": 1,
    },
    "takeover_check": {
        "requires": ["Host"], "produces": ["Vulnerability"],
        "cost": 2, "noise": 1,
    },
    "favicon_hash": {
        "requires": ["Host", "Service:http"],
        "produces": ["Technology"],
        "cost": 1, "noise": 1,
    },
    "js_api_extract": {
        "requires": ["Host", "Service:http", "Endpoint"],
        "produces": ["Endpoint", "Finding"],
        "cost": 3, "noise": 1,
    },
    "js_secret_scan": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "openapi_parser": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint"],
        "cost": 2, "noise": 1,
    },
    "api_detect": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint"],
        "cost": 1, "noise": 1,
    },
    "security_txt": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 1, "noise": 1,
    },
    "meta_extract": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 1, "noise": 1,
    },
    "link_extractor": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint"],
        "cost": 2, "noise": 1,
    },
    "form_analyzer": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint"],
        "cost": 2, "noise": 1,
    },
    "cloud_detect": {
        "requires": ["Host", "Service:http"],
        "produces": ["Technology:cloud"],
        "cost": 1, "noise": 1,
    },
    "prometheus_scrape": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "comment_finder": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    # -- Pentesting --------------------------------------------------
    "sqli_basic": {
        "requires": ["Endpoint:params"],
        "produces": ["Finding:sqli", "Vulnerability"],
        "cost": 5, "noise": 7, "risk_domain": "web",
    },
    "sqli_advanced": {
        "requires": ["Endpoint:params"],
        "produces": ["Finding:sqli", "Vulnerability"],
        "cost": 6, "noise": 8,
    },
    "xss_basic": {
        "requires": ["Endpoint:params"],
        "produces": ["Finding:xss"],
        "cost": 4, "noise": 5,
    },
    "xss_advanced": {
        "requires": ["Endpoint:params"],
        "produces": ["Finding:xss"],
        "cost": 5, "noise": 6,
    },
    "xss_dom": {
        "requires": ["Endpoint"],
        "produces": ["Finding"],
        "cost": 5, "noise": 3,
    },
    "param_tampering": {
        "requires": ["Endpoint:params"],
        "produces": ["Finding"],
        "cost": 4, "noise": 3,
    },
    "auth_bypass": {
        "requires": ["Endpoint"],
        "produces": ["Finding", "Credential"],
        "cost": 5, "noise": 4,
    },
    "ssrf_check": {
        "requires": ["Endpoint:params"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 6,
    },
    "ssrf_advanced": {
        "requires": ["Endpoint:params"],
        "produces": ["Vulnerability"],
        "cost": 6, "noise": 7,
    },
    "ssti_check": {
        "requires": ["Endpoint:params"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 6,
    },
    "ssti_verify": {
        "requires": ["Endpoint:params"],
        "produces": ["Finding", "Vulnerability"],
        "cost": 4, "noise": 5,
        "reduces_uncertainty": ["Finding:ssti", "Vulnerability"],
    },
    "lfi_check": {
        "requires": ["Endpoint:params"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 6,
    },
    "xxe_check": {
        "requires": ["Host", "Service:http"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 6,
    },
    "command_injection": {
        "requires": ["Endpoint:params"],
        "produces": ["Vulnerability"],
        "cost": 6, "noise": 8,
    },
    "nosqli_check": {
        "requires": ["Endpoint:params"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 6,
    },
    "nosqli_verify": {
        "requires": ["Endpoint:params"],
        "produces": ["Finding", "Vulnerability"],
        "cost": 4, "noise": 5,
        "reduces_uncertainty": ["Finding:nosqli", "Vulnerability"],
    },
    "dir_brute": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint"],
        "cost": 6, "noise": 8,
    },
    "git_exposure": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 3, "noise": 3,
    },
    "sensitive_files": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 3, "noise": 3,
    },
    "backup_finder": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 4, "noise": 5,
    },
    "admin_finder": {
        "requires": ["Host", "Service:http"],
        "produces": ["Endpoint:admin"],
        "cost": 4, "noise": 5,
    },
    "admin_brute": {
        "requires": ["Endpoint:admin", "Credential"],
        "produces": ["Credential"],
        "cost": 6, "noise": 8,
    },
    "default_creds": {
        "requires": ["Host", "Service:http"],
        "produces": ["Credential"],
        "cost": 3, "noise": 4, "risk_domain": "auth",
    },
    "jwt_attack": {
        "requires": ["Host", "Service:http"],
        "produces": ["Vulnerability"],
        "cost": 4, "noise": 4,
    },
    "cors_exploit": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 3, "noise": 3,
    },
    "cache_poison": {
        "requires": ["Host", "Service:http"],
        "produces": ["Vulnerability"],
        "cost": 4, "noise": 5,
    },
    "http_smuggling": {
        "requires": ["Host", "Service:http"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 6,
    },
    "host_header_inject": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 2, "noise": 3,
    },
    "crlf_injection": {
        "requires": ["Host", "Service:http"],
        "produces": ["Vulnerability"],
        "cost": 3, "noise": 4,
    },
    "open_redirect": {
        "requires": ["Endpoint:params"],
        "produces": ["Finding"],
        "cost": 3, "noise": 4,
    },
    "csrf_check": {
        "requires": ["Endpoint"], "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "idor_check": {
        "requires": ["Endpoint:params"],
        "produces": ["Finding"],
        "cost": 4, "noise": 4,
    },
    "idor_exploit": {
        "requires": ["Endpoint:params"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 5,
    },
    "path_traversal": {
        "requires": ["Endpoint:params"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 6,
    },
    "error_disclosure": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "debug_endpoints": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 2, "noise": 3,
    },
    "deserialization_check": {
        "requires": ["Host", "Service:http"],
        "produces": ["Vulnerability"],
        "cost": 4, "noise": 5,
    },
    "file_upload_check": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding", "Vulnerability"],
        "cost": 4, "noise": 5,
    },
    "session_check": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "graphql_exploit": {
        "requires": ["Endpoint:graphql"],
        "produces": ["Finding", "Vulnerability"],
        "cost": 4, "noise": 5,
    },
    "prototype_pollution": {
        "requires": ["Host", "Service:http"],
        "produces": ["Vulnerability"],
        "cost": 3, "noise": 3,
    },
    "param_pollution": {
        "requires": ["Endpoint:params"],
        "produces": ["Finding"],
        "cost": 2, "noise": 3,
    },
    "param_discover": {
        "requires": ["Endpoint"],
        "produces": ["Endpoint:params"],
        "cost": 4, "noise": 5,
    },
    "race_condition": {
        "requires": ["Endpoint"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 6,
    },
    "email_spoofing": {
        "requires": ["Host"], "produces": ["Finding"],
        "cost": 1, "noise": 1,
    },
    "ftp_anon": {
        "requires": ["Service:ftp"], "produces": ["Finding"],
        "cost": 1, "noise": 2,
    },
    "port_vuln_check": {
        "requires": ["Service"],
        "produces": ["Vulnerability"],
        "cost": 2, "noise": 1,
    },
    "password_reset_poison": {
        "requires": ["Host", "Service:http"],
        "produces": ["Vulnerability"],
        "cost": 3, "noise": 4,
    },
    "credential_spray": {
        "requires": ["Host", "Service:http", "Credential"],
        "produces": ["Credential"],
        "cost": 6, "noise": 8, "risk_domain": "auth",
    },
    "oauth_attack": {
        "requires": ["Host", "Service:http"],
        "produces": ["Vulnerability"],
        "cost": 4, "noise": 4,
    },
    "pp_exploit": {
        "requires": ["Host", "Service:http"],
        "produces": ["Vulnerability"],
        "cost": 4, "noise": 4,
    },
    "subdomain_takeover_active": {
        "requires": ["Host:subdomain"],
        "produces": ["Vulnerability"],
        "cost": 3, "noise": 3,
    },
    "wordpress_scan": {
        "requires": ["Technology:cms"],
        "produces": ["Finding"],
        "cost": 3, "noise": 3,
    },
    "wp_brute": {
        "requires": ["Technology:cms"],
        "produces": ["Credential"],
        "cost": 6, "noise": 8,
    },
    "wp_deep_scan": {
        "requires": ["Technology:cms"],
        "produces": ["Vulnerability"],
        "cost": 6, "noise": 5,
    },
    "ssh_brute": {
        "requires": ["Service:ssh"],
        "produces": ["Credential"],
        "cost": 6, "noise": 8, "risk_domain": "auth",
    },
    "service_brute": {
        "requires": ["Service"], "produces": ["Credential"],
        "cost": 6, "noise": 8,
    },
    "actuator_exploit": {
        "requires": ["Host", "Service:http"],
        "produces": ["Finding", "Vulnerability"],
        "cost": 3, "noise": 3,
    },
    "api_logic_engine": {
        "requires": ["Endpoint:params"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 5,
    },
    "cloud_metadata_ssrf": {
        "requires": ["Endpoint:params"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 6,
    },
    # -- Container Security ------------------------------------------
    "container_discovery": {
        "requires": ["Host"], "produces": ["Technology:container_runtime"],
        "cost": 2, "noise": 2, "risk_domain": "container",
    },
    "container_enumeration": {
        "requires": ["Host", "Technology:docker"],
        "produces": ["Container", "Image"],
        "cost": 3, "noise": 3, "risk_domain": "container",
    },
    "image_fingerprint": {
        "requires": ["Image"], "produces": ["Finding", "Vulnerability"],
        "cost": 3, "noise": 1, "risk_domain": "container",
    },
    "container_config_audit": {
        "requires": ["Container"], "produces": ["Finding"],
        "cost": 3, "noise": 2, "risk_domain": "container",
    },
    "container_escape_probe": {
        "requires": ["Container"], "produces": ["Finding", "Vulnerability"],
        "cost": 5, "noise": 7, "risk_domain": "container",
    },
    "registry_lookup": {
        "requires": ["Host", "Technology:docker"],
        "produces": ["Finding", "Endpoint"],
        "cost": 2, "noise": 2, "risk_domain": "container",
    },
    "container_verification": {
        "requires": ["Finding"], "produces": ["Finding", "Vulnerability"],
        "cost": 3, "noise": 3, "risk_domain": "container",
        "reduces_uncertainty": ["Finding:container", "Finding:escape", "Finding:privileged"],
    },
    # -- Exploitation ------------------------------------------------
    "cve_exploit": {
        "requires": ["Technology"], "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "credential_reuse": {
        "requires": ["Credential"],
        "produces": ["Credential"],
        "cost": 5, "noise": 7,
    },
    "sqli_extract": {
        "requires": ["Vulnerability:sqli"],
        "produces": ["Credential", "Finding"],
        "cost": 7, "noise": 9,
    },
    "lfi_harvest": {
        "requires": ["Vulnerability:lfi"],
        "produces": ["Credential", "Finding"],
        "cost": 6, "noise": 7,
    },
    "file_upload_bypass": {
        "requires": ["Endpoint"], "produces": ["Finding"],
        "cost": 5, "noise": 8,
    },
    "webshell_deploy": {
        "requires": ["Vulnerability"],
        "produces": ["Finding"],
        "cost": 8, "noise": 9,
    },
    "docker_exploit": {
        "requires": ["Technology:docker"],
        "produces": ["Finding"],
        "cost": 4, "noise": 7,
    },
    "jenkins_exploit": {
        "requires": ["Technology:jenkins"],
        "produces": ["Credential", "Finding"],
        "cost": 5, "noise": 6,
    },
    "tomcat_exploit": {
        "requires": ["Technology:tomcat"],
        "produces": ["Finding"],
        "cost": 5, "noise": 6,
    },
    "wordpress_exploit": {
        "requires": ["Technology:cms"],
        "produces": ["Finding"],
        "cost": 5, "noise": 6,
    },
    "redis_exploit": {
        "requires": ["Service:redis"],
        "produces": ["Finding"],
        "cost": 3, "noise": 5,
    },
    "mysql_exploit": {
        "requires": ["Service:mysql"],
        "produces": ["Finding", "Credential"],
        "cost": 4, "noise": 6,
    },
    "mssql_exploit": {
        "requires": ["Service:mssql"],
        "produces": ["Finding", "Credential"],
        "cost": 5, "noise": 7,
    },
    "smb_enum": {
        "requires": ["Service:smb"],
        "produces": ["Finding", "Credential"],
        "cost": 4, "noise": 6,
    },
    "smb_exploit": {
        "requires": ["Service:smb"],
        "produces": ["Vulnerability"],
        "cost": 5, "noise": 6,
    },
    "snmp_enum": {
        "requires": ["Service:snmp"],
        "produces": ["Finding"],
        "cost": 3, "noise": 5,
    },
    "ldap_enum": {
        "requires": ["Service:ldap"],
        "produces": ["Finding"],
        "cost": 4, "noise": 3,
    },
    "nfs_enum": {
        "requires": ["Service:nfs"], "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "rpc_enum": {
        "requires": ["Service:rpc"], "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "vhost_enum": {
        "requires": ["Host", "Service:http"],
        "produces": ["Host"],
        "cost": 6, "noise": 7,
    },
    "winrm_check": {
        "requires": ["Service:winrm"],
        "produces": ["Finding"],
        "cost": 2, "noise": 4,
    },
    # -- Post-Exploit (require shell access via credentials) ----------
    "credential_harvest": {
        "requires": ["Credential"], "produces": ["Credential"],
        "cost": 3, "noise": 2,
    },
    "file_system_enum": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 4, "noise": 2,
    },
    "linux_enum": {
        "requires": ["Credential"],
        "produces": ["Finding", "Credential"],
        "cost": 5, "noise": 3,
    },
    "windows_enum": {
        "requires": ["Credential"],
        "produces": ["Finding", "Credential"],
        "cost": 5, "noise": 3,
    },
    "network_enum": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "process_enum": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "user_enum": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    # -- PrivEsc (require shell access via credentials) ---------------
    "capability_exploit": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "cron_exploit": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 3, "noise": 2,
    },
    "kernel_exploit": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    "sudo_exploit": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 3, "noise": 2,
    },
    "suid_exploit": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 3, "noise": 2,
    },
    "win_service_exploit": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 3, "noise": 2,
    },
    "win_token_exploit": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 2, "noise": 2,
    },
    # -- Lateral (require AD services or credentials) -----------------
    "ad_acl_abuse": {
        "requires": ["Service:ldap"], "produces": ["Finding"],
        "cost": 3, "noise": 3,
    },
    "ad_cert_attack": {
        "requires": ["Service:ldap"], "produces": ["Credential"],
        "cost": 4, "noise": 5,
    },
    "asrep_roast": {
        "requires": ["Service:ldap"], "produces": ["Credential"],
        "cost": 4, "noise": 5,
    },
    "bloodhound_collect": {
        "requires": ["Service:ldap"], "produces": ["Finding"],
        "cost": 6, "noise": 6,
    },
    "constrained_deleg": {
        "requires": ["Service:ldap"], "produces": ["Finding"],
        "cost": 4, "noise": 5,
    },
    "dcsync": {
        "requires": ["Credential", "Service:ldap"], "produces": ["Credential"],
        "cost": 6, "noise": 9,
    },
    "gpp_decrypt": {
        "requires": ["Service:smb"], "produces": ["Credential"],
        "cost": 3, "noise": 2,
    },
    "kerberoast": {
        "requires": ["Service:ldap"], "produces": ["Credential"],
        "cost": 4, "noise": 5, "risk_domain": "auth",
    },
    "ntlm_relay": {
        "requires": ["Service:smb"], "produces": ["Finding"],
        "cost": 5, "noise": 6,
    },
    "pass_the_hash": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 5, "noise": 6,
    },
    "pass_the_ticket": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 5, "noise": 6,
    },
    "secrets_dump": {
        "requires": ["Credential", "Service:smb"], "produces": ["Credential"],
        "cost": 6, "noise": 9,
    },
    # -- Crypto (jwt/prng need HTTP; others need captured data) -------
    "aes_attack": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 6, "noise": 1,
    },
    "classical_cipher": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 3, "noise": 1,
    },
    "custom_crypto": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "hash_crack": {
        "requires": ["Credential"], "produces": ["Credential"],
        "cost": 6, "noise": 1, "risk_domain": "crypto",
    },
    "hash_extension": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 2, "noise": 1,
    },
    "jwt_forge": {
        "requires": ["Service:http"], "produces": ["Finding"],
        "cost": 3, "noise": 1,
    },
    "prng_crack": {
        "requires": ["Service:http"], "produces": ["Finding"],
        "cost": 3, "noise": 1,
    },
    "rsa_attack": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 6, "noise": 1,
    },
    # -- Forensics (require local access via credentials) -------------
    "disk_forensics": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 6, "noise": 1,
    },
    "file_forensics": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 3, "noise": 1,
    },
    "log_analyze": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 3, "noise": 1, "risk_domain": "forensics",
    },
    "memory_analyze": {
        "requires": ["Credential"],
        "produces": ["Finding", "Credential"],
        "cost": 8, "noise": 1,
    },
    "pcap_analyze": {
        "requires": ["Credential"],
        "produces": ["Finding", "Credential"],
        "cost": 6, "noise": 1,
    },
    "steganography": {
        "requires": ["Credential"], "produces": ["Finding"],
        "cost": 3, "noise": 1,
    },
}


def _noise_from_risk(risk_level: str) -> float:
    """Derive noise score from plugin risk_level."""
    return {"safe": 1.0, "noisy": 5.0, "destructive": 9.0}.get(risk_level, 1.0)


_CATEGORY_TO_ACTION: dict[str, ActionType] = {
    "recon": ActionType.ENUMERATION,
    "scanning": ActionType.ENUMERATION,
    "analysis": ActionType.EXPERIMENT,
    "pentesting": ActionType.EXPERIMENT,
    "exploitation": ActionType.EXPLOIT,
    "lateral": ActionType.EXPLOIT,
    "privesc": ActionType.EXPLOIT,
    "post_exploit": ActionType.EXPLOIT,
    "crypto": ActionType.EXPERIMENT,
    "forensics": ActionType.ENUMERATION,
}


def _infer_action_type(category: str, reduces_uncertainty: list[str]) -> ActionType:
    """Auto-infer action type from category, with verification override."""
    if reduces_uncertainty:
        return ActionType.VERIFICATION
    return _CATEGORY_TO_ACTION.get(category, ActionType.ENUMERATION)


def _infer_state_delta(
    produces: list[str], reduces: list[str],
) -> dict[str, object]:
    """Auto-infer expected state delta from produces/reduces knowledge."""
    delta: dict[str, object] = {}
    if produces:
        delta["produces_entities"] = produces
    if reduces:
        delta["strengthens_entities"] = reduces
        delta["uncertainty_reduction"] = 0.3
    else:
        delta["uncertainty_reduction"] = 0.1
    return delta


_CATEGORY_TO_DOMAIN: dict[str, str] = {
    "recon": "recon",
    "scanning": "network",
    "analysis": "web",
    "pentesting": "web",
    "exploitation": "web",
    "lateral": "auth",
    "privesc": "auth",
    "post_exploit": "general",
    "crypto": "crypto",
    "forensics": "forensics",
}


def _infer_risk_domain(category: str) -> str:
    """Auto-infer risk_domain from plugin category."""
    return _CATEGORY_TO_DOMAIN.get(category, "general")


def build_capabilities(registry: PluginRegistry) -> dict[str, Capability]:
    """Build Capability metadata for all registered plugins.

    Plugins in CAPABILITY_MAP use explicit values.
    Others get auto-inferred defaults from PluginMeta.
    """
    capabilities: dict[str, Capability] = {}

    for plugin_cls in registry.all():
        meta = plugin_cls.meta
        name = meta.name

        if name in CAPABILITY_MAP:
            m = CAPABILITY_MAP[name]
            reduces = m.get("reduces_uncertainty", [])
            produces = m["produces"]
            cap = Capability(
                name=name,
                plugin_name=name,
                category=meta.category.value,
                requires_knowledge=m["requires"],
                produces_knowledge=produces,
                cost_score=m["cost"],
                noise_score=m["noise"],
                execution_time_estimate=meta.timeout,
                reduces_uncertainty=reduces,
                risk_domain=m.get("risk_domain", _infer_risk_domain(meta.category.value)),
                action_type=_infer_action_type(meta.category.value, reduces),
                expected_state_delta=_infer_state_delta(produces, reduces),
            )
        else:
            # Auto-infer from PluginMeta
            requires = ["Host"]
            if meta.requires_http:
                requires.append("Service:http")
            produces = list(meta.produces) if meta.produces else ["Finding"]
            cap = Capability(
                name=name,
                plugin_name=name,
                category=meta.category.value,
                requires_knowledge=requires,
                produces_knowledge=produces,
                cost_score=min(meta.timeout / 10.0, 10.0),
                noise_score=_noise_from_risk(meta.risk_level),
                execution_time_estimate=meta.timeout,
                risk_domain=_infer_risk_domain(meta.category.value),
                action_type=_infer_action_type(meta.category.value, []),
                expected_state_delta=_infer_state_delta(produces, []),
            )

        capabilities[name] = cap

    return capabilities
