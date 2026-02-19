"""Tests for all plugins — meta validation and auto-discovery."""

from __future__ import annotations

from basilisk.core.plugin import BasePlugin, PluginCategory
from basilisk.core.registry import PluginRegistry


class TestAllPluginsMeta:
    """Validate metadata for every plugin."""

    def _get_all_plugins(self) -> list[type[BasePlugin]]:
        registry = PluginRegistry()
        registry.discover()
        return registry.all()

    def test_all_plugins_discovered(self):
        plugins = self._get_all_plugins()
        names = {p.meta.name for p in plugins}
        # 173 plugins total across 10 categories
        expected = {
            # Recon (23)
            "dns_enum", "subdomain_crtsh", "subdomain_hackertarget",
            "subdomain_rapiddns", "subdomain_bruteforce", "reverse_ip", "whois",
            "subdomain_dnsdumpster", "subdomain_virustotal", "subdomain_alienvault",
            "subdomain_wayback", "email_harvest", "asn_lookup",
            "dns_zone_transfer", "robots_parser", "sitemap_parser", "s3_bucket_finder",
            "web_crawler", "shodan_lookup", "github_dorking", "cloud_bucket_enum",
            "subdomain_certspotter", "subdomain_anubis",
            # Scanning (16)
            "port_scan", "ssl_check", "ssl_protocols", "ssl_vulns",
            "ssl_compliance", "service_detect",
            "cors_scan", "cookie_scan", "tls_cipher_scan", "http_methods_scan",
            "websocket_detect", "graphql_detect", "cdn_detect", "dnssec_check",
            "redirect_chain", "ipv6_scan",
            # Analysis (21)
            "http_headers", "tech_detect", "takeover_check",
            "waf_detect", "csp_analyzer", "js_secret_scan", "meta_extract",
            "link_extractor", "form_analyzer", "comment_finder", "version_detect",
            "favicon_hash", "security_txt", "cloud_detect",
            "ssl_cert_chain", "api_detect", "cms_detect",
            "waf_bypass", "prometheus_scrape", "js_api_extract",
            "openapi_parser",
            # Pentesting (55)
            "dir_brute", "git_exposure", "backup_finder", "ftp_anon",
            "sqli_basic", "xss_basic", "open_redirect", "lfi_check",
            "crlf_injection", "host_header_inject",
            "admin_finder", "sensitive_files", "debug_endpoints",
            "error_disclosure", "wordpress_scan", "default_creds",
            "email_spoofing", "csrf_check",
            "port_vuln_check", "admin_brute", "ssrf_check", "path_traversal",
            "http_smuggling", "param_pollution", "subdomain_takeover_active",
            "command_injection", "service_brute",
            "pp_exploit", "idor_exploit", "cloud_metadata_ssrf", "oauth_attack",
            "graphql_exploit", "cors_exploit", "password_reset_poison",
            "race_condition", "param_discover",
            "sqli_advanced", "xss_advanced", "ssrf_advanced",
            "deserialization_check",
            "ssh_brute", "ssti_check", "ssti_verify",
            "nosqli_check", "nosqli_verify", "jwt_attack",
            "wp_brute", "wp_deep_scan", "cache_poison", "xxe_check",
            "idor_check", "actuator_exploit", "api_logic_engine",
            "credential_spray", "prototype_pollution",
            # Exploitation (21)
            "credential_reuse", "cve_exploit", "docker_exploit", "file_upload_bypass",
            "jenkins_exploit", "ldap_enum", "lfi_harvest", "mssql_exploit",
            "mysql_exploit", "nfs_enum", "redis_exploit", "rpc_enum", "smb_enum",
            "smb_exploit", "snmp_enum", "sqli_extract", "tomcat_exploit",
            "vhost_enum", "webshell_deploy", "winrm_check", "wordpress_exploit",
            # Crypto (8)
            "aes_attack", "classical_cipher", "custom_crypto", "hash_crack",
            "hash_extension", "jwt_forge", "prng_crack", "rsa_attack",
            # Lateral (12)
            "ad_acl_abuse", "ad_cert_attack", "asrep_roast",
            "bloodhound_collect", "constrained_deleg", "dcsync",
            "gpp_decrypt", "kerberoast", "ntlm_relay",
            "pass_the_hash", "pass_the_ticket", "secrets_dump",
            # Privesc (7)
            "capability_exploit", "cron_exploit", "kernel_exploit",
            "sudo_exploit", "suid_exploit", "win_service_exploit",
            "win_token_exploit",
            # Post-exploit (7)
            "credential_harvest", "file_system_enum", "linux_enum",
            "network_enum", "process_enum", "user_enum", "windows_enum",
            # Forensics (6)
            "disk_forensics", "file_forensics", "log_analyze",
            "memory_analyze", "pcap_analyze", "steganography",
        }
        assert expected.issubset(names), f"Missing: {expected - names}"
        assert len(names) == 176, f"Expected 176 plugins, got {len(names)}"

    def test_all_have_valid_meta(self):
        for plugin_cls in self._get_all_plugins():
            meta = plugin_cls.meta
            assert meta.name, f"Plugin {plugin_cls} has no name"
            assert meta.display_name, f"Plugin {meta.name} has no display_name"
            assert meta.category in PluginCategory
            assert meta.timeout > 0

    def test_subdomain_providers(self):
        registry = PluginRegistry()
        registry.discover()
        providers = registry.by_provides("subdomains")
        names = {p.meta.name for p in providers}
        assert "subdomain_crtsh" in names
        assert "subdomain_hackertarget" in names
        assert "subdomain_rapiddns" in names
        assert "subdomain_bruteforce" in names
        assert len(providers) >= 7  # 4 original + 3 new subdomain providers

    def test_categories(self):
        registry = PluginRegistry()
        registry.discover()
        for cat in PluginCategory:
            plugins = registry.by_category(cat)
            assert len(plugins) > 0, f"No plugins in category {cat}"

    def test_recon_count(self):
        registry = PluginRegistry()
        registry.discover()
        recon = registry.by_category(PluginCategory.RECON)
        assert len(recon) == 23

    def test_scanning_count(self):
        registry = PluginRegistry()
        registry.discover()
        scanning = registry.by_category(PluginCategory.SCANNING)
        assert len(scanning) == 16

    def test_analysis_count(self):
        registry = PluginRegistry()
        registry.discover()
        analysis = registry.by_category(PluginCategory.ANALYSIS)
        assert len(analysis) == 21

    def test_pentesting_count(self):
        registry = PluginRegistry()
        registry.discover()
        pentesting = registry.by_category(PluginCategory.PENTESTING)
        assert len(pentesting) == 55

    def test_exploitation_count(self):
        registry = PluginRegistry()
        registry.discover()
        exploitation = registry.by_category(PluginCategory.EXPLOITATION)
        assert len(exploitation) == 21

    def test_crypto_count(self):
        registry = PluginRegistry()
        registry.discover()
        crypto = registry.by_category(PluginCategory.CRYPTO)
        assert len(crypto) == 8

    def test_lateral_count(self):
        registry = PluginRegistry()
        registry.discover()
        lateral = registry.by_category(PluginCategory.LATERAL)
        assert len(lateral) == 12

    def test_privesc_count(self):
        registry = PluginRegistry()
        registry.discover()
        privesc = registry.by_category(PluginCategory.PRIVESC)
        assert len(privesc) == 7

    def test_post_exploit_count(self):
        registry = PluginRegistry()
        registry.discover()
        post_exploit = registry.by_category(PluginCategory.POST_EXPLOIT)
        assert len(post_exploit) == 7

    def test_forensics_count(self):
        registry = PluginRegistry()
        registry.discover()
        forensics = registry.by_category(PluginCategory.FORENSICS)
        assert len(forensics) == 6

    def test_execution_order_all(self):
        """Resolve execution order for all plugins."""
        registry = PluginRegistry()
        registry.discover()
        order = registry.resolve_order(registry.names)
        assert len(order) == len(registry.all())
        # dns_enum should come before reverse_ip
        names = [p.meta.name for p in order]
        if "dns_enum" in names and "reverse_ip" in names:
            assert names.index("dns_enum") < names.index("reverse_ip")
        # port_scan should come before service_detect
        if "port_scan" in names and "service_detect" in names:
            assert names.index("port_scan") < names.index("service_detect")

    def test_no_duplicate_names(self):
        registry = PluginRegistry()
        registry.discover()
        names = [p.meta.name for p in registry.all()]
        assert len(names) == len(set(names)), "Duplicate plugin names!"
