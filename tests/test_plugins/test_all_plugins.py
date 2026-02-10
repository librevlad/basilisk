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
        # 74 plugins total (removed misconfig, clickjacking_check, error_page_analyze; added service_brute)
        expected = {
            # Recon (17)
            "dns_enum", "subdomain_crtsh", "subdomain_hackertarget",
            "subdomain_rapiddns", "subdomain_bruteforce", "reverse_ip", "whois",
            "subdomain_dnsdumpster", "subdomain_virustotal", "subdomain_alienvault",
            "subdomain_wayback", "email_harvest", "asn_lookup",
            "dns_zone_transfer", "robots_parser", "sitemap_parser", "s3_bucket_finder",
            # Scanning (13)
            "port_scan", "ssl_check", "service_detect",
            "cors_scan", "cookie_scan", "tls_cipher_scan", "http_methods_scan",
            "websocket_detect", "graphql_detect", "cdn_detect", "dnssec_check",
            "redirect_chain", "ipv6_scan",
            # Analysis (17) — removed error_page_analyze
            "http_headers", "tech_detect", "takeover_check",
            "waf_detect", "csp_analyzer", "js_secret_scan", "meta_extract",
            "link_extractor", "form_analyzer", "comment_finder", "version_detect",
            "favicon_hash", "security_txt", "cloud_detect",
            "ssl_cert_chain", "api_detect", "cms_detect",
            # Pentesting (27) — removed misconfig, clickjacking_check; added service_brute
            "dir_brute", "git_exposure", "backup_finder", "ftp_anon",
            "sqli_basic", "xss_basic", "open_redirect", "lfi_check",
            "crlf_injection", "host_header_inject",
            "admin_finder", "sensitive_files", "debug_endpoints",
            "error_disclosure", "wordpress_scan", "default_creds",
            "email_spoofing", "csrf_check",
            "port_vuln_check", "admin_brute", "ssrf_check", "path_traversal",
            "http_smuggling", "param_pollution", "subdomain_takeover_active",
            "command_injection", "service_brute",
        }
        assert expected.issubset(names), f"Missing: {expected - names}"

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
        assert len(recon) >= 7

    def test_scanning_count(self):
        registry = PluginRegistry()
        registry.discover()
        scanning = registry.by_category(PluginCategory.SCANNING)
        assert len(scanning) >= 3

    def test_analysis_count(self):
        registry = PluginRegistry()
        registry.discover()
        analysis = registry.by_category(PluginCategory.ANALYSIS)
        assert len(analysis) >= 3

    def test_pentesting_count(self):
        registry = PluginRegistry()
        registry.discover()
        pentesting = registry.by_category(PluginCategory.PENTESTING)
        assert len(pentesting) >= 5

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
