"""Tests for Batch 2 analysis/scanning plugins (10 plugins)."""

from unittest.mock import AsyncMock, MagicMock

from basilisk.models.target import Target

# =====================================================================
# tech_detect
# =====================================================================

class TestTechDetect:
    async def test_detects_from_body(self, mock_ctx):
        from basilisk.plugins.analysis.tech_detect import TechDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[
            ("Server", "nginx/1.25.3"),
            ("X-Powered-By", "PHP/8.2.0"),
        ])
        mock_resp.headers.getall = MagicMock(return_value=[])
        mock_resp.text = AsyncMock(return_value=(
            "<html><head>"
            '<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>'
            '<meta name="generator" content="WordPress 6.4">'
            "</head><body>wp-content wp-includes</body></html>"
        ))
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = TechDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        tech_names = [t["name"] for t in result.data["technologies"]]
        assert "WordPress" in tech_names

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.tech_detect import TechDetectPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = TechDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_version_disclosure_finding(self, mock_ctx):
        from basilisk.plugins.analysis.tech_detect import TechDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[
            ("Server", "Apache/2.4.52"),
        ])
        mock_resp.headers.getall = MagicMock(return_value=[])
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = TechDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        # Should flag server version disclosure
        assert any("version" in f.title.lower() for f in result.findings)


# =====================================================================
# waf_detect
# =====================================================================

class TestWafDetect:
    async def test_cloudflare_cdn(self, mock_ctx):
        from basilisk.plugins.analysis.waf_detect import WafDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[
            ("cf-ray", "abc123"),
            ("server", "cloudflare"),
        ])
        mock_resp.headers.getall = MagicMock(return_value=[])
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)
        mock_ctx.http.head = AsyncMock(return_value=mock_resp)
        mock_ctx.http.request = AsyncMock(return_value=mock_resp)

        plugin = WafDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("cloudflare" in f.title.lower() for f in result.findings)

    async def test_no_waf_detected(self, mock_ctx):
        from basilisk.plugins.analysis.waf_detect import WafDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[])
        mock_resp.headers.getall = MagicMock(return_value=[])
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)
        mock_ctx.http.head = AsyncMock(return_value=mock_resp)
        mock_ctx.http.request = AsyncMock(return_value=mock_resp)

        plugin = WafDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.waf_detect import WafDetectPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = WafDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_huaweicloud_no_false_positive(self, mock_ctx):
        """x-request-id alone should NOT trigger HuaweiCloud WAF."""
        from basilisk.plugins.analysis.waf_detect import WafDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[
            ("x-request-id", "abc-123-def"),
        ])
        mock_resp.headers.getall = MagicMock(return_value=[])
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)
        mock_ctx.http.head = AsyncMock(return_value=mock_resp)
        mock_ctx.http.request = AsyncMock(return_value=mock_resp)

        plugin = WafDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert not any("huawei" in f.title.lower() for f in result.findings)


# =====================================================================
# csp_analyzer
# =====================================================================

class TestCspAnalyzer:
    async def test_no_csp(self, mock_ctx):
        from basilisk.plugins.analysis.csp_analyzer import CspAnalyzerPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[])
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CspAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["grade"] == "F"
        assert any("no content-security-policy" in f.title.lower() for f in result.findings)
        # MEDIUM finding should have evidence
        for f in result.findings:
            if f.severity.value >= 2:
                assert f.evidence, f"Finding '{f.title}' has no evidence"

    async def test_strict_csp_grade_a(self, mock_ctx):
        from basilisk.plugins.analysis.csp_analyzer import CspAnalyzerPlugin

        target = Target.domain("example.com")
        csp = (
            "default-src 'none'; "
            "script-src 'nonce-abc123'; "
            "style-src 'self'; "
            "img-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "report-uri /csp-report"
        )
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[
            ("content-security-policy", csp),
        ])
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CspAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["grade"] in ("A", "B")
        assert result.data["has_nonces"] is True

    async def test_bypass_domain_detected(self, mock_ctx):
        from basilisk.plugins.analysis.csp_analyzer import CspAnalyzerPlugin

        target = Target.domain("example.com")
        csp = "default-src 'self'; script-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com"
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[
            ("content-security-policy", csp),
        ])
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CspAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.data["bypass_domains"]) >= 2
        assert any("bypass" in f.title.lower() for f in result.findings)

    async def test_static_nonce_detection(self, mock_ctx):
        from basilisk.plugins.analysis.csp_analyzer import CspAnalyzerPlugin

        target = Target.domain("example.com")
        # Both requests return same nonce = static nonce
        csp = "script-src 'nonce-STATIC123' 'self'"
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[
            ("content-security-policy", csp),
        ])
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CspAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        # Should detect static nonce
        assert any("static" in f.title.lower() or "nonce" in f.title.lower()
                    for f in result.findings)


# =====================================================================
# takeover_check
# =====================================================================

class TestTakeoverCheck:
    async def test_github_pages_fingerprint(self, mock_ctx):
        from basilisk.plugins.analysis.takeover_check import TakeoverCheckPlugin

        target = Target.domain("blog.example.com")

        # CNAME points to github.io
        cname_record = MagicMock()
        cname_record.value = "example.github.io."

        async def mock_resolve(domain, rtype="A"):
            if rtype == "CNAME":
                return [cname_record]
            return []  # NXDOMAIN

        mock_ctx.dns.resolve = mock_resolve

        mock_resp = AsyncMock()
        mock_resp.status = 404
        mock_resp.text = AsyncMock(
            return_value="There isn't a GitHub Pages site here."
        )
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = TakeoverCheckPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["takeover_vulnerable"]
        assert any("github" in f.title.lower() for f in result.findings)

    async def test_no_takeover(self, mock_ctx):
        from basilisk.plugins.analysis.takeover_check import TakeoverCheckPlugin

        target = Target.domain("example.com")
        mock_ctx.dns.resolve = AsyncMock(return_value=[])
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="<html>Normal page</html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = TakeoverCheckPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert not result.data["takeover_vulnerable"]

    async def test_ns_takeover_uses_value(self, mock_ctx):
        """NS record should use .value, not str() repr."""
        from basilisk.plugins.analysis.takeover_check import TakeoverCheckPlugin

        target = Target.domain("example.com")
        ns_record = MagicMock()
        ns_record.value = "ns1.defunct-provider.com."

        async def mock_resolve(domain, rtype="A"):
            if rtype == "CNAME":
                return []
            if rtype == "NS":
                return [ns_record]
            if rtype == "MX":
                return []
            # A record for ns1 returns empty = unresolvable
            if "defunct" in domain:
                return []
            return []

        mock_ctx.dns.resolve = mock_resolve
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="<html>Normal</html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = TakeoverCheckPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        # Should mention the hostname, not DnsRecord repr
        for f in result.findings:
            if "ns takeover" in f.title.lower():
                assert "defunct-provider.com" in f.title
                assert "DnsRecord" not in f.title

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.takeover_check import TakeoverCheckPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = TakeoverCheckPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# cms_detect
# =====================================================================

class TestCmsDetect:
    async def test_wordpress_body(self, mock_ctx):
        from basilisk.plugins.analysis.cms_detect import CmsDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[])
        mock_resp.text = AsyncMock(return_value=(
            '<html><link rel="stylesheet" href="/wp-content/themes/test/style.css">'
            '<script src="/wp-includes/js/jquery.js"></script></html>'
        ))
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CmsDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any(c["name"] == "WordPress" for c in result.data["cms"])

    async def test_drupal_via_header(self, mock_ctx):
        """x-drupal-cache header should detect Drupal."""
        from basilisk.plugins.analysis.cms_detect import CmsDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[
            ("x-drupal-cache", "HIT"),
            ("x-drupal-dynamic-cache", "MISS"),
        ])
        mock_resp.text = AsyncMock(return_value="<html>No body patterns</html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CmsDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any(c["name"] == "Drupal" for c in result.data["cms"])

    async def test_no_cms(self, mock_ctx):
        from basilisk.plugins.analysis.cms_detect import CmsDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[])
        mock_resp.text = AsyncMock(return_value="<html>Custom site</html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CmsDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.data["cms"]) == 0
        assert "no cms" in result.findings[0].title.lower()

    async def test_meta_generator_version(self, mock_ctx):
        from basilisk.plugins.analysis.cms_detect import CmsDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[])
        mock_resp.text = AsyncMock(return_value=(
            '<html><meta name="generator" content="WordPress 6.4.2"></html>'
        ))
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CmsDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        wp = [c for c in result.data["cms"] if c["name"] == "WordPress"]
        assert len(wp) == 1
        assert wp[0]["version"] == "6.4.2"

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.cms_detect import CmsDetectPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = CmsDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# comment_finder
# =====================================================================

class TestCommentFinder:
    async def test_html_comment_with_secret(self, mock_ctx):
        from basilisk.plugins.analysis.comment_finder import CommentFinderPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=(
            "<html>"
            "<!-- TODO: remove before production -->"
            "<!-- api_key = stripe_secret_FAKE1234567890 -->"
            "<!-- Normal navigation comment -->"
            "</html>"
        ))
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CommentFinderPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["total_comments"] >= 2
        assert len(result.data["sensitive_comments"]) >= 1

    async def test_js_comment_internal_ip(self, mock_ctx):
        from basilisk.plugins.analysis.comment_finder import CommentFinderPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=(
            "<html><script>"
            "// Backend API at 192.168.1.100:8080\n"
            "var x = 1;\n"
            "</script></html>"
        ))
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CommentFinderPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        internal = [c for c in result.data["sensitive_comments"]
                    if c["category"] == "internal_ip"]
        assert len(internal) >= 1

    async def test_no_comments(self, mock_ctx):
        from basilisk.plugins.analysis.comment_finder import CommentFinderPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="<html><body>Clean page</body></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CommentFinderPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["total_comments"] == 0

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.comment_finder import CommentFinderPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = CommentFinderPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# favicon_hash
# =====================================================================

class TestFaviconHash:
    async def test_known_favicon(self, mock_ctx):
        from basilisk.plugins.analysis.favicon_hash import FaviconHashPlugin

        target = Target.domain("example.com")
        real_content = b"fake favicon content"

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=real_content)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = FaviconHashPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data.get("md5")

    async def test_no_favicon(self, mock_ctx):
        from basilisk.plugins.analysis.favicon_hash import FaviconHashPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 404
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = FaviconHashPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "no favicon" in result.findings[0].title.lower()

    async def test_corrupted_hash_fixed(self):
        """Verify the corrupted Drupal hash was fixed."""
        from basilisk.plugins.analysis.favicon_hash import KNOWN_FAVICONS

        # Should be valid 32-char hex
        for md5_hash, tech in KNOWN_FAVICONS.items():
            assert len(md5_hash) == 32, f"Bad hash for {tech}: {md5_hash}"
            assert all(c in "0123456789abcdef" for c in md5_hash), (
                f"Non-hex chars in hash for {tech}: {md5_hash}"
            )

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.favicon_hash import FaviconHashPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = FaviconHashPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# version_detect
# =====================================================================

class TestVersionDetect:
    async def test_apache_version_and_cve(self, mock_ctx):
        from basilisk.plugins.analysis.version_detect import VersionDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {"Server": "Apache/2.4.49"}
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = VersionDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["versions"].get("Apache") == "2.4.49"
        # Should have CVE hits for Apache < 2.4.52
        assert len(result.data["cve_hits"]) > 0
        assert any("cve" in f.title.lower() or "vulnerable" in f.title.lower()
                    for f in result.findings)

    async def test_jquery_version_no_dot_only(self):
        """Version pattern should not match bare '.' as version."""
        import re

        from basilisk.plugins.analysis.version_detect import _BODY_VERSION_RULES

        pattern, tech = _BODY_VERSION_RULES[0]  # jQuery rule
        # Should NOT match "jquery.once.js" or "jquery.min.js"
        for bad in ["jquery.once.js", "jquery.min.js", "jquery.js"]:
            m = re.search(pattern, bad, re.IGNORECASE)
            if m:
                # If it matches, version should not be just "."
                assert m.group(1) != ".", f"Matched bare dot for {bad!r}"

        # Should match "jquery-3.6.0.min.js"
        m = re.search(pattern, "jquery-3.6.0.min.js", re.IGNORECASE)
        assert m and m.group(1) == "3.6.0"

    async def test_error_page_version(self, mock_ctx):
        from basilisk.plugins.analysis.version_detect import VersionDetectPlugin

        target = Target.domain("example.com")

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = AsyncMock()
            if "nonexistent" in url:
                resp.status = 404
                resp.headers = {"Server": "Apache/2.4.58"}
                resp.text = AsyncMock(return_value=(
                    "<html>Not Found. Apache/2.4.58 Server at example.com</html>"
                ))
            else:
                resp.status = 200
                resp.headers = {}
                resp.text = AsyncMock(return_value="<html></html>")
            return resp

        mock_ctx.http.get = mock_get

        plugin = VersionDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "Apache" in result.data["versions"]

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.version_detect import VersionDetectPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = VersionDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# cors_scan
# =====================================================================

class TestCorsScan:
    async def test_wildcard_with_credentials(self, mock_ctx):
        from basilisk.plugins.scanning.cors_scan import CorsScanPlugin

        target = Target.domain("example.com")

        cors_headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "",
            "Access-Control-Allow-Headers": "",
            "Access-Control-Expose-Headers": "",
            "Vary": "",
        }
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.get = MagicMock(side_effect=lambda k, d="": cors_headers.get(k, d))
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)
        mock_ctx.http.request = AsyncMock(return_value=mock_resp)

        plugin = CorsScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("wildcard" in f.title.lower() and "credential" in f.title.lower()
                    for f in result.findings)

    async def test_no_cors_issues(self, mock_ctx):
        from basilisk.plugins.scanning.cors_scan import CorsScanPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.get = MagicMock(return_value="")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)
        mock_ctx.http.request = AsyncMock(return_value=mock_resp)

        plugin = CorsScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("no cors" in f.title.lower() for f in result.findings)

    async def test_arbitrary_origin_reflection(self, mock_ctx):
        from basilisk.plugins.scanning.cors_scan import CorsScanPlugin

        target = Target.domain("example.com")

        async def mock_get(url, headers=None, **kwargs):
            resp = AsyncMock()
            resp.status = 200
            origin = (headers or {}).get("Origin", "")
            resp.headers = MagicMock()
            resp.headers.get = lambda k, d="": {
                "Access-Control-Allow-Origin": origin,  # reflects any origin
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "",
                "Access-Control-Allow-Headers": "",
                "Access-Control-Expose-Headers": "",
                "Vary": "",
            }.get(k, d)
            return resp

        mock_ctx.http.get = mock_get
        mock_ctx.http.request = AsyncMock(return_value=AsyncMock(
            status=200,
            headers=MagicMock(get=lambda k, d="": ""),
        ))

        plugin = CorsScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("reflect" in f.title.lower() or "arbitrary" in f.title.lower()
                    for f in result.findings)

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.scanning.cors_scan import CorsScanPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = CorsScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# http_headers
# =====================================================================

class TestHttpHeaders:
    async def test_missing_security_headers(self, mock_ctx):
        from basilisk.plugins.analysis.http_headers import HttpHeadersPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[
            ("Content-Type", "text/html"),
        ])
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = HttpHeadersPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        # Should find many missing headers
        missing = [f for f in result.findings if "missing" in f.title.lower()]
        assert len(missing) >= 3  # At least HSTS, X-Content-Type-Options, etc.

    async def test_good_security_headers(self, mock_ctx):
        from basilisk.plugins.analysis.http_headers import HttpHeadersPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(return_value=[
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "geolocation=()"),
        ])
        mock_resp.text = AsyncMock(return_value="<html></html>")
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = HttpHeadersPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.http_headers import HttpHeadersPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = HttpHeadersPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"
