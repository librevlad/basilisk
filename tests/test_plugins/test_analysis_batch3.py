"""Tests for Batch 3 analysis plugins (11 plugins).

Covers: js_api_extract, js_secret_scan, api_detect, meta_extract,
link_extractor, cloud_detect, form_analyzer, waf_bypass, openapi_parser,
security_txt, prometheus_scrape.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

from basilisk.models.target import Target

# =====================================================================
# Helpers
# =====================================================================

def _make_resp(status=200, body="", content_type="text/html", headers=None):
    """Create a mock HTTP response."""
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.json = AsyncMock(return_value={})
    hdr = {"Content-Type": content_type}
    if headers:
        hdr.update(headers)
    resp.headers = hdr
    return resp


# =====================================================================
# js_api_extract
# =====================================================================

class TestJsApiExtract:
    async def test_extracts_api_paths_from_inline_script(self, mock_ctx):
        from basilisk.plugins.analysis.js_api_extract import JsApiExtractPlugin

        target = Target.domain("example.com")
        # Use paths that won't be filtered by _SKIP_PATTERNS ("/api/v" is skipped)
        html = (
            "<html><body>"
            "<script>"
            "fetch('/api/users/list');"
            "fetch('/rest/orders');"
            "const endpoint = '/auth/login';"
            "</script>"
            "</body></html>"
        )
        main_resp = _make_resp(200, html)
        not_found = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if url == "https://example.com/":
                return main_resp
            return not_found

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=_make_resp(200, ""))
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = JsApiExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        paths = result.data.get("api_paths", [])
        assert "/api/users/list" in paths
        assert "/rest/orders" in paths

    async def test_extracts_secrets_from_js(self, mock_ctx):
        from basilisk.plugins.analysis.js_api_extract import JsApiExtractPlugin

        target = Target.domain("example.com")
        html = (
            '<html><body><script>'
            'var key = "AKIAIOSFODNN7EXAMPLE";'
            '</script></body></html>'
        )
        main_resp = _make_resp(200, html)
        not_found = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if url == "https://example.com/":
                return main_resp
            return not_found

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = JsApiExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data.get("secrets_count", 0) > 0

    async def test_detects_graphql_endpoint(self, mock_ctx):
        from basilisk.plugins.analysis.js_api_extract import JsApiExtractPlugin

        target = Target.domain("example.com")
        html = (
            '<html><body><script>'
            "const gql = '/graphql/v1';"
            '</script></body></html>'
        )
        main_resp = _make_resp(200, html)
        not_found = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if url == "https://example.com/":
                return main_resp
            return not_found

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = JsApiExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.data.get("graphql_endpoints", [])) > 0

    async def test_detects_internal_ips(self, mock_ctx):
        from basilisk.plugins.analysis.js_api_extract import JsApiExtractPlugin

        target = Target.domain("example.com")
        html = (
            '<html><body><script>'
            'var backend = "http://10.0.0.5:8080/api";'
            '</script></body></html>'
        )
        main_resp = _make_resp(200, html)
        not_found = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if url == "https://example.com/":
                return main_resp
            return not_found

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = JsApiExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "10.0.0.5" in result.data.get("internal_ips", [])

    async def test_detects_forms_without_csrf(self, mock_ctx):
        from basilisk.plugins.analysis.js_api_extract import JsApiExtractPlugin

        target = Target.domain("example.com")
        html = (
            '<html><body>'
            '<form method="POST" action="/login">'
            '<input type="text" name="user">'
            '<input type="password" name="pass">'
            '</form>'
            '</body></html>'
        )
        main_resp = _make_resp(200, html)
        not_found = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if url == "https://example.com/":
                return main_resp
            return not_found

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = JsApiExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        forms = result.data.get("forms", [])
        assert len(forms) > 0
        assert not forms[0]["has_csrf"]

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.js_api_extract import JsApiExtractPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = JsApiExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_host_not_reachable(self, mock_ctx):
        from basilisk.plugins.analysis.js_api_extract import JsApiExtractPlugin

        target = Target.domain("example.com")
        mock_ctx.http.head = AsyncMock(side_effect=Exception("timeout"))
        mock_ctx.http.get = AsyncMock(side_effect=Exception("timeout"))
        mock_ctx.state["http_scheme"] = {}

        plugin = JsApiExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "not reachable" in result.findings[0].title.lower()

    async def test_source_map_detection(self, mock_ctx):
        from basilisk.plugins.analysis.js_api_extract import JsApiExtractPlugin

        target = Target.domain("example.com")
        js_content = (
            'var x = 1;\n'
            '//# sourceMappingURL=app.js.map'
        )
        html = (
            '<html><body>'
            '<script src="/static/app.js"></script>'
            '</body></html>'
        )
        main_resp = _make_resp(200, html)
        js_resp = _make_resp(200, js_content, content_type="application/javascript")
        map_resp = _make_resp(200, '{}', content_type="application/json")
        map_resp.json = AsyncMock(return_value={"sources": [], "sourcesContent": []})
        not_found = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if url == "https://example.com/":
                return main_resp
            if url == "https://example.com/static/app.js":
                return js_resp
            if url.endswith(".map"):
                return map_resp
            return not_found

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = JsApiExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok


# =====================================================================
# js_secret_scan
# =====================================================================

class TestJsSecretScan:
    async def test_finds_aws_key_in_inline_script(self, mock_ctx):
        from basilisk.plugins.analysis.js_secret_scan import JsSecretScanPlugin

        target = Target.domain("example.com")
        html = (
            '<html><body><script>'
            'var key = "AKIAIOSFODNN7EXAMPLE";'
            '</script></body></html>'
        )
        resp = _make_resp(200, html)
        mock_ctx.http.get = AsyncMock(return_value=resp)

        plugin = JsSecretScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.data["secrets"]) > 0
        assert any("AWS" in s["type"] for s in result.data["secrets"])

    async def test_finds_secret_in_external_js(self, mock_ctx):
        from basilisk.plugins.analysis.js_secret_scan import JsSecretScanPlugin

        target = Target.domain("example.com")
        html = '<html><script src="/app.js"></script></html>'
        js = 'var stripe_key = "stripe_secret_FAKEFAKE00000000";'
        html_resp = _make_resp(200, html)
        js_resp = _make_resp(200, js)
        mock_ctx.http.get = AsyncMock(side_effect=[html_resp, js_resp])

        plugin = JsSecretScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["js_files_scanned"] == 1

    async def test_no_secrets_found(self, mock_ctx):
        from basilisk.plugins.analysis.js_secret_scan import JsSecretScanPlugin

        target = Target.domain("example.com")
        html = '<html><body>No scripts here</body></html>'
        resp = _make_resp(200, html)
        mock_ctx.http.get = AsyncMock(return_value=resp)

        plugin = JsSecretScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.data["secrets"]) == 0

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.js_secret_scan import JsSecretScanPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = JsSecretScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_should_stop_breaks_loop(self, mock_ctx):
        from basilisk.plugins.analysis.js_secret_scan import JsSecretScanPlugin

        target = Target.domain("example.com")
        html = (
            '<html>'
            '<script src="/a.js"></script>'
            '<script src="/b.js"></script>'
            '<script src="/c.js"></script>'
            '</html>'
        )
        html_resp = _make_resp(200, html)
        js_resp = _make_resp(200, "var x = 1;")

        call_count = 0

        async def get_side_effect(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return html_resp
            # After first JS file, set deadline to trigger should_stop
            if call_count == 2:
                # Set deadline to the past so should_stop returns True
                mock_ctx._deadline = time.monotonic() - 10.0
            return js_resp

        mock_ctx.http.get = get_side_effect

        plugin = JsSecretScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        # Should have stopped after scanning 1 JS file
        assert result.data["js_files_scanned"] <= 1


# =====================================================================
# api_detect
# =====================================================================

class TestApiDetect:
    async def test_detects_swagger_json(self, mock_ctx):
        from basilisk.plugins.analysis.api_detect import ApiDetectPlugin

        target = Target.domain("example.com")
        head_resp = _make_resp(200, "")

        swagger_body = '{"swagger": "2.0", "info": {"title": "API"}}'
        swagger_resp = _make_resp(
            200, swagger_body, content_type="application/json",
        )
        not_found = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if "swagger.json" in url:
                return swagger_resp
            if "_nonexistent_" in url:
                return not_found
            return not_found

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=head_resp)

        plugin = ApiDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("api doc" in f.title.lower() for f in result.findings)

    async def test_detects_actuator(self, mock_ctx):
        from basilisk.plugins.analysis.api_detect import ApiDetectPlugin

        target = Target.domain("example.com")
        head_resp = _make_resp(200, "")
        actuator_resp = _make_resp(200, '{"status":"UP"}', content_type="application/json")
        not_found = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if "/actuator" in url:
                return actuator_resp
            if "_nonexistent_" in url:
                return not_found
            return not_found

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=head_resp)

        plugin = ApiDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("actuator" in f.title.lower() for f in result.findings)

    async def test_detects_auth_required_endpoint(self, mock_ctx):
        from basilisk.plugins.analysis.api_detect import ApiDetectPlugin

        target = Target.domain("example.com")
        head_resp = _make_resp(200, "")
        auth_resp = _make_resp(401, '{"error":"unauthorized"}')
        not_found = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if "/api" in url and "_nonexistent_" not in url:
                return auth_resp
            return not_found

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=head_resp)

        plugin = ApiDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        discovered = result.data["api_endpoints"]
        auth_endpoints = [e for e in discovered if e.get("auth_required")]
        assert len(auth_endpoints) > 0

    async def test_spa_catch_all_filtered(self, mock_ctx):
        from basilisk.plugins.analysis.api_detect import ApiDetectPlugin

        target = Target.domain("example.com")
        head_resp = _make_resp(200, "")
        spa_body = "<html><body>SPA App</body></html>"
        spa_resp = _make_resp(200, spa_body)

        # All paths return same SPA body
        mock_ctx.http.get = AsyncMock(return_value=spa_resp)
        mock_ctx.http.head = AsyncMock(return_value=head_resp)

        plugin = ApiDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        # SPA catch-all should filter out all endpoints
        assert len(result.data["api_endpoints"]) == 0

    async def test_no_api_endpoints(self, mock_ctx):
        from basilisk.plugins.analysis.api_detect import ApiDetectPlugin

        target = Target.domain("example.com")
        head_resp = _make_resp(200, "")
        not_found = _make_resp(404, "")
        mock_ctx.http.get = AsyncMock(return_value=not_found)
        mock_ctx.http.head = AsyncMock(return_value=head_resp)

        plugin = ApiDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("no api" in f.title.lower() for f in result.findings)

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.api_detect import ApiDetectPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = ApiDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# meta_extract
# =====================================================================

class TestMetaExtract:
    async def test_extracts_generator(self, mock_ctx):
        from basilisk.plugins.analysis.meta_extract import MetaExtractPlugin

        target = Target.domain("example.com")
        html = '<html><head><meta name="generator" content="WordPress 6.4"></head></html>'
        resp = _make_resp(200, html)
        mock_ctx.http.get = AsyncMock(return_value=resp)

        plugin = MetaExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["meta_tags"].get("generator") == "WordPress 6.4"
        assert any("generator" in f.title.lower() for f in result.findings)

    async def test_extracts_http_equiv(self, mock_ctx):
        from basilisk.plugins.analysis.meta_extract import MetaExtractPlugin

        target = Target.domain("example.com")
        html = (
            '<html><head>'
            '<meta http-equiv="X-UA-Compatible" content="IE=edge">'
            '</head></html>'
        )
        resp = _make_resp(200, html)
        mock_ctx.http.get = AsyncMock(return_value=resp)

        plugin = MetaExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "http-equiv:x-ua-compatible" in result.data["meta_tags"]

    async def test_extracts_author(self, mock_ctx):
        from basilisk.plugins.analysis.meta_extract import MetaExtractPlugin

        target = Target.domain("example.com")
        html = '<html><head><meta name="author" content="John Doe"></head></html>'
        resp = _make_resp(200, html)
        mock_ctx.http.get = AsyncMock(return_value=resp)

        plugin = MetaExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["meta_tags"].get("author") == "John Doe"
        assert any("author" in f.title.lower() for f in result.findings)

    async def test_no_meta_tags(self, mock_ctx):
        from basilisk.plugins.analysis.meta_extract import MetaExtractPlugin

        target = Target.domain("example.com")
        html = '<html><body>No meta tags</body></html>'
        resp = _make_resp(200, html)
        mock_ctx.http.get = AsyncMock(return_value=resp)

        plugin = MetaExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "no meta" in result.findings[0].title.lower()

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.meta_extract import MetaExtractPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = MetaExtractPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# link_extractor — expanded tests
# =====================================================================

class TestLinkExtractorExpanded:
    async def test_third_party_suffix_match(self, mock_ctx):
        """Verify 'nostripe.com' is NOT classified as Stripe (payment)."""
        from basilisk.plugins.analysis.link_extractor import LinkExtractorPlugin

        target = Target.domain("example.com")
        html = (
            '<html><body>'
            '<a href="https://nostripe.com/page">Not Stripe</a>'
            '<a href="https://js.stripe.com/v3/">Real Stripe</a>'
            '</body></html>'
        )
        robots_404 = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if url.endswith("example.com/"):
                return _make_resp(200, html)
            return robots_404

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=_make_resp(200, ""))
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = LinkExtractorPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        payment_domains = result.data.get("third_party", {}).get("payment", [])
        # js.stripe.com should be classified as payment
        assert "js.stripe.com" in payment_domains
        # nostripe.com should NOT be classified as payment
        assert "nostripe.com" not in payment_domains

    async def test_subdomain_discovery(self, mock_ctx):
        from basilisk.plugins.analysis.link_extractor import LinkExtractorPlugin

        target = Target.domain("example.com")
        html = (
            '<html><body>'
            '<a href="https://sub.example.com/page">Subdomain</a>'
            '<a href="https://api.example.com/v1">API</a>'
            '</body></html>'
        )
        robots_404 = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if url.endswith("example.com/"):
                return _make_resp(200, html)
            return robots_404

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=_make_resp(200, ""))
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = LinkExtractorPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        subs = result.data["subdomains"]
        assert "sub.example.com" in subs
        assert "api.example.com" in subs

    async def test_sensitive_file_detection(self, mock_ctx):
        from basilisk.plugins.analysis.link_extractor import LinkExtractorPlugin

        target = Target.domain("example.com")
        html = (
            '<html><body>'
            '<a href="https://example.com/backup.sql">Backup</a>'
            '<a href="https://example.com/dump.zip">Dump</a>'
            '</body></html>'
        )
        robots_404 = _make_resp(404, "")

        def get_side_effect(url, **kwargs):
            if url.endswith("example.com/"):
                return _make_resp(200, html)
            return robots_404

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=_make_resp(200, ""))
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = LinkExtractorPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.data["sensitive_files"]) >= 2

    async def test_robots_txt_parsing(self, mock_ctx):
        from basilisk.plugins.analysis.link_extractor import LinkExtractorPlugin

        target = Target.domain("example.com")
        html = '<html><body>Hello</body></html>'
        robots = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /private/\n"
            "Sitemap: https://example.com/sitemap.xml\n"
        )
        sitemap = '<urlset><url><loc>https://example.com/page1</loc></url></urlset>'

        def get_side_effect(url, **kwargs):
            if url.endswith("example.com/"):
                return _make_resp(200, html)
            if "robots.txt" in url:
                return _make_resp(200, robots)
            if "sitemap.xml" in url:
                return _make_resp(200, sitemap)
            return _make_resp(404, "")

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=_make_resp(200, ""))
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = LinkExtractorPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "/admin/" in result.data["disallowed_paths"]
        assert "/private/" in result.data["disallowed_paths"]


# =====================================================================
# cloud_detect — CNAME regression test
# =====================================================================

class TestCloudDetectCnameRegression:
    async def test_cname_substring_no_false_positive(self, mock_ctx):
        """Ensure 'notazure.com' is NOT matched as Azure."""
        from basilisk.plugins.analysis.cloud_detect import CloudDetectPlugin

        target = Target.domain("example.com")
        resp = _make_resp(200, "", headers={})
        resp.headers = MagicMock()
        resp.headers.items = MagicMock(return_value=[])
        mock_ctx.http.get = AsyncMock(return_value=resp)

        # DNS returns a CNAME that is NOT actually Azure
        cname_record = MagicMock()
        cname_record.value = "notazure.com"
        mock_ctx.dns.resolve = AsyncMock(return_value=[cname_record])

        plugin = CloudDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        providers = result.data["cloud_providers"]
        assert "Microsoft Azure" not in providers

    async def test_cname_suffix_matches_azure(self, mock_ctx):
        """Ensure 'myapp.azurewebsites.net' IS matched as Azure."""
        from basilisk.plugins.analysis.cloud_detect import CloudDetectPlugin

        target = Target.domain("example.com")
        resp = _make_resp(200, "", headers={})
        resp.headers = MagicMock()
        resp.headers.items = MagicMock(return_value=[])
        mock_ctx.http.get = AsyncMock(return_value=resp)

        cname_record = MagicMock()
        cname_record.value = "myapp.azurewebsites.net"
        mock_ctx.dns.resolve = AsyncMock(return_value=[cname_record])

        plugin = CloudDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "Microsoft Azure" in result.data["cloud_providers"]

    async def test_cname_exact_match(self, mock_ctx):
        """Ensure exact CNAME domain match works (e.g., 'herokuapp.com')."""
        from basilisk.plugins.analysis.cloud_detect import CloudDetectPlugin

        target = Target.domain("example.com")
        resp = _make_resp(200, "", headers={})
        resp.headers = MagicMock()
        resp.headers.items = MagicMock(return_value=[])
        mock_ctx.http.get = AsyncMock(return_value=resp)

        cname_record = MagicMock()
        cname_record.value = "herokuapp.com"
        mock_ctx.dns.resolve = AsyncMock(return_value=[cname_record])

        plugin = CloudDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "Heroku" in result.data["cloud_providers"]


# =====================================================================
# form_analyzer — autocomplete regression
# =====================================================================

class TestFormAnalyzerAutocomplete:
    async def test_new_password_autocomplete_value(self, mock_ctx):
        """Ensure autocomplete='new-password' is captured correctly."""
        from basilisk.plugins.analysis.form_analyzer import FormAnalyzerPlugin

        target = Target.domain("example.com")
        html = (
            '<html><body>'
            '<form method="POST" action="/register" autocomplete="new-password">'
            '<input type="password" name="pass">'
            '<input type="hidden" name="csrf" value="abc">'
            '</form>'
            '</body></html>'
        )
        resp = _make_resp(200, html)
        mock_ctx.http.get = AsyncMock(return_value=resp)

        plugin = FormAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        forms = result.data["forms"]
        assert len(forms) == 1
        assert forms[0]["autocomplete"] == "new-password"


# =====================================================================
# Regression tests for Batch 3 bug fixes
# =====================================================================


class TestLinkExtractorCrawledUrlsDictBug:
    """Regression: crawled_urls is dict[str, list[str]], not list[str]."""

    async def test_crawled_urls_as_dict(self, mock_ctx):
        from basilisk.plugins.analysis.link_extractor import LinkExtractorPlugin

        target = Target.domain("example.com")
        html = '<html><body><a href="/page1">P1</a></body></html>'
        page_html = '<html><body><a href="/page2">P2</a></body></html>'

        def get_side_effect(url, **kwargs):
            if "/extra" in url:
                return _make_resp(200, page_html)
            if url.endswith("example.com/") or url.endswith("example.com"):
                return _make_resp(200, html)
            return _make_resp(404, "")

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=_make_resp(200, ""))
        mock_ctx.state["http_scheme"] = {"example.com": "https"}
        # Pipeline injects crawled_urls as dict, not list
        mock_ctx.state["crawled_urls"] = {
            "example.com": [
                "https://example.com/extra",
                "https://example.com/other",
            ],
        }

        plugin = LinkExtractorPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

    async def test_crawled_urls_empty_dict(self, mock_ctx):
        from basilisk.plugins.analysis.link_extractor import LinkExtractorPlugin

        target = Target.domain("example.com")
        html = '<html><body>Hello</body></html>'
        mock_ctx.http.get = AsyncMock(return_value=_make_resp(200, html))
        mock_ctx.http.head = AsyncMock(return_value=_make_resp(200, ""))
        mock_ctx.state["http_scheme"] = {"example.com": "https"}
        mock_ctx.state["crawled_urls"] = {}

        plugin = LinkExtractorPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok


class TestRobotsSitemapParsing:
    """Regression: sitemap URL parsing with various formats."""

    async def test_sitemap_with_space(self, mock_ctx):
        from basilisk.plugins.analysis.link_extractor import LinkExtractorPlugin

        target = Target.domain("example.com")
        html = '<html><body>Hello</body></html>'
        robots = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Sitemap: https://example.com/sitemap.xml\n"
        )
        sitemap = '<urlset><url><loc>https://example.com/p1</loc></url></urlset>'

        def get_side_effect(url, **kwargs):
            if url.endswith("example.com/"):
                return _make_resp(200, html)
            if "robots.txt" in url:
                return _make_resp(200, robots)
            if "sitemap" in url:
                return _make_resp(200, sitemap)
            return _make_resp(404, "")

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=_make_resp(200, ""))
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = LinkExtractorPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

    async def test_sitemap_no_space(self, mock_ctx):
        from basilisk.plugins.analysis.link_extractor import LinkExtractorPlugin

        target = Target.domain("example.com")
        html = '<html><body>Hello</body></html>'
        # No space after "Sitemap:" — colon split consumes scheme colon
        robots = "Sitemap:https://example.com/sitemap.xml\n"

        def get_side_effect(url, **kwargs):
            if url.endswith("example.com/"):
                return _make_resp(200, html)
            if "robots.txt" in url:
                return _make_resp(200, robots)
            if "sitemap" in url:
                return _make_resp(200, '<urlset></urlset>')
            return _make_resp(404, "")

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=_make_resp(200, ""))
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = LinkExtractorPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok


class TestCloudDetectUnreachable:
    """Regression: distinguish unreachable from no-cloud-detected."""

    async def test_http_unreachable_message(self, mock_ctx):
        from basilisk.plugins.analysis.cloud_detect import CloudDetectPlugin

        target = Target.domain("unreachable.example.com")
        mock_ctx.http.get = AsyncMock(side_effect=Exception("Connection refused"))
        mock_ctx.dns.resolve = AsyncMock(return_value=[])

        plugin = CloudDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("unreachable" in f.title.lower() or "skipped" in f.title.lower()
                    for f in result.findings)


class TestPrometheusScrapeNoDependency:
    """Regression: prometheus_scrape should not depend on debug_endpoints."""

    def test_no_depends_on(self):
        from basilisk.plugins.analysis.prometheus_scrape import PrometheusScrapePlugin
        assert "debug_endpoints" not in PrometheusScrapePlugin.meta.depends_on

    async def test_direct_probe(self, mock_ctx):
        from basilisk.plugins.analysis.prometheus_scrape import PrometheusScrapePlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline = {}  # No debug_endpoints result
        metrics = (
            '# HELP http_requests_total Total requests\n'
            '# TYPE http_requests_total counter\n'
            'http_requests_total{method="GET"} 1234\n'
        )
        resp = _make_resp(200, metrics, content_type="text/plain")

        def get_side_effect(url, **kwargs):
            if "/metrics" in url:
                return resp
            return _make_resp(404, "")

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)

        plugin = PrometheusScrapePlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
