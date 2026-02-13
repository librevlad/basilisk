"""Tests for analysis plugins — new batch."""

from unittest.mock import AsyncMock, MagicMock, patch

from basilisk.models.target import Target

# =====================================================================
# waf_bypass
# =====================================================================


class TestWafBypass:
    async def test_bypass_found(self, mock_ctx):
        """Happy path: WAF detected, baseline blocked, bypass technique succeeds."""
        from basilisk.models.result import PluginResult
        from basilisk.plugins.analysis.waf_bypass import WafBypassPlugin

        target = Target.domain("example.com")

        # WAF was detected upstream
        mock_ctx.pipeline["waf_detect:example.com"] = PluginResult.success(
            "waf_detect", "example.com",
            data={"waf": [{"name": "Cloudflare"}]},
        )

        # head() succeeds for scheme detection
        mock_head = MagicMock()
        mock_head.status = 200
        mock_ctx.http.head = AsyncMock(return_value=mock_head)

        call_count = 0

        async def mock_get(url, headers=None, timeout=None):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            # First GET is the baseline (blocked payload) -> 403
            # Subsequent GETs are bypass attempts
            if call_count == 1:
                resp.status = 403
            else:
                # Simulate one bypass technique succeeding
                resp.status = 200
            return resp

        mock_ctx.http.get = mock_get

        plugin = WafBypassPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.data["bypass_techniques"]) > 0
        assert any("bypass" in f.title.lower() for f in result.findings)

    async def test_no_http(self, mock_ctx):
        """HTTP client not available -> error status."""
        from basilisk.models.result import PluginResult
        from basilisk.plugins.analysis.waf_bypass import WafBypassPlugin

        target = Target.domain("example.com")
        mock_ctx.http = None

        # WAF detected so plugin actually tries to use http
        mock_ctx.pipeline["waf_detect:example.com"] = PluginResult.success(
            "waf_detect", "example.com",
            data={"waf": [{"name": "Cloudflare"}]},
        )

        plugin = WafBypassPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_skipped_no_waf_result(self, mock_ctx):
        """When waf_detect result is missing, plugin should skip."""
        from basilisk.plugins.analysis.waf_bypass import WafBypassPlugin

        target = Target.domain("example.com")
        # No waf_detect in pipeline

        plugin = WafBypassPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "skipped"

    async def test_no_waf_detected(self, mock_ctx):
        """WAF detect ran but found no WAF -> no bypass needed."""
        from basilisk.models.result import PluginResult
        from basilisk.plugins.analysis.waf_bypass import WafBypassPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline["waf_detect:example.com"] = PluginResult.success(
            "waf_detect", "example.com",
            data={"waf": []},
        )

        plugin = WafBypassPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["bypass_techniques"] == []
        assert any("no waf" in f.title.lower() for f in result.findings)

    async def test_baseline_not_blocked(self, mock_ctx):
        """When baseline payload is NOT blocked (200), WAF doesn't filter this path."""
        from basilisk.models.result import PluginResult
        from basilisk.plugins.analysis.waf_bypass import WafBypassPlugin

        target = Target.domain("example.com")
        mock_ctx.pipeline["waf_detect:example.com"] = PluginResult.success(
            "waf_detect", "example.com",
            data={"waf": [{"name": "ModSecurity"}]},
        )

        mock_head = MagicMock()
        mock_head.status = 200
        mock_ctx.http.head = AsyncMock(return_value=mock_head)

        # Baseline returns 200 (not blocked)
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = WafBypassPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["bypass_techniques"] == []
        assert any("did not block" in f.title.lower() for f in result.findings)


# =====================================================================
# prometheus_scrape
# =====================================================================


class TestPrometheusScrape:
    async def test_internal_ips_leaked(self, mock_ctx):
        """Happy path: /metrics exposed with internal IPs and DB names."""
        from basilisk.plugins.analysis.prometheus_scrape import PrometheusScrapePlugin

        target = Target.domain("example.com")

        metrics_body = (
            '# HELP http_requests_total Total requests\n'
            '# TYPE http_requests_total counter\n'
            'http_requests_total{method="GET",path="/api/users",instance="10.0.1.5:9090"} 1234\n'
            'http_requests_total{method="POST",path="/api/orders",instance="10.0.1.6:9090"} 567\n'
            'db_connections_active{database="orders_db",host="db1.internal"} 42\n'
            'app_build_info{version="1.2.3",commit="abc123"} 1\n'
        )

        call_count = 0

        async def mock_get(url, timeout=None, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status = 200
            resp.headers = {"content-type": "text/plain; charset=utf-8"}
            resp.text = AsyncMock(return_value=metrics_body)
            return resp

        mock_ctx.http.get = mock_get

        plugin = PrometheusScrapePlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "10.0.1.5" in result.data["internal_ips"]
        assert "10.0.1.6" in result.data["internal_ips"]
        assert "/api/users" in result.data["api_endpoints"]
        assert "orders_db" in result.data["databases"]
        assert any("internal ip" in f.title.lower() for f in result.findings)

    async def test_no_http(self, mock_ctx):
        """HTTP client not available -> error when metrics_url found."""
        from basilisk.models.result import PluginResult
        from basilisk.plugins.analysis.prometheus_scrape import PrometheusScrapePlugin

        target = Target.domain("example.com")

        # Simulate debug_endpoints found /metrics
        mock_ctx.pipeline["debug_endpoints:example.com"] = PluginResult.success(
            "debug_endpoints", "example.com",
            data={"exposed_endpoints": [
                {"path": "/metrics", "url": "https://example.com/metrics"},
            ]},
        )
        mock_ctx.http = None

        plugin = PrometheusScrapePlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_metrics_endpoint(self, mock_ctx):
        """No /metrics endpoint found -> info finding."""
        from basilisk.plugins.analysis.prometheus_scrape import PrometheusScrapePlugin

        target = Target.domain("example.com")

        # All requests return 404
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.headers = {"content-type": "text/html"}
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = PrometheusScrapePlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("no prometheus" in f.title.lower() for f in result.findings)

    async def test_build_info_leaked(self, mock_ctx):
        """Build info metrics generate LOW findings."""
        from basilisk.plugins.analysis.prometheus_scrape import PrometheusScrapePlugin

        target = Target.domain("example.com")

        metrics_body = (
            'app_build_info{version="2.0.0",commit="deadbeef",branch="main"} 1\n'
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"content-type": "text/plain"}
        mock_resp.text = AsyncMock(return_value=metrics_body)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = PrometheusScrapePlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["build_info"].get("version") == "2.0.0"
        assert any("build info" in f.title.lower() for f in result.findings)


# =====================================================================
# cloud_detect
# =====================================================================


class TestCloudDetect:
    async def test_aws_via_header(self, mock_ctx):
        """Detects AWS via response headers."""
        from basilisk.plugins.analysis.cloud_detect import CloudDetectPlugin

        target = Target.domain("example.com")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {
            "x-amz-request-id": "ABC123",
            "Content-Type": "text/html",
        }
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CloudDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "AWS" in result.data["cloud_providers"]
        assert any("aws" in f.title.lower() for f in result.findings)

    async def test_vercel_via_cname(self, mock_ctx):
        """Detects Vercel via DNS CNAME record."""
        from basilisk.plugins.analysis.cloud_detect import CloudDetectPlugin

        target = Target.domain("example.com")

        # HTTP response with no cloud headers
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        # CNAME points to vercel.app
        cname_record = MagicMock()
        cname_record.value = "cname.vercel.app."
        mock_ctx.dns.resolve = AsyncMock(return_value=[cname_record])

        plugin = CloudDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "Vercel" in result.data["cloud_providers"]

    async def test_no_http(self, mock_ctx):
        """HTTP client not available -> error."""
        from basilisk.plugins.analysis.cloud_detect import CloudDetectPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")

        plugin = CloudDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_cloud_detected(self, mock_ctx):
        """No cloud signatures found -> self-hosted info finding."""
        from basilisk.plugins.analysis.cloud_detect import CloudDetectPlugin

        target = Target.domain("example.com")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html", "Server": "nginx"}
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)
        # No CNAME
        mock_ctx.dns.resolve = AsyncMock(return_value=[])

        plugin = CloudDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["cloud_providers"] == []
        assert any("no cloud" in f.title.lower() for f in result.findings)


# =====================================================================
# ssl_cert_chain
# =====================================================================


class TestSslCertChain:
    async def test_valid_chain(self, mock_ctx):
        """Happy path: valid SSL cert with matching SAN and trusted issuer."""
        from basilisk.plugins.analysis.ssl_cert_chain import SslCertChainPlugin

        target = Target.domain("example.com")

        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
        }

        mock_ssl_obj = MagicMock()
        mock_ssl_obj.getpeercert.return_value = cert

        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = mock_ssl_obj
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        mock_reader = MagicMock()

        with patch("asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
            mock_wait.return_value = (mock_reader, mock_writer)

            plugin = SslCertChainPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data.get("subject") == "example.com"
        assert result.data.get("issuer") == "Let's Encrypt"
        # No issues -> info finding about chain being OK
        assert any("ok" in f.title.lower() or "chain" in f.title.lower()
                    for f in result.findings)

    async def test_self_signed_cert(self, mock_ctx):
        """Self-signed cert should produce HIGH finding."""
        from basilisk.plugins.analysis.ssl_cert_chain import SslCertChainPlugin

        target = Target.domain("example.com")

        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "example.com"),),),
            "subjectAltName": (("DNS", "example.com"),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
        }

        mock_ssl_obj = MagicMock()
        mock_ssl_obj.getpeercert.return_value = cert

        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = mock_ssl_obj
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        mock_reader = MagicMock()

        with patch("asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
            mock_wait.return_value = (mock_reader, mock_writer)

            plugin = SslCertChainPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("self-signed" in f.title.lower() for f in result.findings)

    async def test_ssl_connection_error(self, mock_ctx):
        """Connection failure -> info finding about unreachable host."""
        from basilisk.plugins.analysis.ssl_cert_chain import SslCertChainPlugin

        target = Target.domain("example.com")

        with patch("asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
            mock_wait.side_effect = ConnectionRefusedError("Connection refused")

            plugin = SslCertChainPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("could not analyze" in f.title.lower() for f in result.findings)

    async def test_ssl_verification_error(self, mock_ctx):
        """SSL verification error -> HIGH finding."""
        import ssl as _ssl

        from basilisk.plugins.analysis.ssl_cert_chain import SslCertChainPlugin

        target = Target.domain("example.com")

        with patch("asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
            mock_wait.side_effect = _ssl.SSLCertVerificationError(
                "certificate verify failed"
            )

            plugin = SslCertChainPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("verification failed" in f.title.lower() for f in result.findings)


# =====================================================================
# form_analyzer
# =====================================================================


class TestFormAnalyzer:
    async def test_post_without_csrf(self, mock_ctx):
        """POST form without CSRF token -> MEDIUM finding."""
        from basilisk.plugins.analysis.form_analyzer import FormAnalyzerPlugin

        target = Target.domain("example.com")

        html_body = (
            '<html><body>'
            '<form method="POST" action="/login">'
            '<input type="text" name="username">'
            '<input type="password" name="password">'
            '<button type="submit">Login</button>'
            '</form>'
            '</body></html>'
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=html_body)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = FormAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.data["forms"]) == 1
        assert any("csrf" in f.title.lower() for f in result.findings)
        # Also should detect password autocomplete
        assert any("autocomplete" in f.title.lower() or "password" in f.title.lower()
                    for f in result.findings)

    async def test_secure_form(self, mock_ctx):
        """Form with CSRF token and autocomplete=off -> no issues."""
        from basilisk.plugins.analysis.form_analyzer import FormAnalyzerPlugin

        target = Target.domain("example.com")

        html_body = (
            '<html><body>'
            '<form method="POST" action="/login" autocomplete="off">'
            '<input type="hidden" name="csrf" value="token123">'
            '<input type="text" name="username">'
            '<input type="password" name="password">'
            '<button type="submit">Login</button>'
            '</form>'
            '</body></html>'
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=html_body)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = FormAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.data["forms"]) == 1
        assert any("no issues" in f.title.lower() for f in result.findings)

    async def test_http_form_action(self, mock_ctx):
        """Form that submits to HTTP (insecure) -> MEDIUM finding."""
        from basilisk.plugins.analysis.form_analyzer import FormAnalyzerPlugin

        target = Target.domain("example.com")

        html_body = (
            '<html><body>'
            '<form method="GET" action="http://insecure.example.com/search">'
            '<input type="text" name="q">'
            '</form>'
            '</body></html>'
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=html_body)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = FormAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("http" in f.title.lower() and "insecure" in f.title.lower()
                    for f in result.findings)

    async def test_no_forms(self, mock_ctx):
        """Page with no forms -> info finding."""
        from basilisk.plugins.analysis.form_analyzer import FormAnalyzerPlugin

        target = Target.domain("example.com")

        html_body = "<html><body><h1>Welcome</h1><p>No forms here.</p></body></html>"

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=html_body)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = FormAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["forms"] == []
        assert any("no forms" in f.title.lower() for f in result.findings)

    async def test_no_http(self, mock_ctx):
        """HTTP client not available -> error."""
        from basilisk.plugins.analysis.form_analyzer import FormAnalyzerPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")

        plugin = FormAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"
