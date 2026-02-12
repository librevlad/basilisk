"""Tests for analysis plugin run() methods."""

from unittest.mock import AsyncMock

from basilisk.models.target import Target


class TestHttpHeadersPlugin:
    async def test_success(self, mock_ctx):
        from basilisk.plugins.analysis.http_headers import HttpHeadersPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {
            "Server": "Apache/2.4.52",
            "X-Powered-By": "PHP/8.1",
            "Content-Type": "text/html",
        }
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = HttpHeadersPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        # Should report missing security headers
        assert len(result.findings) > 0

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.http_headers import HttpHeadersPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = HttpHeadersPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


class TestTechDetect:
    async def test_detects_nginx(self, mock_ctx):
        from unittest.mock import MagicMock

        from basilisk.plugins.analysis.tech_detect import TechDetectPlugin

        target = Target.domain("example.com")

        # Setup resolve_base_url support
        mock_head = MagicMock()
        mock_head.status = 200
        mock_ctx.http.head = AsyncMock(return_value=mock_head)

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.items = MagicMock(
            return_value=[("Server", "nginx/1.24.0")],
        )
        mock_resp.headers.get = MagicMock(
            side_effect=lambda k, d="": {
                "Server": "nginx/1.24.0",
            }.get(k, d),
        )
        mock_resp.headers.getall = MagicMock(return_value=[])
        mock_resp.text = AsyncMock(
            return_value="<html><body>Hello</body></html>",
        )
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = TechDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        techs = result.data.get("technologies", [])
        # technologies can be list of strings or list of dicts
        assert any(
            ("nginx" in (
                t.get("name", "") if isinstance(t, dict) else t
            ).lower())
            for t in techs
        )

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.tech_detect import TechDetectPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = TechDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


class TestSecurityTxt:
    async def test_found(self, mock_ctx):
        from basilisk.plugins.analysis.security_txt import SecurityTxtPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=(
            "Contact: security@example.com\n"
            "Expires: 2027-01-01T00:00:00Z\n"
        ))
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SecurityTxtPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

    async def test_not_found(self, mock_ctx):
        from basilisk.plugins.analysis.security_txt import SecurityTxtPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 404
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SecurityTxtPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.security_txt import SecurityTxtPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = SecurityTxtPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


class TestTakeoverCheck:
    async def test_no_takeover(self, mock_ctx):
        from basilisk.plugins.analysis.takeover_check import TakeoverCheckPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="<html>Normal page</html>")
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = TakeoverCheckPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.takeover_check import TakeoverCheckPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = TakeoverCheckPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


def _setup_inline_scheme(mock_ctx):
    """Standard mock for plugins with inline https→http scheme detection."""
    from unittest.mock import MagicMock

    mock_head = MagicMock()
    mock_head.status = 200
    mock_ctx.http.head = AsyncMock(return_value=mock_head)
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.text = AsyncMock(return_value="<html><body>Normal</body></html>")
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_ctx.http.get = AsyncMock(return_value=mock_resp)
    return mock_ctx


class TestCspAnalyzer:
    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.csp_analyzer import CspAnalyzerPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = CspAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_csp_header(self, mock_ctx):
        from basilisk.plugins.analysis.csp_analyzer import CspAnalyzerPlugin

        target = Target.domain("example.com")
        _setup_inline_scheme(mock_ctx)

        plugin = CspAnalyzerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok


class TestWafDetect:
    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.waf_detect import WafDetectPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = WafDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_waf_detected(self, mock_ctx):
        from basilisk.plugins.analysis.waf_detect import WafDetectPlugin

        target = Target.domain("example.com")
        _setup_inline_scheme(mock_ctx)

        plugin = WafDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok


class TestCommentFinder:
    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.comment_finder import CommentFinderPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = CommentFinderPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_comments(self, mock_ctx):
        from basilisk.plugins.analysis.comment_finder import CommentFinderPlugin

        target = Target.domain("example.com")
        _setup_inline_scheme(mock_ctx)

        plugin = CommentFinderPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok


class TestLinkExtractor:
    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.analysis.link_extractor import LinkExtractorPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = LinkExtractorPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_external_links(self, mock_ctx):
        from basilisk.plugins.analysis.link_extractor import LinkExtractorPlugin

        target = Target.domain("example.com")
        _setup_inline_scheme(mock_ctx)

        plugin = LinkExtractorPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
