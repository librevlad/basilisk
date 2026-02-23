"""Tests for scanning plugin run() methods."""

from unittest.mock import AsyncMock, MagicMock

from basilisk.models.target import Target
from basilisk.models.types import PortInfo, PortState


class TestPortScanPlugin:
    async def test_success(self, mock_ctx):
        from basilisk.plugins.scanning.port_scan import PortScanPlugin

        target = Target.domain("example.com")
        mock_ctx.net.scan_ports = AsyncMock(return_value=[
            PortInfo(port=80, state=PortState.OPEN),
            PortInfo(port=443, state=PortState.OPEN),
            PortInfo(port=22, state=PortState.CLOSED),
        ])

        plugin = PortScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        open_ports = result.data.get("open_ports", [])
        assert len(open_ports) == 2

    async def test_no_net(self, mock_ctx):
        from basilisk.plugins.scanning.port_scan import PortScanPlugin

        mock_ctx.net = None
        target = Target.domain("example.com")
        plugin = PortScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


class TestCorsScan:
    async def test_no_cors_issues(self, mock_ctx):
        from basilisk.plugins.scanning.cors_scan import CorsScanPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {}  # No CORS headers
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CorsScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

    async def test_wildcard_cors(self, mock_ctx):
        from basilisk.plugins.scanning.cors_scan import CorsScanPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CorsScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.findings) > 0

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.scanning.cors_scan import CorsScanPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = CorsScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


class TestHttpMethodsScan:
    async def test_success(self, mock_ctx):
        from basilisk.plugins.scanning.http_methods_scan import HttpMethodsScanPlugin

        target = Target.domain("example.com")

        async def fake_request(method, url, **kwargs):
            resp = MagicMock()
            resp.status = 200 if method in ("GET", "HEAD", "OPTIONS") else 405
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        mock_ctx.http.request = fake_request

        plugin = HttpMethodsScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.scanning.http_methods_scan import HttpMethodsScanPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = HttpMethodsScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


class TestCookieScan:
    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.scanning.cookie_scan import CookieScanPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = CookieScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_cookies(self, mock_ctx):
        from basilisk.plugins.scanning.cookie_scan import CookieScanPlugin

        target = Target.domain("example.com")
        mock_head = MagicMock()
        mock_head.status = 200
        mock_ctx.http.head = AsyncMock(return_value=mock_head)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.cookies = {}
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = CookieScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok


class TestServiceDetect:
    async def test_no_net(self, mock_ctx):
        from basilisk.plugins.scanning.service_detect import ServiceDetectPlugin

        mock_ctx.net = None
        target = Target.domain("example.com")
        plugin = ServiceDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_detects_services(self, mock_ctx):
        from basilisk.plugins.scanning.service_detect import ServiceDetectPlugin

        target = Target.domain("example.com")
        target.ports = [80, 443, 22]

        mock_ctx.net.grab_banner = AsyncMock(return_value="SSH-2.0-OpenSSH_8.9")

        plugin = ServiceDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
