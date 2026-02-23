"""Tests for recon and scanning plugins — new batch."""

from unittest.mock import AsyncMock, MagicMock, patch

from basilisk.models.target import Target

# =====================================================================
# whois
# =====================================================================


class TestWhois:
    async def test_success_with_rdap_and_whois(self, mock_ctx):
        from basilisk.plugins.recon.whois import WhoisPlugin

        target = Target.domain("example.com")

        # Mock RDAP response
        import json

        rdap_json = json.dumps({
            "handle": "EX123",
            "events": [
                {"eventAction": "registration", "eventDate": "2005-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ],
            "status": ["active"],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                },
            ],
            "secureDNS": {"delegationSigned": False},
        })

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=rdap_json)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        # Mock DNS for ASN lookup
        mock_ctx.dns.get_ips = AsyncMock(return_value=["93.184.216.34"])

        # Mock WHOIS TCP (bypass real socket connection)
        whois_text = (
            "Domain Name: EXAMPLE.COM\n"
            "Registrar: Example Registrar Inc.\n"
            "Creation Date: 2005-01-01T00:00:00Z\n"
            "Registry Expiry Date: 2030-01-01T00:00:00Z\n"
            "DNSSEC: unsigned\n"
        )
        with patch.object(WhoisPlugin, "_query_whois", new_callable=AsyncMock) as mock_whois:
            mock_whois.return_value = whois_text

            plugin = WhoisPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert len(result.findings) > 0
        # Should have registrar info finding
        assert any("registrar" in f.title.lower() or "whois" in f.title.lower()
                    for f in result.findings)

    async def test_cached_result(self, mock_ctx):
        from basilisk.plugins.recon.whois import WhoisPlugin

        target = Target.domain("example.com")

        # Pre-populate cache
        mock_ctx.state["whois_cache:example.com"] = {
            "findings": [],
            "data": {"whois_raw": "cached", "whois_parsed": {}, "rdap": {}},
        }

        plugin = WhoisPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["whois_raw"] == "cached"

    async def test_both_rdap_and_whois_fail(self, mock_ctx):
        from basilisk.plugins.recon.whois import WhoisPlugin

        target = Target.domain("example.com")

        # RDAP fails (status != 200)
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        # WHOIS TCP also fails
        with patch.object(WhoisPlugin, "_query_whois", new_callable=AsyncMock) as mock_whois:
            mock_whois.return_value = ""

            plugin = WhoisPlugin()
            result = await plugin.run(target, mock_ctx)

        assert not result.ok
        assert "failed" in result.error.lower()

    async def test_extract_base_domain(self):
        from basilisk.plugins.recon.whois import WhoisPlugin

        assert WhoisPlugin._extract_base_domain("example.com") == "example.com"
        assert WhoisPlugin._extract_base_domain("sub.example.com") == "example.com"
        assert WhoisPlugin._extract_base_domain("deep.sub.example.co.uk") == "example.co.uk"

    async def test_parse_whois_text(self):
        from basilisk.plugins.recon.whois import WhoisPlugin

        text = (
            "Domain Name: EXAMPLE.COM\n"
            "Registrar: Example Registrar Inc.\n"
            "Creation Date: 2005-01-01T00:00:00Z\n"
            "Registry Expiry Date: 2030-01-01T00:00:00Z\n"
            "DNSSEC: unsigned\n"
            "Name Server: ns1.example.com\n"
            "Name Server: ns2.example.com\n"
        )
        parsed = WhoisPlugin._parse_whois(text)
        assert "Example Registrar Inc." in parsed["registrar"]
        assert parsed["creation_date"] == "2005-01-01T00:00:00Z"
        assert "ns1.example.com" in parsed["name_servers"]


# =====================================================================
# web_crawler
# =====================================================================


class TestWebCrawler:
    async def test_success_crawl(self, mock_ctx):
        from basilisk.plugins.recon.web_crawler import WebCrawlerPlugin

        target = Target.domain("example.com")

        page_html = (
            '<html><head>'
            '<script src="/static/app.js"></script>'
            '</head><body>'
            '<a href="/about">About</a>'
            '<a href="/contact">Contact</a>'
            '<form action="/login" method="POST">'
            '<input name="username"><input name="password">'
            '</form>'
            '</body></html>'
        )

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            if url.endswith(".js"):
                resp.status = 200
                resp.text = AsyncMock(return_value="var x = 1;")
            elif "manifest" in url or "webpack" in url:
                resp.status = 404
                resp.text = AsyncMock(return_value="Not Found")
            else:
                resp.status = 200
                resp.text = AsyncMock(return_value=page_html)
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        mock_ctx.http.get = mock_get

        plugin = WebCrawlerPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert len(result.data["js_files"]) >= 1
        assert len(result.data["forms"]) == 1
        assert result.data["forms"][0]["method"] == "POST"

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.recon.web_crawler import WebCrawlerPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = WebCrawlerPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_host_not_reachable(self, mock_ctx):
        from basilisk.plugins.recon.web_crawler import WebCrawlerPlugin

        target = Target.domain("unreachable.example.com")
        # resolve_base_url returns None when host is not in http_scheme and probes fail
        mock_ctx.state["http_scheme"] = {}
        mock_ctx.http.get = AsyncMock(side_effect=Exception("Connection refused"))

        plugin = WebCrawlerPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("not reachable" in f.title.lower() or "could not" in f.title.lower()
                    for f in result.findings)

    async def test_webpack_detected(self, mock_ctx):
        from basilisk.plugins.recon.web_crawler import WebCrawlerPlugin

        target = Target.domain("example.com")

        page_html = (
            '<html><body>'
            '<script>window.webpackJsonp = [];</script>'
            '</body></html>'
        )

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            if "manifest" in url:
                resp.status = 200
                resp.text = AsyncMock(return_value='{"files": {}}')
            else:
                resp.status = 200
                resp.text = AsyncMock(return_value=page_html)
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        mock_ctx.http.get = mock_get

        plugin = WebCrawlerPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data["webpack_detected"] is True
        assert any("webpack" in f.title.lower() for f in result.findings)


# =====================================================================
# shodan_lookup
# =====================================================================


class TestShodanLookup:
    async def test_success(self, mock_ctx):
        import json

        from basilisk.plugins.recon.shodan_lookup import ShodanLookupPlugin

        target = Target.domain("example.com")
        mock_ctx.state["SHODAN_API_KEY"] = "test-api-key"
        mock_ctx.pipeline["dns_enum:example.com"] = MagicMock(
            ok=True,
            data={"a_records": ["93.184.216.34"]},
        )

        shodan_json = json.dumps({
            "ports": [80, 443, 22],
            "org": "Edgecast Inc.",
            "asn": "AS15133",
            "os": "Linux",
            "data": [
                {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.18"},
                {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18"},
                {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.9"},
            ],
        })

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=shodan_json)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = ShodanLookupPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data["ip"] == "93.184.216.34"
        assert 80 in result.data["ports"]
        assert len(result.data["services"]) == 3

    async def test_no_api_key(self, mock_ctx):
        from basilisk.plugins.recon.shodan_lookup import ShodanLookupPlugin

        target = Target.domain("example.com")
        # Ensure no API key
        mock_ctx.state.pop("SHODAN_API_KEY", None)

        with patch.dict("os.environ", {"SHODAN_API_KEY": ""}):
            plugin = ShodanLookupPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("not configured" in f.title.lower() for f in result.findings)

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.recon.shodan_lookup import ShodanLookupPlugin

        mock_ctx.http = None
        mock_ctx.state["SHODAN_API_KEY"] = "test-key"
        target = Target.domain("example.com")
        plugin = ShodanLookupPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_ip_resolved(self, mock_ctx):
        from basilisk.plugins.recon.shodan_lookup import ShodanLookupPlugin

        target = Target.domain("example.com")
        mock_ctx.state["SHODAN_API_KEY"] = "test-key"
        # No dns_enum result in pipeline, dns resolve returns empty
        mock_ctx.dns.resolve = AsyncMock(return_value=[])

        plugin = ShodanLookupPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("could not resolve" in f.title.lower() for f in result.findings)

    async def test_api_returns_401(self, mock_ctx):

        from basilisk.plugins.recon.shodan_lookup import ShodanLookupPlugin

        target = Target.domain("example.com")
        mock_ctx.state["SHODAN_API_KEY"] = "invalid-key"
        mock_ctx.pipeline["dns_enum:example.com"] = MagicMock(
            ok=True,
            data={"a_records": ["1.2.3.4"]},
        )

        mock_resp = MagicMock()
        mock_resp.status = 401
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = ShodanLookupPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("invalid" in f.title.lower() for f in result.findings)


# =====================================================================
# github_dorking
# =====================================================================


class TestGithubDorking:
    async def test_success_finds_leaks(self, mock_ctx):
        import json

        from basilisk.plugins.recon.github_dorking import GithubDorkingPlugin

        target = Target.domain("example.com")
        mock_ctx.state["GITHUB_TOKEN"] = "ghp_test_token"

        github_resp = json.dumps({
            "items": [
                {
                    "repository": {"full_name": "user/repo"},
                    "path": "config.py",
                    "html_url": "https://github.com/user/repo/blob/main/config.py",
                    "text_matches": [{"fragment": "password = 'secret123'"}],
                },
            ],
        })

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=github_resp)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        # Patch sleep to avoid slow test
        with patch.object(GithubDorkingPlugin, "_sleep_rate_limit", new_callable=AsyncMock):
            plugin = GithubDorkingPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert len(result.data["github_leaks"]) > 0
        assert any("leak" in f.title.lower() for f in result.findings)

    async def test_no_github_token(self, mock_ctx):
        from basilisk.plugins.recon.github_dorking import GithubDorkingPlugin

        target = Target.domain("example.com")
        mock_ctx.state.pop("GITHUB_TOKEN", None)

        with patch.dict("os.environ", {"GITHUB_TOKEN": ""}):
            plugin = GithubDorkingPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("not configured" in f.title.lower() for f in result.findings)

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.recon.github_dorking import GithubDorkingPlugin

        mock_ctx.http = None
        mock_ctx.state["GITHUB_TOKEN"] = "ghp_test"
        target = Target.domain("example.com")
        plugin = GithubDorkingPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_leaks_found(self, mock_ctx):
        import json

        from basilisk.plugins.recon.github_dorking import GithubDorkingPlugin

        target = Target.domain("example.com")
        mock_ctx.state["GITHUB_TOKEN"] = "ghp_test_token"

        # All searches return empty
        empty_resp = json.dumps({"items": []})
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=empty_resp)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        with patch.object(GithubDorkingPlugin, "_sleep_rate_limit", new_callable=AsyncMock):
            plugin = GithubDorkingPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("no github" in f.title.lower() for f in result.findings)


# =====================================================================
# tls_cipher_scan
# =====================================================================


class TestTlsCipherScan:
    async def test_success_strong_tls(self, mock_ctx):
        from basilisk.plugins.scanning.tls_cipher_scan import TlsCipherScanPlugin

        target = Target.domain("example.com")

        mock_ssl_obj = MagicMock()
        mock_ssl_obj.version.return_value = "TLSv1.3"
        mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        mock_writer = MagicMock()
        mock_writer.get_extra_info = MagicMock(return_value=mock_ssl_obj)
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        mock_reader = MagicMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)
            plugin = TlsCipherScanPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data["protocol"] == "TLSv1.3"
        assert result.data["cipher"] == "TLS_AES_256_GCM_SHA384"
        assert result.data["bits"] == 256
        # No security issues — should only have an info finding
        assert all(f.severity.value <= 1 for f in result.findings)

    async def test_weak_protocol_tls10(self, mock_ctx):
        from basilisk.plugins.scanning.tls_cipher_scan import TlsCipherScanPlugin

        target = Target.domain("example.com")

        mock_ssl_obj = MagicMock()
        mock_ssl_obj.version.return_value = "TLSv1"
        mock_ssl_obj.cipher.return_value = ("AES128-SHA", "TLSv1", 128)

        mock_writer = MagicMock()
        mock_writer.get_extra_info = MagicMock(return_value=mock_ssl_obj)
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        mock_reader = MagicMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)
            plugin = TlsCipherScanPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        # Should flag TLSv1 as outdated
        assert any("outdated" in f.title.lower() for f in result.findings)

    async def test_connection_failure(self, mock_ctx):
        from basilisk.plugins.scanning.tls_cipher_scan import TlsCipherScanPlugin

        target = Target.domain("example.com")

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError("Connection refused")
            plugin = TlsCipherScanPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("could not" in f.title.lower() for f in result.findings)

    async def test_weak_cipher_detected(self, mock_ctx):
        from basilisk.plugins.scanning.tls_cipher_scan import TlsCipherScanPlugin

        target = Target.domain("example.com")

        mock_ssl_obj = MagicMock()
        mock_ssl_obj.version.return_value = "TLSv1.2"
        mock_ssl_obj.cipher.return_value = ("RC4-SHA", "TLSv1.2", 128)

        mock_writer = MagicMock()
        mock_writer.get_extra_info = MagicMock(return_value=mock_ssl_obj)
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        mock_reader = MagicMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)
            plugin = TlsCipherScanPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("weak cipher" in f.title.lower() for f in result.findings)


# =====================================================================
# websocket_detect
# =====================================================================


class TestWebSocketDetect:
    async def test_success_ws_endpoint_found(self, mock_ctx):
        from basilisk.plugins.scanning.websocket_detect import WebSocketDetectPlugin

        target = Target.domain("example.com")

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            headers = kwargs.get("headers", {})
            if headers.get("Upgrade") == "websocket" and "/ws" in url and "/ws/" not in url:
                # WebSocket upgrade accepted
                resp.status = 101
                resp.headers = {"upgrade": "websocket"}
            elif url.endswith("/"):
                resp.status = 200
                resp.text = AsyncMock(
                    return_value='<html><script>var ws = new WebSocket("wss://example.com/ws")</script></html>',
                )
                resp.headers = {"Content-Type": "text/html"}
            else:
                resp.status = 404
                resp.headers = {}
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        mock_ctx.http.get = mock_get

        plugin = WebSocketDetectPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert len(result.data["websocket_endpoints"]) >= 1
        assert any("websocket" in f.title.lower() for f in result.findings)

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.scanning.websocket_detect import WebSocketDetectPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = WebSocketDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_host_not_reachable(self, mock_ctx):
        from basilisk.plugins.scanning.websocket_detect import WebSocketDetectPlugin

        target = Target.domain("example.com")
        mock_ctx.state["http_scheme"] = {}
        mock_ctx.http.get = AsyncMock(side_effect=Exception("Connection refused"))

        plugin = WebSocketDetectPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("not reachable" in f.title.lower() for f in result.findings)

    async def test_no_ws_endpoints(self, mock_ctx):
        from basilisk.plugins.scanning.websocket_detect import WebSocketDetectPlugin

        target = Target.domain("example.com")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="<html><body>Hello</body></html>")
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        # All WS path probes return 404
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            if url.endswith("/"):
                resp.status = 200
                resp.text = AsyncMock(return_value="<html>No WS here</html>")
                resp.headers = {"Content-Type": "text/html"}
            else:
                resp.status = 404
                resp.headers = {}
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        mock_ctx.http.get = mock_get

        plugin = WebSocketDetectPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("no websocket" in f.title.lower() for f in result.findings)


# =====================================================================
# ipv6_scan
# =====================================================================


class TestIpv6Scan:
    async def test_success_with_ipv6(self, mock_ctx):
        from basilisk.plugins.scanning.ipv6_scan import Ipv6ScanPlugin

        target = Target.domain("example.com")

        aaaa_record = MagicMock()
        aaaa_record.value = "2606:2800:220:1:248:1893:25c8:1946"

        a_record = MagicMock()
        a_record.value = "93.184.216.34"

        async def mock_resolve(host, rtype="A"):
            if rtype == "AAAA":
                return [aaaa_record]
            if rtype == "A":
                return [a_record]
            return []

        mock_ctx.dns.resolve = mock_resolve

        # Mock net.check_port for IPv6 connectivity
        port_result = MagicMock()
        port_result.state = MagicMock()
        port_result.state.value = "open"
        mock_ctx.net.check_port = AsyncMock(return_value=port_result)

        # Mock HTTP for discrepancy check
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Server": "nginx"}
        mock_resp.text = AsyncMock(return_value="<html>OK</html>")
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = Ipv6ScanPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data["has_ipv6"] is True
        assert result.data["dual_stack"] is True
        assert result.data["ipv6_reachable"] is True
        assert "2606:2800:220:1:248:1893:25c8:1946" in result.data["ipv6_addresses"]

    async def test_no_dns_client(self, mock_ctx):
        from basilisk.plugins.scanning.ipv6_scan import Ipv6ScanPlugin

        mock_ctx.dns = None
        target = Target.domain("example.com")
        plugin = Ipv6ScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_aaaa_records(self, mock_ctx):
        from basilisk.plugins.scanning.ipv6_scan import Ipv6ScanPlugin

        target = Target.domain("example.com")

        a_record = MagicMock()
        a_record.value = "93.184.216.34"

        async def mock_resolve(host, rtype="A"):
            if rtype == "A":
                return [a_record]
            return []

        mock_ctx.dns.resolve = mock_resolve

        plugin = Ipv6ScanPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data["has_ipv6"] is False
        assert any("no ipv6" in f.title.lower() for f in result.findings)

    async def test_link_local_address_flagged(self, mock_ctx):
        from basilisk.plugins.scanning.ipv6_scan import Ipv6ScanPlugin

        target = Target.domain("example.com")

        link_local = MagicMock()
        link_local.value = "fe80::1"

        a_record = MagicMock()
        a_record.value = "93.184.216.34"

        async def mock_resolve(host, rtype="A"):
            if rtype == "AAAA":
                return [link_local]
            if rtype == "A":
                return [a_record]
            return []

        mock_ctx.dns.resolve = mock_resolve
        mock_ctx.net = None  # Skip connectivity test

        plugin = Ipv6ScanPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("link-local" in f.title.lower() for f in result.findings)

    async def test_deprecated_6to4_address(self, mock_ctx):
        from basilisk.plugins.scanning.ipv6_scan import Ipv6ScanPlugin

        target = Target.domain("example.com")

        tunnel_addr = MagicMock()
        tunnel_addr.value = "2002:c000:0204::1"  # 6to4 address

        async def mock_resolve(host, rtype="A"):
            if rtype == "AAAA":
                return [tunnel_addr]
            return []

        mock_ctx.dns.resolve = mock_resolve
        mock_ctx.net = None

        plugin = Ipv6ScanPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("6to4" in f.title.lower() for f in result.findings)

    async def test_classify_ipv6_helper(self):
        from basilisk.plugins.scanning.ipv6_scan import _classify_ipv6

        props = _classify_ipv6("::1")
        assert props["is_loopback"] is True

        props = _classify_ipv6("fe80::1")
        assert props["is_link_local"] is True

        props = _classify_ipv6("2002:c000:0204::1")
        assert props["is_6to4"] is True

        result = _classify_ipv6("not-an-ip")
        assert result == {}
