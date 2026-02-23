"""Tests for Batch 2 scanning plugins (redirect_chain, graphql_detect,
dnssec_check, ssl_check).

tls_cipher_scan, websocket_detect, and ipv6_scan already have tests
in test_recon_scanning_new.py.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

from basilisk.models.target import Target

# =====================================================================
# Helpers
# =====================================================================

def _make_resp(status=200, body="", content_type="text/html", headers=None):
    """Create a mock HTTP response."""
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    hdr = {"Content-Type": content_type}
    if headers:
        hdr.update(headers)
    resp.headers = hdr
    return resp


# =====================================================================
# redirect_chain
# =====================================================================

class TestRedirectChain:
    async def test_normal_redirect_chain(self, mock_ctx):
        from basilisk.plugins.scanning.redirect_chain import RedirectChainPlugin

        target = Target.domain("example.com")

        def get_side_effect(url, **kwargs):
            if url == "http://example.com/":
                return _make_resp(301, "", headers={"Location": "https://example.com/"})
            if url == "https://example.com/":
                return _make_resp(200, "<html></html>")
            return _make_resp(200, "")

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)

        plugin = RedirectChainPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert len(result.data["chain"]) >= 2

    async def test_detects_redirect_loop(self, mock_ctx):
        from basilisk.plugins.scanning.redirect_chain import RedirectChainPlugin

        target = Target.domain("example.com")

        def get_side_effect(url, **kwargs):
            if url == "http://example.com/":
                return _make_resp(302, "", headers={"Location": "http://example.com/a"})
            if url == "http://example.com/a":
                return _make_resp(302, "", headers={"Location": "http://example.com/"})
            return _make_resp(200, "")

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)

        plugin = RedirectChainPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("loop" in f.title.lower() for f in result.findings)

    async def test_detects_https_downgrade(self, mock_ctx):
        from basilisk.plugins.scanning.redirect_chain import RedirectChainPlugin

        target = Target.domain("example.com")

        def get_side_effect(url, **kwargs):
            if url == "http://example.com/":
                return _make_resp(200, "")
            if url == "https://example.com/":
                return _make_resp(
                    301, "", headers={"Location": "http://example.com/insecure"},
                )
            if url == "http://example.com/insecure":
                return _make_resp(200, "")
            return _make_resp(200, "")

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)

        plugin = RedirectChainPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("downgrade" in f.title.lower() for f in result.findings)

    async def test_detects_no_https_redirect(self, mock_ctx):
        from basilisk.plugins.scanning.redirect_chain import RedirectChainPlugin

        target = Target.domain("example.com")

        # HTTP returns 200, no redirect to HTTPS
        def get_side_effect(url, **kwargs):
            return _make_resp(200, "<html></html>")

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)

        plugin = RedirectChainPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("no http to https" in f.title.lower() for f in result.findings)

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.scanning.redirect_chain import RedirectChainPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = RedirectChainPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_should_stop_breaks_loop(self, mock_ctx):
        from basilisk.plugins.scanning.redirect_chain import RedirectChainPlugin

        target = Target.domain("example.com")

        call_count = 0

        def get_side_effect(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                mock_ctx._deadline = time.monotonic() - 10.0
            return _make_resp(302, "", headers={"Location": f"http://example.com/r{call_count}"})

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)

        plugin = RedirectChainPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        # Should have stopped early due to should_stop
        assert len(result.data["chain"]) <= 4


# =====================================================================
# graphql_detect
# =====================================================================

class TestGraphqlDetect:
    async def test_detects_graphql_with_introspection(self, mock_ctx):
        from basilisk.plugins.scanning.graphql_detect import GraphqlDetectPlugin

        target = Target.domain("example.com")
        head_resp = _make_resp(200, "")
        schema_body = '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'
        schema_resp = _make_resp(200, schema_body, content_type="application/json")
        not_found = _make_resp(404, "Not found")

        def post_side_effect(url, **kwargs):
            if "/graphql" in url:
                return schema_resp
            return not_found

        mock_ctx.http.post = AsyncMock(side_effect=post_side_effect)
        mock_ctx.http.get = AsyncMock(return_value=not_found)
        mock_ctx.http.head = AsyncMock(return_value=head_resp)
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = GraphqlDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("introspection" in f.title.lower() for f in result.findings)
        endpoints = result.data["graphql_endpoints"]
        assert len(endpoints) > 0
        assert endpoints[0]["introspection"] is True

    async def test_detects_graphql_no_introspection(self, mock_ctx):
        from basilisk.plugins.scanning.graphql_detect import GraphqlDetectPlugin

        target = Target.domain("example.com")
        head_resp = _make_resp(200, "")
        gql_resp = _make_resp(
            200, '{"errors":[{"message":"introspection disabled"}]}',
            content_type="application/json",
        )
        not_found = _make_resp(404, "")

        def post_side_effect(url, **kwargs):
            if "/graphql" in url:
                return gql_resp
            return not_found

        mock_ctx.http.post = AsyncMock(side_effect=post_side_effect)
        mock_ctx.http.get = AsyncMock(return_value=not_found)
        mock_ctx.http.head = AsyncMock(return_value=head_resp)
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = GraphqlDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        endpoints = result.data["graphql_endpoints"]
        assert len(endpoints) > 0
        assert endpoints[0]["introspection"] is False

    async def test_detects_graphql_via_get(self, mock_ctx):
        from basilisk.plugins.scanning.graphql_detect import GraphqlDetectPlugin

        target = Target.domain("example.com")
        head_resp = _make_resp(200, "")
        not_found = _make_resp(404, "")
        schema_body = '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'
        schema_resp = _make_resp(200, schema_body, content_type="application/json")

        # POST fails, GET succeeds
        mock_ctx.http.post = AsyncMock(side_effect=Exception("POST blocked"))

        def get_side_effect(url, **kwargs):
            if "__schema" in url:
                return schema_resp
            return not_found

        mock_ctx.http.get = AsyncMock(side_effect=get_side_effect)
        mock_ctx.http.head = AsyncMock(return_value=head_resp)
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = GraphqlDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        endpoints = result.data["graphql_endpoints"]
        introspection_eps = [e for e in endpoints if e.get("introspection")]
        assert len(introspection_eps) > 0
        assert introspection_eps[0]["method"] == "GET"

    async def test_no_graphql_found(self, mock_ctx):
        from basilisk.plugins.scanning.graphql_detect import GraphqlDetectPlugin

        target = Target.domain("example.com")
        head_resp = _make_resp(200, "")
        not_found = _make_resp(404, "")
        mock_ctx.http.post = AsyncMock(return_value=not_found)
        mock_ctx.http.get = AsyncMock(return_value=not_found)
        mock_ctx.http.head = AsyncMock(return_value=head_resp)
        mock_ctx.state["http_scheme"] = {"example.com": "https"}

        plugin = GraphqlDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("no graphql" in f.title.lower() for f in result.findings)

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.scanning.graphql_detect import GraphqlDetectPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = GraphqlDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_host_not_reachable(self, mock_ctx):
        from basilisk.plugins.scanning.graphql_detect import GraphqlDetectPlugin

        target = Target.domain("example.com")
        mock_ctx.http.head = AsyncMock(side_effect=Exception("timeout"))
        mock_ctx.http.get = AsyncMock(side_effect=Exception("timeout"))
        mock_ctx.state["http_scheme"] = {}

        plugin = GraphqlDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "not reachable" in result.findings[0].title.lower()


# =====================================================================
# dnssec_check
# =====================================================================

class TestDnssecCheck:
    async def test_dnssec_not_enabled(self, mock_ctx):
        import dns.exception

        from basilisk.plugins.scanning.dnssec_check import DnssecCheckPlugin

        target = Target.domain("example.com")
        # All DNS queries return no records
        mock_ctx.dns.resolver.resolve = AsyncMock(
            side_effect=dns.exception.DNSException("no DNSKEY"),
        )

        plugin = DnssecCheckPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["dnssec_enabled"] is False
        assert any("not enabled" in f.title.lower() for f in result.findings)

    async def test_no_dns(self, mock_ctx):
        from basilisk.plugins.scanning.dnssec_check import DnssecCheckPlugin

        mock_ctx.dns = None
        target = Target.domain("example.com")
        plugin = DnssecCheckPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_weak_algorithm_detected(self, mock_ctx):
        from basilisk.plugins.scanning.dnssec_check import DnssecCheckPlugin

        target = Target.domain("example.com")

        # Mock DNSKEY with weak algorithm (5 = RSASHA1)
        dnskey_rdata = MagicMock()
        dnskey_rdata.flags = 0x0101  # ZONE + SEP (KSK)
        dnskey_rdata.algorithm = 5  # RSASHA1 = weak
        dnskey_rdata.protocol = 3
        dnskey_rdata.key = b"\x03\x01\x00\x01" + b"\x00" * 256  # fake RSA key

        dnskey_answer = MagicMock()
        dnskey_answer.__iter__ = MagicMock(return_value=iter([dnskey_rdata]))

        def resolve_side_effect(domain, rdtype):
            import dns.rdatatype
            if rdtype == dns.rdatatype.DNSKEY:
                return dnskey_answer
            raise dns.exception.DNSException("not found")

        mock_ctx.dns.resolver.resolve = AsyncMock(side_effect=resolve_side_effect)

        plugin = DnssecCheckPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("weak" in f.title.lower() and "algorithm" in f.title.lower()
                    for f in result.findings)

    async def test_dnssec_enabled_with_strong_keys(self, mock_ctx):
        from basilisk.plugins.scanning.dnssec_check import DnssecCheckPlugin

        target = Target.domain("example.com")

        # Mock DNSKEY with strong algorithm (13 = ECDSAP256SHA256)
        dnskey_rdata = MagicMock()
        dnskey_rdata.flags = 0x0101  # KSK
        dnskey_rdata.algorithm = 13  # strong
        dnskey_rdata.protocol = 3
        dnskey_rdata.key = b"\x00" * 64  # fake ECDSA P-256 key

        dnskey_answer = MagicMock()
        dnskey_answer.__iter__ = MagicMock(return_value=iter([dnskey_rdata]))

        def resolve_side_effect(domain, rdtype):
            import dns.rdatatype
            if rdtype == dns.rdatatype.DNSKEY:
                return dnskey_answer
            raise dns.exception.DNSException("not found")

        mock_ctx.dns.resolver.resolve = AsyncMock(side_effect=resolve_side_effect)

        plugin = DnssecCheckPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["dnssec_enabled"] is True
        assert "ECDSAP256SHA256" in result.data["algorithms"]


# =====================================================================
# ssl_check
# =====================================================================

class TestSslCheck:
    async def test_valid_certificate(self, mock_ctx):
        from datetime import UTC, datetime, timedelta

        from basilisk.models.types import SslInfo
        from basilisk.plugins.scanning.ssl_check import SslCheckPlugin

        target = Target.domain("example.com")
        now = datetime.now(UTC)
        ssl_info = SslInfo(
            subject={"commonName": "example.com"},
            issuer={"commonName": "Let's Encrypt"},
            serial_number="1234567890",
            not_before=now - timedelta(days=30),
            not_after=now + timedelta(days=335),
            san=["example.com", "www.example.com"],
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_size=256,
            is_expired=False,
            is_self_signed=False,
            days_until_expiry=335,
            signature_algorithm="sha256WithRSAEncryption",
        )
        cert_bin = b"\x30\x82" + b"\x00" * 100  # fake DER

        with patch("basilisk.plugins.scanning.ssl_check.ssl_connect",
                    new_callable=AsyncMock) as mock_ssl:
            mock_ssl.return_value = (ssl_info, cert_bin, {})
            plugin = SslCheckPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data["ssl_available"] is True
        assert any("TLSv1.3" in f.title for f in result.findings)

    async def test_ssl_not_available(self, mock_ctx):
        from basilisk.plugins.scanning.ssl_check import SslCheckPlugin

        target = Target.domain("example.com")

        with patch("basilisk.plugins.scanning.ssl_check.ssl_connect",
                    new_callable=AsyncMock) as mock_ssl:
            mock_ssl.side_effect = ConnectionRefusedError("Connection refused")
            plugin = SslCheckPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.status == "partial"
        assert result.data["ssl_available"] is False

    async def test_expired_certificate(self, mock_ctx):
        from datetime import UTC, datetime, timedelta

        from basilisk.models.types import SslInfo
        from basilisk.plugins.scanning.ssl_check import SslCheckPlugin

        target = Target.domain("example.com")
        now = datetime.now(UTC)
        ssl_info = SslInfo(
            subject={"commonName": "example.com"},
            issuer={"commonName": "Let's Encrypt"},
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=35),
            san=["example.com"],
            protocol="TLSv1.2",
            cipher="ECDHE-RSA-AES256-GCM-SHA384",
            key_size=2048,
            is_expired=True,
            is_self_signed=False,
            days_until_expiry=-35,
            signature_algorithm="sha256WithRSAEncryption",
        )

        with patch("basilisk.plugins.scanning.ssl_check.ssl_connect",
                    new_callable=AsyncMock) as mock_ssl:
            mock_ssl.return_value = (ssl_info, b"\x30\x82\x00", {})
            plugin = SslCheckPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("expired" in f.title.lower() for f in result.findings)

    async def test_self_signed_certificate(self, mock_ctx):
        from datetime import UTC, datetime, timedelta

        from basilisk.models.types import SslInfo
        from basilisk.plugins.scanning.ssl_check import SslCheckPlugin

        target = Target.domain("example.com")
        now = datetime.now(UTC)
        ssl_info = SslInfo(
            subject={"commonName": "example.com"},
            issuer={"commonName": "example.com"},
            not_before=now - timedelta(days=30),
            not_after=now + timedelta(days=335),
            san=["example.com"],
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_size=2048,
            is_expired=False,
            is_self_signed=True,
            days_until_expiry=335,
            signature_algorithm="sha256WithRSAEncryption",
        )

        with patch("basilisk.plugins.scanning.ssl_check.ssl_connect",
                    new_callable=AsyncMock) as mock_ssl:
            mock_ssl.return_value = (ssl_info, b"\x30\x82\x00", {})
            plugin = SslCheckPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("self-signed" in f.title.lower() for f in result.findings)

    async def test_hostname_mismatch(self, mock_ctx):
        from datetime import UTC, datetime, timedelta

        from basilisk.models.types import SslInfo
        from basilisk.plugins.scanning.ssl_check import SslCheckPlugin

        target = Target.domain("example.com")
        now = datetime.now(UTC)
        ssl_info = SslInfo(
            subject={"commonName": "other.com"},
            issuer={"commonName": "CA"},
            not_before=now - timedelta(days=30),
            not_after=now + timedelta(days=335),
            san=["other.com", "www.other.com"],
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_size=2048,
            is_expired=False,
            is_self_signed=False,
            days_until_expiry=335,
            signature_algorithm="sha256WithRSAEncryption",
        )

        with patch("basilisk.plugins.scanning.ssl_check.ssl_connect",
                    new_callable=AsyncMock) as mock_ssl:
            mock_ssl.return_value = (ssl_info, b"\x30\x82\x00", {})
            plugin = SslCheckPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("mismatch" in f.title.lower() for f in result.findings)

    async def test_weak_rsa_key(self, mock_ctx):
        from datetime import UTC, datetime, timedelta

        from basilisk.models.types import SslInfo
        from basilisk.plugins.scanning.ssl_check import SslCheckPlugin

        target = Target.domain("example.com")
        now = datetime.now(UTC)
        ssl_info = SslInfo(
            subject={"commonName": "example.com"},
            issuer={"commonName": "CA"},
            not_before=now - timedelta(days=30),
            not_after=now + timedelta(days=335),
            san=["example.com"],
            protocol="TLSv1.2",
            cipher="RSA-AES256-GCM-SHA384",
            key_size=1024,
            is_expired=False,
            is_self_signed=False,
            days_until_expiry=335,
            signature_algorithm="sha256WithRSAEncryption",
        )

        with patch("basilisk.plugins.scanning.ssl_check.ssl_connect",
                    new_callable=AsyncMock) as mock_ssl:
            mock_ssl.return_value = (ssl_info, b"\x30\x82\x00", {})
            plugin = SslCheckPlugin()
            result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert any("weak" in f.title.lower() and "1024" in f.title for f in result.findings)
