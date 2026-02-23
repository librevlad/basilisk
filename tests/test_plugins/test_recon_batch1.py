"""Tests for Batch 1 recon plugins (non-subdomain) + scanning fixes."""

from unittest.mock import AsyncMock, MagicMock

from basilisk.models.target import Target

# =====================================================================
# dns_zone_transfer
# =====================================================================

class TestDnsZoneTransfer:
    async def test_zone_denied(self, mock_ctx):
        from basilisk.plugins.recon.dns_zone_transfer import DnsZoneTransferPlugin

        target = Target.domain("example.com")
        mock_ctx.dns.resolve = AsyncMock(return_value=[
            MagicMock(value="ns1.example.com."),
            MagicMock(value="ns2.example.com."),
        ])

        plugin = DnsZoneTransferPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["zone_transfer"] is False
        assert "denied" in result.findings[0].title.lower()

    async def test_no_ns_records(self, mock_ctx):
        from basilisk.plugins.recon.dns_zone_transfer import DnsZoneTransferPlugin

        target = Target.domain("example.com")
        mock_ctx.dns.resolve = AsyncMock(return_value=[])

        plugin = DnsZoneTransferPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "no ns" in result.findings[0].title.lower()

    async def test_no_dns_client(self, mock_ctx):
        from basilisk.plugins.recon.dns_zone_transfer import DnsZoneTransferPlugin

        mock_ctx.dns = None
        target = Target.domain("example.com")
        plugin = DnsZoneTransferPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# asn_lookup
# =====================================================================

class TestAsnLookup:
    async def test_success(self, mock_ctx):
        from basilisk.plugins.recon.asn_lookup import AsnLookupPlugin

        target = Target.domain("example.com")
        target.ips = ["93.184.216.34"]

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value={
            "as": "AS15133 Edgecast Inc.",
            "org": "Edgecast Inc.",
            "isp": "Verizon Digital Media",
            "country": "United States",
            "city": "Los Angeles",
            "query": "93.184.216.34",
        })
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = AsnLookupPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["asn"] == "AS15133 Edgecast Inc."
        assert result.data["org"] == "Edgecast Inc."

    async def test_rate_limited(self, mock_ctx):
        from basilisk.plugins.recon.asn_lookup import AsnLookupPlugin

        target = Target.domain("example.com")
        target.ips = ["1.2.3.4"]

        mock_resp = AsyncMock()
        mock_resp.status = 429
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = AsnLookupPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "rate limited" in result.findings[0].title.lower()

    async def test_no_ip(self, mock_ctx):
        from basilisk.plugins.recon.asn_lookup import AsnLookupPlugin

        target = Target.domain("example.com")
        mock_ctx.dns.resolve = AsyncMock(return_value=[])

        plugin = AsnLookupPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "no ip" in result.findings[0].title.lower()

    async def test_api_error_message(self, mock_ctx):
        from basilisk.plugins.recon.asn_lookup import AsnLookupPlugin

        target = Target.domain("example.com")
        target.ips = ["1.2.3.4"]

        mock_resp = AsyncMock()
        mock_resp.status = 500
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = AsnLookupPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "http 500" in result.findings[0].title.lower()


# =====================================================================
# reverse_ip
# =====================================================================

class TestReverseIp:
    async def test_hackertarget_api_count_exceeded(self, mock_ctx):
        from basilisk.plugins.recon.reverse_ip import ReverseIpPlugin

        target = Target.domain("example.com")
        target.ips = ["1.2.3.4"]

        # HackerTarget returns "API count exceeded"
        mock_ctx.http.fetch_text = AsyncMock(
            return_value="API count exceeded - Bandwidth Limit Exceeded"
        )
        mock_resp = AsyncMock()
        mock_resp.status = 403  # ViewDNS blocked
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)
        mock_ctx.dns.reverse_lookup = AsyncMock(return_value=[])

        plugin = ReverseIpPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        # Should return "no shared hosts" since all sources failed
        assert "no shared hosts" in result.findings[0].title.lower()

    async def test_rejects_no_ips(self):
        from basilisk.plugins.recon.reverse_ip import ReverseIpPlugin

        target = Target.domain("example.com")
        plugin = ReverseIpPlugin()
        assert plugin.accepts(target) is False

    async def test_accepts_with_ips(self):
        from basilisk.plugins.recon.reverse_ip import ReverseIpPlugin

        target = Target.domain("example.com")
        target.ips = ["1.2.3.4"]
        plugin = ReverseIpPlugin()
        assert plugin.accepts(target) is True


# =====================================================================
# s3_bucket_finder
# =====================================================================

class TestS3BucketFinder:
    async def test_meta_disabled_by_default(self):
        from basilisk.plugins.recon.s3_bucket_finder import S3BucketFinderPlugin

        plugin = S3BucketFinderPlugin()
        assert plugin.meta.default_enabled is False

    async def test_finds_public_bucket(self, mock_ctx):
        from basilisk.plugins.recon.s3_bucket_finder import S3BucketFinderPlugin

        target = Target.domain("example.com")

        async def mock_get(url, **kwargs):
            resp = AsyncMock()
            if "example" in url and "backup" not in url:
                resp.status = 200
                resp.text = AsyncMock(return_value="<ListBucketResult>...")
            else:
                resp.status = 404
                resp.text = AsyncMock(return_value="NoSuchBucket")
            return resp

        mock_ctx.http.get = mock_get

        plugin = S3BucketFinderPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        # Should find at least one public bucket
        assert any("public s3" in f.title.lower() for f in result.findings)

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.recon.s3_bucket_finder import S3BucketFinderPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = S3BucketFinderPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# robots_parser
# =====================================================================

class TestRobotsParser:
    async def test_disallow_found(self, mock_ctx):
        from basilisk.plugins.recon.robots_parser import RobotsParserPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=(
            "User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /secret\n"
            "Sitemap: https://example.com/sitemap.xml\n"
        ))
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = RobotsParserPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "/admin" in result.data.get("disallow_paths", [])


# =====================================================================
# email_harvest
# =====================================================================

class TestEmailHarvest:
    async def test_pgp_emails(self, mock_ctx):
        from basilisk.plugins.recon.email_harvest import EmailHarvestPlugin

        target = Target.domain("example.com")

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = AsyncMock()
            if "openpgp.org" in url:
                resp.status = 200
                resp.text = AsyncMock(return_value="admin@example.com info@example.com")
            elif "gnupg.net" in url:
                resp.status = 200
                resp.text = AsyncMock(return_value="")
            elif "github.com" in url:
                resp.status = 200
                resp.json = AsyncMock(return_value={"items": []})
            else:
                resp.status = 404
                resp.text = AsyncMock(return_value="")
            return resp

        mock_ctx.http.get = mock_get

        plugin = EmailHarvestPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "admin@example.com" in result.data.get("domain_emails", [])

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.recon.email_harvest import EmailHarvestPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = EmailHarvestPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# cloud_bucket_enum
# =====================================================================

class TestCloudBucketEnum:
    async def test_finds_aws_bucket(self, mock_ctx):
        from basilisk.plugins.recon.cloud_bucket_enum import CloudBucketEnumPlugin

        target = Target.domain("example.com")

        async def mock_get(url, **kwargs):
            resp = AsyncMock()
            if "s3.amazonaws.com" in url and "example" in url:
                resp.status = 403  # exists but denied
                resp.text = AsyncMock(return_value="AccessDenied")
            else:
                resp.status = 404
                resp.text = AsyncMock(return_value="NoSuchBucket")
            return resp

        mock_ctx.http.get = mock_get

        plugin = CloudBucketEnumPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.recon.cloud_bucket_enum import CloudBucketEnumPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = CloudBucketEnumPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# cookie_scan (scanning)
# =====================================================================

class TestCookieScan:
    async def test_parse_secure_flag(self):
        from basilisk.plugins.scanning.cookie_scan import CookieScanPlugin

        plugin = CookieScanPlugin()
        cookie = plugin._parse_cookie(
            "session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/",
            is_https=True,
        )
        assert cookie["secure"] is True
        assert cookie["httponly"] is True
        assert cookie["samesite"] is True
        assert cookie["samesite_value"] == "Strict"
        assert cookie["path"] == "/"

    async def test_parse_insecure_cookie(self):
        from basilisk.plugins.scanning.cookie_scan import CookieScanPlugin

        plugin = CookieScanPlugin()
        cookie = plugin._parse_cookie("tracker=xyz; Path=/", is_https=False)
        assert cookie["secure"] is False
        assert cookie["httponly"] is False
        assert cookie["samesite"] is False

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.scanning.cookie_scan import CookieScanPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = CookieScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


# =====================================================================
# cdn_detect (scanning)
# =====================================================================

class TestCdnDetect:
    async def test_cloudflare_detected(self, mock_ctx):
        from basilisk.plugins.scanning.cdn_detect import CdnDetectPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {"cf-ray": "abc123", "server": "cloudflare"}
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)
        mock_ctx.dns.resolve = AsyncMock(return_value=[])

        plugin = CdnDetectPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert any("cloudflare" in f.title.lower() for f in result.findings)


# =====================================================================
# http_methods_scan (scanning)
# =====================================================================

class TestHttpMethodsScan:
    async def test_basic_methods(self, mock_ctx):
        from basilisk.plugins.scanning.http_methods_scan import HttpMethodsScanPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {"Allow": "GET, HEAD, POST"}
        mock_ctx.http.request = AsyncMock(return_value=mock_resp)
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)
        mock_ctx.http.head = AsyncMock(return_value=mock_resp)
        mock_ctx.http.post = AsyncMock(return_value=mock_resp)

        plugin = HttpMethodsScanPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok


# =====================================================================
# dns_enum — evidence quality
# =====================================================================

class TestDnsEnumEvidence:
    async def test_no_spf_has_evidence(self, mock_ctx):
        """Ensure MEDIUM findings have evidence field (quality check)."""
        from basilisk.plugins.recon.dns_enum import DnsEnumPlugin

        target = Target.domain("example.com")
        # Return A records but no TXT
        mock_a = MagicMock()
        mock_a.type = MagicMock()
        mock_a.type.name = "A"
        mock_a.value = "1.2.3.4"

        async def mock_resolve(domain, rtype="A"):
            if rtype == "A":
                return [mock_a]
            return []

        mock_ctx.dns.resolve = mock_resolve
        mock_ctx.dns.resolve_all = AsyncMock(return_value=[mock_a])

        plugin = DnsEnumPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok

        # All MEDIUM+ findings must have evidence
        for f in result.findings:
            if f.severity.value >= 2:  # MEDIUM = 2
                assert f.evidence, f"Finding '{f.title}' has no evidence"
