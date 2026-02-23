"""Tests for recon plugin run() methods."""

from unittest.mock import AsyncMock

from basilisk.models.target import Target
from basilisk.models.types import DnsRecord, DnsRecordType


class TestDnsEnumPlugin:
    async def test_success(self, mock_ctx):
        from basilisk.plugins.recon.dns_enum import DnsEnumPlugin

        target = Target.domain("example.com")
        mock_ctx.dns.resolve_all = AsyncMock(return_value=[
            DnsRecord(type=DnsRecordType.A, name="example.com", value="1.2.3.4", ttl=300),
            DnsRecord(type=DnsRecordType.MX, name="example.com", value="mail.example.com",
                      ttl=300, priority=10),
        ])

        plugin = DnsEnumPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert "1.2.3.4" in target.ips
        assert len(result.data["records"]) == 2

    async def test_no_dns_client(self, mock_ctx):
        from basilisk.plugins.recon.dns_enum import DnsEnumPlugin

        mock_ctx.dns = None
        target = Target.domain("example.com")
        plugin = DnsEnumPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_no_records(self, mock_ctx):
        from basilisk.plugins.recon.dns_enum import DnsEnumPlugin

        target = Target.domain("example.com")
        mock_ctx.dns.resolve_all = AsyncMock(return_value=[])
        plugin = DnsEnumPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok


class TestSubdomainCrtsh:
    async def test_success(self, mock_ctx):
        import json

        from basilisk.plugins.recon.subdomain_crtsh import SubdomainCrtshPlugin

        target = Target.domain("example.com")
        # crt.sh plugin uses ctx.http.fetch_text(), not ctx.http.get().json()
        json_data = [
            {"name_value": "api.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "mail.example.com"},
        ]
        mock_ctx.http.fetch_text = AsyncMock(return_value=json.dumps(json_data))

        plugin = SubdomainCrtshPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        subs = result.data.get("subdomains", [])
        assert "api.example.com" in subs
        assert "mail.example.com" in subs

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_crtsh import SubdomainCrtshPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = SubdomainCrtshPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


class TestReverseIp:
    async def test_accepts_with_ips(self):
        from basilisk.plugins.recon.reverse_ip import ReverseIpPlugin

        target = Target.domain("example.com")
        target.ips = ["1.2.3.4"]
        plugin = ReverseIpPlugin()
        assert plugin.accepts(target) is True

    async def test_rejects_no_ips(self):
        from basilisk.plugins.recon.reverse_ip import ReverseIpPlugin

        target = Target.domain("example.com")
        plugin = ReverseIpPlugin()
        assert plugin.accepts(target) is False

    async def test_success(self, mock_ctx):
        from basilisk.plugins.recon.reverse_ip import ReverseIpPlugin

        target = Target.domain("example.com")
        target.ips = ["1.2.3.4"]
        mock_ctx.http.fetch_text = AsyncMock(return_value="other.com\nanother.com\n")

        plugin = ReverseIpPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok


class TestRobotsParser:
    async def test_success(self, mock_ctx):
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
