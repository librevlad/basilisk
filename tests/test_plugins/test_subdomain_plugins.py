"""Tests for subdomain discovery plugins."""

from unittest.mock import AsyncMock

from basilisk.models.target import Target


class TestSubdomainCertspotter:
    async def test_success(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_certspotter import SubdomainCertspotterPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=[
            {"dns_names": ["api.example.com", "mail.example.com", "*.example.com"]},
            {"dns_names": ["dev.example.com", "example.com"]},
        ])
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SubdomainCertspotterPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        subs = result.data["subdomains"]
        assert "api.example.com" in subs
        assert "mail.example.com" in subs
        assert "dev.example.com" in subs
        assert "example.com" not in subs  # root domain excluded

    async def test_rate_limited(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_certspotter import SubdomainCertspotterPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 429
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SubdomainCertspotterPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data["subdomains"] == []
        assert "rate limited" in result.findings[0].title.lower()

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_certspotter import SubdomainCertspotterPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = SubdomainCertspotterPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_empty_response(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_certspotter import SubdomainCertspotterPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=[])
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SubdomainCertspotterPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert result.data["subdomains"] == []


class TestSubdomainAnubis:
    async def test_success(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_anubis import SubdomainAnubisPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=[
            "api.example.com",
            "mail.example.com",
            "dev.example.com",
            "example.com",  # root should be excluded
        ])
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SubdomainAnubisPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        subs = result.data["subdomains"]
        assert "api.example.com" in subs
        assert "mail.example.com" in subs
        assert "dev.example.com" in subs
        assert "example.com" not in subs

    async def test_rate_limited(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_anubis import SubdomainAnubisPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 429
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SubdomainAnubisPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data["subdomains"] == []

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_anubis import SubdomainAnubisPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = SubdomainAnubisPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"

    async def test_invalid_json_entries(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_anubis import SubdomainAnubisPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        # Mix of valid strings and invalid entries
        mock_resp.json = AsyncMock(return_value=[
            "api.example.com", None, 123, "valid.example.com",
        ])
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SubdomainAnubisPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "api.example.com" in result.data["subdomains"]
        assert "valid.example.com" in result.data["subdomains"]


class TestSubdomainHackerTarget:
    async def test_api_count_exceeded(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_hackertarget import SubdomainHackerTargetPlugin

        target = Target.domain("example.com")
        mock_ctx.http.fetch_text = AsyncMock(
            return_value="API count exceeded - Bandwidth Limit Exceeded"
        )

        plugin = SubdomainHackerTargetPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data["subdomains"] == []
        assert "api count exceeded" in result.findings[0].title.lower()

    async def test_success(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_hackertarget import SubdomainHackerTargetPlugin

        target = Target.domain("example.com")
        mock_ctx.http.fetch_text = AsyncMock(
            return_value="api.example.com,1.2.3.4\nmail.example.com,5.6.7.8\n"
        )

        plugin = SubdomainHackerTargetPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        subs = result.data["subdomains"]
        assert "api.example.com" in subs
        assert "mail.example.com" in subs


class TestSubdomainAlienVault:
    async def test_rate_limited(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_alienvault import SubdomainAlienVaultPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 429
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SubdomainAlienVaultPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert result.data["subdomains"] == []
        assert "rate limited" in result.findings[0].title.lower()

    async def test_success(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_alienvault import SubdomainAlienVaultPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value={
            "passive_dns": [
                {"hostname": "api.example.com"},
                {"hostname": "mail.example.com"},
                {"hostname": "example.com"},  # root excluded
            ]
        })
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SubdomainAlienVaultPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "api.example.com" in result.data["subdomains"]
        assert "mail.example.com" in result.data["subdomains"]


class TestSubdomainVirusTotal:
    async def test_no_api_key_rate_limited(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_virustotal import SubdomainVirusTotalPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 429
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SubdomainVirusTotalPlugin()
        result = await plugin.run(target, mock_ctx)

        assert result.ok
        assert "rate limited" in result.findings[0].title.lower()
        assert "virustotal_api_key" in result.findings[0].title.lower()

    async def test_no_http(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_virustotal import SubdomainVirusTotalPlugin

        mock_ctx.http = None
        target = Target.domain("example.com")
        plugin = SubdomainVirusTotalPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.status == "error"


class TestSubdomainDnsDumpster:
    async def test_api_success(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_dnsdumpster import SubdomainDnsDumpsterPlugin

        target = Target.domain("example.com")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value={
            "dns_records": {"host": [
                {"host": "api.example.com"},
                {"host": "mail.example.com"},
            ]}
        })
        mock_ctx.http.get = AsyncMock(return_value=mock_resp)

        plugin = SubdomainDnsDumpsterPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        assert "api.example.com" in result.data["subdomains"]

    async def test_api_401_html_fallback(self, mock_ctx):
        from basilisk.plugins.recon.subdomain_dnsdumpster import SubdomainDnsDumpsterPlugin

        target = Target.domain("example.com")

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = AsyncMock()
            if "api.dnsdumpster.com" in url:
                resp.status = 401  # API requires key
                resp.json = AsyncMock(return_value={})
            else:
                resp.status = 200
                resp.text = AsyncMock(
                    return_value=(
                        '<td>api.example.com</td><td>mail.example.com</td>'
                    )
                )
            return resp

        mock_ctx.http.get = mock_get

        plugin = SubdomainDnsDumpsterPlugin()
        result = await plugin.run(target, mock_ctx)
        assert result.ok
        subs = result.data["subdomains"]
        assert "api.example.com" in subs
        assert "mail.example.com" in subs
