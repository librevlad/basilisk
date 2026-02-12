"""Tests for HTTP reachability utilities."""

from unittest.mock import AsyncMock, MagicMock

from basilisk.utils.http_check import resolve_base_url


class TestResolveBaseUrl:
    async def test_cache_hit_https(self):
        ctx = MagicMock()
        ctx.state = {"http_scheme": {"example.com": "https"}}
        result = await resolve_base_url("example.com", ctx)
        assert result == "https://example.com"

    async def test_cache_hit_http(self):
        ctx = MagicMock()
        ctx.state = {"http_scheme": {"example.com": "http"}}
        result = await resolve_base_url("example.com", ctx)
        assert result == "http://example.com"

    async def test_cache_hit_none(self):
        ctx = MagicMock()
        ctx.state = {"http_scheme": {"example.com": None}}
        result = await resolve_base_url("example.com", ctx)
        assert result is None

    async def test_no_cache_probe_https_success(self):
        ctx = MagicMock()
        ctx.state = {}
        ctx.http = AsyncMock()
        ctx.http.head = AsyncMock(return_value=MagicMock())
        result = await resolve_base_url("example.com", ctx)
        assert result == "https://example.com"

    async def test_no_cache_probe_http_fallback(self):
        ctx = MagicMock()
        ctx.state = {}
        ctx.http = AsyncMock()
        call_count = 0

        async def mock_head(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "https" in url:
                raise ConnectionError("refused")
            return MagicMock()

        ctx.http.head = mock_head
        result = await resolve_base_url("example.com", ctx)
        assert result == "http://example.com"

    async def test_no_cache_both_fail(self):
        ctx = MagicMock()
        ctx.state = {}
        ctx.http = AsyncMock()
        ctx.http.head = AsyncMock(side_effect=ConnectionError("refused"))
        result = await resolve_base_url("example.com", ctx)
        assert result is None

    async def test_no_http_client(self):
        ctx = MagicMock()
        ctx.state = {}
        ctx.http = None
        result = await resolve_base_url("example.com", ctx)
        assert result is None
