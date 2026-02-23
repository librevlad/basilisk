"""Tests for session_check plugin."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from basilisk.models.target import Target
from basilisk.plugins.pentesting.session_check import SessionCheckPlugin


def _make_ctx(*, set_cookies: list[list[str]] | None = None):
    """Build a mock PluginContext.

    set_cookies: list of Set-Cookie header lists, one per request.
    """
    ctx = MagicMock()
    ctx.should_stop = False
    ctx.state = {}
    ctx.pipeline = {}

    rate = MagicMock()
    rate.__aenter__ = AsyncMock()
    rate.__aexit__ = AsyncMock()
    ctx.rate = rate

    cookie_iter = iter(set_cookies or [])

    async def _get(url, **kw):
        try:
            cookies = next(cookie_iter)
        except StopIteration:
            cookies = []
        resp = MagicMock()
        resp.status = 200
        resp.text = AsyncMock(return_value="OK")
        resp.headers = MagicMock()
        resp.headers.getall = MagicMock(return_value=cookies)
        return resp

    async def _head(url, **kw):
        resp = MagicMock()
        resp.status = 200
        return resp

    http = MagicMock()
    http.get = AsyncMock(side_effect=_get)
    http.head = AsyncMock(side_effect=_head)
    ctx.http = http

    dns = MagicMock()
    dns.resolve = AsyncMock(return_value=["127.0.0.1"])
    ctx.dns = dns

    config = MagicMock()
    config.http = MagicMock()
    config.http.verify_ssl = False
    ctx.config = config

    return ctx


class TestSessionCheckMeta:
    def test_meta(self):
        p = SessionCheckPlugin()
        assert p.meta.name == "session_check"
        assert p.meta.category.value == "pentesting"

    def test_discovery(self):
        from basilisk.core.registry import PluginRegistry
        r = PluginRegistry()
        r.discover()
        names = [p.meta.name for p in r.all()]
        assert "session_check" in names


class TestSessionCheckNoHttp:
    @pytest.mark.asyncio
    async def test_no_http(self):
        ctx = MagicMock()
        ctx.http = None
        target = Target.domain("test.com")
        p = SessionCheckPlugin()
        result = await p.run(target, ctx)
        assert not result.ok


class TestSessionCheckNoCookies:
    @pytest.mark.asyncio
    async def test_no_session_cookies(self):
        """When server sets no session cookies, returns info finding."""
        ctx = _make_ctx(set_cookies=[[] for _ in range(15)])
        target = Target.domain("test.com")
        p = SessionCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        assert any("no session" in f.title.lower() for f in result.findings)


class TestSessionCheckSequential:
    @pytest.mark.asyncio
    async def test_detects_sequential_ids(self):
        """Sequential numeric session IDs should be flagged as CRITICAL."""
        cookies = [
            [f"PHPSESSID={1000 + i}; Path=/; HttpOnly"]
            for i in range(10)
        ]
        # Extra request for fixation test
        cookies.append([])
        ctx = _make_ctx(set_cookies=cookies)
        target = Target.domain("test.com")
        p = SessionCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        critical = [f for f in result.findings if f.severity.value >= 4]
        assert len(critical) >= 1
        assert any("sequential" in f.title.lower() for f in critical)


class TestSessionCheckLowEntropy:
    @pytest.mark.asyncio
    async def test_detects_low_entropy(self):
        """Tokens with very low entropy should be flagged."""
        # All same character = 0 entropy
        cookies = [
            ["PHPSESSID=aaaaaaaaaaaaaaaaaa; Path=/"]
            for _ in range(10)
        ]
        cookies.append([])
        ctx = _make_ctx(set_cookies=cookies)
        target = Target.domain("test.com")
        p = SessionCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        # Should find entropy issue
        assert any(
            "entropy" in f.title.lower() or "numeric" in f.title.lower()
            for f in result.findings
        )


class TestSessionCheckShortToken:
    @pytest.mark.asyncio
    async def test_detects_short_tokens(self):
        """Short session tokens should be flagged."""
        cookies = [
            [f"sid=ab{i}; Path=/"]
            for i in range(10)
        ]
        cookies.append([])
        ctx = _make_ctx(set_cookies=cookies)
        target = Target.domain("test.com")
        p = SessionCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        assert any("short" in f.title.lower() for f in result.findings)


class TestSessionCheckNumericOnly:
    @pytest.mark.asyncio
    async def test_detects_numeric_only(self):
        """Purely numeric tokens have limited keyspace."""
        import random
        cookies = [
            [f"PHPSESSID={random.randint(100000, 999999)}; Path=/"]
            for _ in range(10)
        ]
        cookies.append([])
        ctx = _make_ctx(set_cookies=cookies)
        target = Target.domain("test.com")
        p = SessionCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        assert any("numeric" in f.title.lower() for f in result.findings)


class TestSessionCheckFixation:
    @pytest.mark.asyncio
    async def test_detects_fixation(self):
        """Session fixation: server accepts arbitrary session value."""
        # Normal collection phase
        cookies = [
            ["PHPSESSID=abc123def456ghi789; Path=/"]
            for _ in range(10)
        ]
        # Fixation test: server echoes back our fake session
        cookies.append(["PHPSESSID=BASILISK_FIXATION_TEST_000; Path=/"])
        ctx = _make_ctx(set_cookies=cookies)
        target = Target.domain("test.com")
        p = SessionCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        assert any("fixation" in f.title.lower() for f in result.findings)


class TestSessionCheckGoodTokens:
    @pytest.mark.asyncio
    async def test_good_tokens_no_high_findings(self):
        """Strong random tokens should not produce HIGH/CRITICAL findings."""
        import secrets
        cookies = [
            [f"PHPSESSID={secrets.token_hex(32)}; Path=/; HttpOnly; Secure"]
            for _ in range(10)
        ]
        # Fixation test: server does NOT echo our token (regenerates)
        cookies.append([f"PHPSESSID={secrets.token_hex(32)}; Path=/"])
        ctx = _make_ctx(set_cookies=cookies)
        target = Target.domain("test.com")
        p = SessionCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        # No HIGH or CRITICAL findings for properly generated tokens
        high_crit = [f for f in result.findings if f.severity.value >= 3]
        assert len(high_crit) == 0


class TestSessionCheckCapability:
    def test_capability_mapping(self):
        from basilisk.capabilities.mapping import CAPABILITY_MAP
        entry = CAPABILITY_MAP["session_check"]
        assert "Host" in entry["requires"]
        assert "Service:http" in entry["requires"]
