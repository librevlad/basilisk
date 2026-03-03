"""Tests for composite actor."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from basilisk.actor.composite import CompositeActor


def _mock_composite():
    """Build a CompositeActor with mocked clients."""
    http = AsyncMock()
    resp = AsyncMock()
    resp.status = 200
    resp.headers = {"Content-Type": "text/html"}
    resp.url = "https://example.com/"
    resp.read = AsyncMock(return_value=b"OK")
    http.get = AsyncMock(return_value=resp)
    http.post = AsyncMock(return_value=resp)
    http.head = AsyncMock(return_value=resp)
    http.request = AsyncMock(return_value=resp)
    http.close = AsyncMock()

    dns = AsyncMock()
    dns.resolve = AsyncMock(return_value=["1.2.3.4"])

    net = AsyncMock()
    port_result = MagicMock()
    port_result.state.value = "open"
    net.check_port = AsyncMock(return_value=port_result)
    net.grab_banner = AsyncMock(return_value="SSH-2.0-OpenSSH")

    return CompositeActor(
        http_client=http, dns_client=dns, net_utils=net,
    )


class TestCompositeActor:
    async def test_http_get(self):
        actor = _mock_composite()
        resp = await actor.http_get("https://example.com/")
        assert resp.status == 200

    async def test_dns_resolve(self):
        actor = _mock_composite()
        records = await actor.dns_resolve("example.com")
        assert "1.2.3.4" in records

    async def test_tcp_connect(self):
        actor = _mock_composite()
        assert await actor.tcp_connect("example.com", 22)

    async def test_tcp_banner(self):
        actor = _mock_composite()
        banner = await actor.tcp_banner("example.com", 22)
        assert "SSH" in banner

    async def test_close(self):
        actor = _mock_composite()
        await actor.close()
        actor.http_client.close.assert_called_once()

    def test_scoped(self):
        actor = _mock_composite()
        scoped = actor.scoped(30.0)
        assert scoped.http_client is actor.http_client  # shared
        assert scoped._deadline > 0
        assert scoped.time_remaining <= 30.0


class TestCompositeActorNullSafety:
    async def test_http_get_no_client(self):
        actor = CompositeActor()
        resp = await actor.http_get("https://example.com/")
        assert resp.status == 0
        assert resp.url == "https://example.com/"

    async def test_http_post_no_client(self):
        actor = CompositeActor()
        resp = await actor.http_post("https://example.com/", data={"a": "1"})
        assert resp.status == 0

    async def test_http_head_no_client(self):
        actor = CompositeActor()
        resp = await actor.http_head("https://example.com/")
        assert resp.status == 0

    async def test_http_request_no_client(self):
        actor = CompositeActor()
        resp = await actor.http_request("PUT", "https://example.com/")
        assert resp.status == 0

    async def test_dns_no_client(self):
        actor = CompositeActor()
        records = await actor.dns_resolve("example.com")
        assert records == []

    async def test_tcp_connect_no_client(self):
        actor = CompositeActor()
        assert await actor.tcp_connect("example.com", 80) is False

    async def test_tcp_banner_no_client(self):
        actor = CompositeActor()
        assert await actor.tcp_banner("example.com", 80) == ""


class TestCompositeActorTimeoutPropagation:
    async def test_http_get_passes_timeout(self):
        actor = _mock_composite()
        await actor.http_get("https://example.com/", timeout=5.0)
        actor.http_client.get.assert_called_once_with(
            "https://example.com/", headers=None, timeout=5.0,
        )

    async def test_http_get_zero_timeout_passes_none(self):
        actor = _mock_composite()
        await actor.http_get("https://example.com/")
        actor.http_client.get.assert_called_once_with(
            "https://example.com/", headers=None, timeout=None,
        )

    async def test_http_post_passes_timeout(self):
        actor = _mock_composite()
        await actor.http_post("https://example.com/", data={"a": "1"}, timeout=8.0)
        actor.http_client.post.assert_called_once_with(
            "https://example.com/", data={"a": "1"}, json=None,
            headers=None, timeout=8.0,
        )

    async def test_http_head_passes_timeout(self):
        actor = _mock_composite()
        await actor.http_head("https://example.com/", timeout=3.0)
        actor.http_client.head.assert_called_once_with(
            "https://example.com/", timeout=3.0,
        )
