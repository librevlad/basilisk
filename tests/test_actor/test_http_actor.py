"""Tests for HTTP actor."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from basilisk.actor.http_actor import HttpActor


def _mock_http_client():
    """Create a mock AsyncHttpClient."""
    client = AsyncMock()
    resp = AsyncMock()
    resp.status = 200
    resp.headers = {"Content-Type": "text/html"}
    resp.url = "https://example.com/"
    resp.read = AsyncMock(return_value=b"<html>OK</html>")
    client.get = AsyncMock(return_value=resp)
    client.post = AsyncMock(return_value=resp)
    client.head = AsyncMock(return_value=resp)
    client.request = AsyncMock(return_value=resp)
    return client


class TestHttpActor:
    async def test_get(self):
        client = _mock_http_client()
        actor = HttpActor(client)
        resp = await actor.http_get("https://example.com/")
        assert resp.status == 200
        assert "OK" in resp.text
        client.get.assert_called_once()

    async def test_post(self):
        client = _mock_http_client()
        actor = HttpActor(client)
        resp = await actor.http_post("https://example.com/", data={"key": "val"})
        assert resp.status == 200
        client.post.assert_called_once()

    async def test_head(self):
        client = _mock_http_client()
        actor = HttpActor(client)
        resp = await actor.http_head("https://example.com/")
        assert resp.status == 200
        client.head.assert_called_once()

    async def test_request(self):
        client = _mock_http_client()
        actor = HttpActor(client)
        resp = await actor.http_request("PUT", "https://example.com/")
        assert resp.status == 200
        client.request.assert_called_once()

    async def test_rate_limiting(self):
        client = _mock_http_client()
        rate = MagicMock()
        rate.__aenter__ = AsyncMock()
        rate.__aexit__ = AsyncMock()
        actor = HttpActor(client, rate_limiter=rate)
        await actor.http_get("https://example.com/")
        rate.__aenter__.assert_called_once()

    async def test_no_rate_limiter(self):
        client = _mock_http_client()
        actor = HttpActor(client, rate_limiter=None)
        resp = await actor.http_get("https://example.com/")
        assert resp.status == 200

    def test_should_stop_no_deadline(self):
        client = _mock_http_client()
        actor = HttpActor(client, deadline=0.0)
        assert not actor.should_stop

    def test_time_remaining_no_deadline(self):
        client = _mock_http_client()
        actor = HttpActor(client, deadline=0.0)
        assert actor.time_remaining == float("inf")
