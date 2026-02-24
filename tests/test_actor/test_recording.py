"""Tests for recording actor."""

from __future__ import annotations

from basilisk.actor.base import HttpResponse
from basilisk.actor.recording import RecordingActor


class TestRecordingActor:
    async def test_record_get(self):
        actor = RecordingActor()
        resp = await actor.http_get("https://example.com/")
        assert resp.status == 200
        assert len(actor.requests) == 1
        assert actor.requests[0].method == "GET"

    async def test_canned_response(self):
        actor = RecordingActor()
        actor.set_response("https://example.com/login", HttpResponse(
            status=302, text="Redirect",
        ))
        resp = await actor.http_get("https://example.com/login")
        assert resp.status == 302

    async def test_dns_resolve(self):
        actor = RecordingActor()
        actor.set_dns("example.com", ["1.2.3.4", "5.6.7.8"])
        records = await actor.dns_resolve("example.com")
        assert len(records) == 2

    async def test_tcp_connect(self):
        actor = RecordingActor()
        actor.set_tcp("example.com", 22, True)
        assert await actor.tcp_connect("example.com", 22)
        assert not await actor.tcp_connect("example.com", 23)
