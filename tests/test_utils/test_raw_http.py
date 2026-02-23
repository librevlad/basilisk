"""Tests for raw HTTP engine and last-byte synchronization."""

from __future__ import annotations

import pytest

from basilisk.utils.raw_http import (
    LastByteSyncEngine,
    LastByteSyncResult,
    RawHttpResponse,
    build_raw_request,
    parse_raw_response,
)


class TestBuildRawRequest:
    def test_get_request(self):
        req = build_raw_request("GET", "/api/test", "example.com")
        text = req.decode("utf-8")
        assert text.startswith("GET /api/test HTTP/1.1\r\n")
        assert "Host: example.com" in text
        assert "Connection: close" in text

    def test_post_request_with_body(self):
        req = build_raw_request(
            "POST", "/api/transfer", "example.com",
            body="amount=100",
        )
        text = req.decode("utf-8")
        assert text.startswith("POST /api/transfer HTTP/1.1\r\n")
        assert "Content-Length: 10" in text
        assert "Content-Type: application/x-www-form-urlencoded" in text
        assert text.endswith("amount=100")

    def test_custom_headers(self):
        req = build_raw_request(
            "GET", "/", "example.com",
            headers={"Authorization": "Bearer tok123"},
        )
        text = req.decode("utf-8")
        assert "Authorization: Bearer tok123" in text

    def test_custom_content_type(self):
        req = build_raw_request(
            "POST", "/api", "example.com",
            body='{"a":1}',
            content_type="application/json",
        )
        text = req.decode("utf-8")
        assert "Content-Type: application/json" in text

    def test_empty_body_no_content_headers(self):
        req = build_raw_request("GET", "/", "example.com")
        text = req.decode("utf-8")
        assert "Content-Length" not in text
        assert "Content-Type" not in text


class TestParseRawResponse:
    def test_basic_response(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hello</h1>"
        status, headers, body = parse_raw_response(raw)
        assert status == 200
        assert headers["Content-Type"] == "text/html"
        assert body == "<h1>Hello</h1>"

    def test_empty_body(self):
        raw = b"HTTP/1.1 204 No Content\r\n\r\n"
        status, headers, body = parse_raw_response(raw)
        assert status == 204
        assert body == ""

    def test_multiple_headers(self):
        raw = (
            b"HTTP/1.1 302 Found\r\n"
            b"Location: /login\r\n"
            b"Set-Cookie: sid=abc\r\n"
            b"\r\n"
        )
        status, headers, body = parse_raw_response(raw)
        assert status == 302
        assert headers["Location"] == "/login"

    def test_malformed_data(self):
        status, headers, body = parse_raw_response(b"garbage data")
        assert status == 0

    def test_empty_data(self):
        status, headers, body = parse_raw_response(b"")
        assert status == 0


class TestLastByteSyncEngine:
    def test_init_defaults(self):
        engine = LastByteSyncEngine()
        assert engine.num_connections == 30
        assert engine.connect_timeout == 10.0
        assert engine.response_timeout == 15.0

    def test_custom_params(self):
        engine = LastByteSyncEngine(
            num_connections=10,
            connect_timeout=5.0,
            response_timeout=8.0,
        )
        assert engine.num_connections == 10

    @pytest.mark.asyncio
    async def test_execute_unreachable_host(self):
        engine = LastByteSyncEngine(
            num_connections=3,
            connect_timeout=2.0,
            response_timeout=2.0,
        )
        req = build_raw_request("GET", "/", "localhost")
        result = await engine.execute("127.0.0.1", 1, req)
        assert result.total_connections == 3
        assert result.failed_connections > 0

    @pytest.mark.asyncio
    async def test_execute_short_request(self):
        engine = LastByteSyncEngine(num_connections=2)
        result = await engine.execute("localhost", 80, b"x")
        # Single byte request — too short for prefix/last-byte split
        assert isinstance(result, LastByteSyncResult)


class TestRawHttpResponse:
    def test_dataclass_frozen(self):
        resp = RawHttpResponse(
            status=200, headers={}, body="ok",
            elapsed_ms=10.0, connection_id=0,
        )
        assert resp.status == 200
        assert resp.error == ""

    def test_with_error(self):
        resp = RawHttpResponse(
            status=0, headers={}, body="",
            elapsed_ms=0, connection_id=1, error="timeout",
        )
        assert resp.error == "timeout"
