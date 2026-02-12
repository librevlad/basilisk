"""Tests for batch_head_check — concurrent URL checking."""

import time
from unittest.mock import AsyncMock, MagicMock

from basilisk.utils.batch_check import batch_head_check


def _make_rate():
    rate = AsyncMock()
    rate.__aenter__ = AsyncMock(return_value=rate)
    rate.__aexit__ = AsyncMock(return_value=False)
    return rate


class TestBatchHeadCheck:
    async def test_default_200_with_size(self):
        """Default: only return status=200 with content-length > 0."""
        http = AsyncMock()
        resp = MagicMock()
        resp.status = 200
        resp.headers = {"content-length": "1234"}
        http.head = AsyncMock(return_value=resp)

        results = await batch_head_check(
            http, ["http://example.com/admin"], _make_rate(),
        )
        assert len(results) == 1
        assert results[0] == ("http://example.com/admin", 200, 1234)

    async def test_default_200_zero_size_excluded(self):
        """Status 200 but content-length=0 should be excluded."""
        http = AsyncMock()
        resp = MagicMock()
        resp.status = 200
        resp.headers = {"content-length": "0"}
        http.head = AsyncMock(return_value=resp)

        results = await batch_head_check(
            http, ["http://example.com/empty"], _make_rate(),
        )
        assert len(results) == 0

    async def test_default_404_excluded(self):
        http = AsyncMock()
        resp = MagicMock()
        resp.status = 404
        resp.headers = {"content-length": "100"}
        http.head = AsyncMock(return_value=resp)

        results = await batch_head_check(
            http, ["http://example.com/nope"], _make_rate(),
        )
        assert len(results) == 0

    async def test_custom_valid_statuses(self):
        """With valid_statuses, match by status code ignoring size."""
        http = AsyncMock()
        resp = MagicMock()
        resp.status = 403
        resp.headers = {}
        http.head = AsyncMock(return_value=resp)

        results = await batch_head_check(
            http, ["http://example.com/secret"], _make_rate(),
            valid_statuses={200, 403},
        )
        assert len(results) == 1
        assert results[0][1] == 403

    async def test_exception_handled(self):
        """Network errors should be silently ignored."""
        http = AsyncMock()
        http.head = AsyncMock(side_effect=ConnectionError("timeout"))

        results = await batch_head_check(
            http, ["http://example.com/fail"], _make_rate(),
        )
        assert len(results) == 0

    async def test_multiple_urls(self):
        http = AsyncMock()
        call_count = 0

        async def mock_head(url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status = 200
            resp.headers = {"content-length": "100"}
            return resp

        http.head = mock_head
        urls = [f"http://example.com/{i}" for i in range(5)]
        results = await batch_head_check(http, urls, _make_rate())
        assert len(results) == 5
        assert call_count == 5

    async def test_deadline_stops_early(self):
        """When deadline is in the past, checks should be skipped."""
        http = AsyncMock()
        resp = MagicMock()
        resp.status = 200
        resp.headers = {"content-length": "100"}
        http.head = AsyncMock(return_value=resp)

        # Deadline already passed
        results = await batch_head_check(
            http,
            ["http://example.com/a", "http://example.com/b"],
            _make_rate(),
            deadline=time.monotonic() - 10,
        )
        assert len(results) == 0

    async def test_non_digit_content_length(self):
        """Non-numeric content-length should default to 0."""
        http = AsyncMock()
        resp = MagicMock()
        resp.status = 200
        resp.headers = {"content-length": "unknown"}
        http.head = AsyncMock(return_value=resp)

        results = await batch_head_check(
            http, ["http://example.com/weird"], _make_rate(),
        )
        # size=0, so default filter excludes it
        assert len(results) == 0
