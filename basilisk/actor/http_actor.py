"""HTTP actor — wraps AsyncHttpClient + RateLimiter."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from basilisk.actor.base import BaseActor, HttpResponse

if TYPE_CHECKING:
    from basilisk.utils.http import AsyncHttpClient
    from basilisk.utils.rate_limiter import RateLimiter


class HttpActor(BaseActor):
    """Actor that handles HTTP requests with rate limiting."""

    def __init__(
        self,
        http_client: AsyncHttpClient,
        rate_limiter: RateLimiter | None = None,
        deadline: float = 0.0,
    ):
        super().__init__(deadline)
        self._http = http_client
        self._rate = rate_limiter

    async def _rate_wait(self) -> None:
        if self._rate:
            async with self._rate:
                pass

    async def http_get(
        self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 0,
    ) -> HttpResponse:
        await self._rate_wait()
        start = time.monotonic()
        resp = await self._http.get(url, headers=headers)
        elapsed = time.monotonic() - start
        return await self._wrap_response(resp, elapsed)

    async def http_post(
        self,
        url: str,
        *,
        data: dict | bytes | str | None = None,
        json: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 0,
    ) -> HttpResponse:
        await self._rate_wait()
        start = time.monotonic()
        resp = await self._http.post(url, data=data, json=json, headers=headers)
        elapsed = time.monotonic() - start
        return await self._wrap_response(resp, elapsed)

    async def http_head(
        self, url: str, *, timeout: float = 0,
    ) -> HttpResponse:
        await self._rate_wait()
        start = time.monotonic()
        resp = await self._http.head(url)
        elapsed = time.monotonic() - start
        return await self._wrap_response(resp, elapsed)

    async def http_request(
        self, method: str, url: str, **kwargs: Any,
    ) -> HttpResponse:
        await self._rate_wait()
        start = time.monotonic()
        resp = await self._http.request(method, url, **kwargs)
        elapsed = time.monotonic() - start
        return await self._wrap_response(resp, elapsed)

    @staticmethod
    async def _wrap_response(resp: Any, elapsed: float) -> HttpResponse:
        """Convert aiohttp response to HttpResponse."""
        try:
            body = await resp.read()
            text = body.decode("utf-8", errors="replace")
        except Exception:
            body = b""
            text = ""
        return HttpResponse(
            status=resp.status,
            headers=dict(resp.headers) if hasattr(resp, "headers") else {},
            body=body,
            text=text,
            url=str(resp.url) if hasattr(resp, "url") else "",
            elapsed=elapsed,
        )
