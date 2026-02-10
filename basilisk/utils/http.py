"""Async HTTP client — shared connection pool, retries, rate limiting."""

from __future__ import annotations

import logging
import ssl
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


class AsyncHttpClient:
    """Shared async HTTP client with connection pooling.

    Usage:
        async with AsyncHttpClient() as http:
            resp = await http.get("https://example.com")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_connections: int = 100,
        max_per_host: int = 30,
        user_agent: str = "Basilisk/2.0",
        verify_ssl: bool = False,
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects

        ssl_ctx = None
        if not verify_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        self._connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=max_per_host,
            ssl=ssl_ctx,
        )
        self._session: aiohttp.ClientSession | None = None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                connector=self._connector,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            )
        return self._session

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        session = await self._ensure_session()
        kw: dict[str, Any] = {
            "allow_redirects": self.follow_redirects,
            "max_redirects": self.max_redirects,
            **kwargs,
        }
        if headers:
            kw["headers"] = headers
        if timeout:
            kw["timeout"] = aiohttp.ClientTimeout(total=timeout)
        return await session.get(url, **kw)

    async def head(
        self,
        url: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        session = await self._ensure_session()
        kw: dict[str, Any] = {
            "allow_redirects": self.follow_redirects,
            **kwargs,
        }
        if timeout:
            kw["timeout"] = aiohttp.ClientTimeout(total=timeout)
        return await session.head(url, **kw)

    async def fetch_text(self, url: str, **kwargs: Any) -> str | None:
        """Convenience: GET and return response body as text, or None on error."""
        try:
            resp = await self.get(url, **kwargs)
            async with resp:
                if resp.status == 200:
                    return await resp.text()
        except Exception as e:
            logger.debug("fetch_text failed for %s: %s", url, e)
        return None

    async def check_url(
        self, url: str, timeout: float = 5.0
    ) -> dict[str, Any]:
        """Quick URL check — returns status, headers, title."""
        result: dict[str, Any] = {"url": url, "status": 0, "error": None}
        try:
            resp = await self.get(url, timeout=timeout)
            async with resp:
                result["status"] = resp.status
                result["headers"] = dict(resp.headers)
                if resp.status == 200 and resp.content_type == "text/html":
                    text = await resp.text()
                    # Simple title extraction
                    start = text.lower().find("<title>")
                    if start != -1:
                        end = text.lower().find("</title>", start)
                        if end != -1:
                            result["title"] = text[start + 7 : end].strip()
        except Exception as e:
            result["error"] = str(e)
        return result

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> AsyncHttpClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
