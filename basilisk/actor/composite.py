"""Composite actor — combines HTTP + DNS + Net into one interface."""

from __future__ import annotations

import copy
import time
from typing import TYPE_CHECKING, Any

from basilisk.actor.base import BaseActor, HttpResponse

if TYPE_CHECKING:
    from basilisk.config import Settings
    from basilisk.utils.browser import BrowserManager
    from basilisk.utils.dns import DnsClient
    from basilisk.utils.http import AsyncHttpClient
    from basilisk.utils.net import NetUtils
    from basilisk.utils.rate_limiter import RateLimiter


class CompositeActor(BaseActor):
    """Full actor combining HTTP, DNS, TCP, and Browser capabilities.

    Satisfies ActorProtocol and provides access to underlying clients
    for the bridge layer (context_adapter).
    """

    def __init__(
        self,
        http_client: AsyncHttpClient | None = None,
        dns_client: DnsClient | None = None,
        net_utils: NetUtils | None = None,
        rate_limiter: RateLimiter | None = None,
        browser: BrowserManager | None = None,
        deadline: float = 0.0,
    ):
        super().__init__(deadline)
        self.http_client = http_client
        self.dns_client = dns_client
        self.net_utils = net_utils
        self.rate_limiter = rate_limiter
        self.browser = browser

    @classmethod
    def build(cls, settings: Settings) -> CompositeActor:
        """Build a CompositeActor from Settings."""
        from basilisk.utils.dns import DnsClient
        from basilisk.utils.http import AsyncHttpClient
        from basilisk.utils.net import NetUtils
        from basilisk.utils.rate_limiter import RateLimiter

        http = AsyncHttpClient(
            timeout=settings.http.timeout,
            max_connections=settings.http.max_connections,
            max_per_host=settings.http.max_connections_per_host,
            user_agent=settings.http.user_agent,
            verify_ssl=settings.http.verify_ssl,
        )
        dns = DnsClient(
            nameservers=settings.dns.nameservers,
            timeout=settings.dns.timeout,
        )
        net = NetUtils(timeout=settings.scan.port_timeout)
        rate = RateLimiter(
            rate=settings.rate_limit.requests_per_second,
            burst=settings.rate_limit.burst,
        )
        return cls(
            http_client=http,
            dns_client=dns,
            net_utils=net,
            rate_limiter=rate,
        )

    async def close(self) -> None:
        """Cleanup all clients."""
        if self.http_client:
            await self.http_client.close()
        if self.browser:
            await self.browser.stop()

    def scoped(self, timeout: float) -> CompositeActor:
        """Create a shallow copy with a new deadline."""
        actor = copy.copy(self)
        actor._deadline = time.monotonic() + timeout
        return actor

    # -- HTTP methods --

    async def _rate_wait(self) -> None:
        if self.rate_limiter:
            async with self.rate_limiter:
                pass

    async def http_get(
        self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 0,
    ) -> HttpResponse:
        await self._rate_wait()
        start = time.monotonic()
        resp = await self.http_client.get(url, headers=headers)
        elapsed = time.monotonic() - start
        return await self._wrap(resp, elapsed)

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
        resp = await self.http_client.post(url, data=data, json=json, headers=headers)
        elapsed = time.monotonic() - start
        return await self._wrap(resp, elapsed)

    async def http_head(
        self, url: str, *, timeout: float = 0,
    ) -> HttpResponse:
        await self._rate_wait()
        start = time.monotonic()
        resp = await self.http_client.head(url)
        elapsed = time.monotonic() - start
        return await self._wrap(resp, elapsed)

    async def http_request(
        self, method: str, url: str, **kwargs: Any,
    ) -> HttpResponse:
        await self._rate_wait()
        start = time.monotonic()
        resp = await self.http_client.request(method, url, **kwargs)
        elapsed = time.monotonic() - start
        return await self._wrap(resp, elapsed)

    # -- DNS methods --

    async def dns_resolve(
        self, hostname: str, rdtype: str = "A",
    ) -> list[str]:
        if not self.dns_client:
            return []
        records = await self.dns_client.resolve(hostname, rdtype)
        return [str(r) for r in records]

    # -- TCP methods --

    async def tcp_connect(
        self, host: str, port: int, timeout: float = 3.0,
    ) -> bool:
        if not self.net_utils:
            return False
        result = await self.net_utils.check_port(host, port, timeout)
        return result.state.value == "open"

    async def tcp_banner(
        self, host: str, port: int, timeout: float = 3.0,
    ) -> str:
        if not self.net_utils:
            return ""
        return await self.net_utils.grab_banner(host, port, timeout)

    @staticmethod
    async def _wrap(resp: Any, elapsed: float) -> HttpResponse:
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
