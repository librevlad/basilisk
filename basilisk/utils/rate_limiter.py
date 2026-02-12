"""Rate limiter — compound global + per-host token bucket using aiolimiter."""

from __future__ import annotations

from aiolimiter import AsyncLimiter


class RateLimiter:
    """Compound async rate limiter: global + per-host buckets.

    Global bucket prevents overwhelming the network adapter.
    Per-host bucket prevents target ban / WAF escalation.

    Usage (simple — global only):
        async with limiter:
            await do_request()

    Usage (per-host):
        async with limiter.host(hostname):
            await do_request()
    """

    def __init__(
        self,
        rate: float = 200.0,
        burst: int = 40,
        per_host_rate: float = 30.0,
        per_host_burst: int = 10,
    ):
        self._global = AsyncLimiter(rate, 1.0)
        self.rate = rate
        self.burst = burst
        self._per_host_rate = per_host_rate
        self._per_host_burst = per_host_burst
        self._hosts: dict[str, AsyncLimiter] = {}

    def _get_host_limiter(self, host: str) -> AsyncLimiter:
        if host not in self._hosts:
            self._hosts[host] = AsyncLimiter(self._per_host_rate, 1.0)
        return self._hosts[host]

    async def acquire(self, host: str | None = None) -> None:
        """Acquire a token from global (and optionally per-host) bucket."""
        if host:
            host_limiter = self._get_host_limiter(host)
            await host_limiter.acquire()
        await self._global.acquire()

    def host(self, hostname: str) -> _HostRateContext:
        """Return an async context manager that acquires both global + per-host."""
        return _HostRateContext(self, hostname)

    async def __aenter__(self) -> RateLimiter:
        await self._global.acquire()
        return self

    async def __aexit__(self, *_) -> None:
        pass


class _HostRateContext:
    """Async context manager for compound global + per-host rate limiting."""

    __slots__ = ("_limiter", "_host")

    def __init__(self, limiter: RateLimiter, host: str):
        self._limiter = limiter
        self._host = host

    async def __aenter__(self) -> _HostRateContext:
        await self._limiter.acquire(self._host)
        return self

    async def __aexit__(self, *_) -> None:
        pass
