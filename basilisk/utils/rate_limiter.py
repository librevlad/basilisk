"""Rate limiter — async token bucket using aiolimiter."""

from __future__ import annotations

from aiolimiter import AsyncLimiter


class RateLimiter:
    """Async rate limiter wrapping aiolimiter's token bucket.

    Usage:
        limiter = RateLimiter(100)  # 100 requests/sec
        async with limiter:
            await do_request()
    """

    def __init__(self, rate: float = 100.0, burst: int = 20):
        self._limiter = AsyncLimiter(rate, 1.0)
        self.rate = rate
        self.burst = burst

    async def acquire(self) -> None:
        await self._limiter.acquire()

    async def __aenter__(self) -> RateLimiter:
        await self.acquire()
        return self

    async def __aexit__(self, *_) -> None:
        pass
