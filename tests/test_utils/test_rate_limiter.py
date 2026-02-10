"""Tests for rate limiter."""



from basilisk.utils.rate_limiter import RateLimiter


class TestRateLimiter:
    async def test_basic_acquire(self):
        limiter = RateLimiter(rate=1000.0)
        await limiter.acquire()  # Should not block

    async def test_context_manager(self):
        limiter = RateLimiter(rate=1000.0)
        async with limiter:
            pass  # Should not raise

    async def test_attributes(self):
        limiter = RateLimiter(rate=50.0, burst=10)
        assert limiter.rate == 50.0
        assert limiter.burst == 10
