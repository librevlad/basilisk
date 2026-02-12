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

    async def test_acquire_with_host(self):
        limiter = RateLimiter(rate=1000.0, per_host_rate=500.0)
        await limiter.acquire("example.com")  # Should not block

    async def test_per_host_limiter_created(self):
        limiter = RateLimiter(rate=1000.0, per_host_rate=500.0)
        await limiter.acquire("test.com")
        assert "test.com" in limiter._hosts

    async def test_host_context_manager(self):
        limiter = RateLimiter(rate=1000.0)
        async with limiter.host("example.com"):
            pass  # Should acquire both global and per-host

    async def test_host_context_creates_limiter(self):
        limiter = RateLimiter(rate=1000.0)
        async with limiter.host("new-host.com"):
            pass
        assert "new-host.com" in limiter._hosts

    async def test_multiple_hosts(self):
        limiter = RateLimiter(rate=1000.0)
        await limiter.acquire("a.com")
        await limiter.acquire("b.com")
        assert "a.com" in limiter._hosts
        assert "b.com" in limiter._hosts

    async def test_same_host_reuses_limiter(self):
        limiter = RateLimiter(rate=1000.0)
        await limiter.acquire("x.com")
        first = limiter._hosts["x.com"]
        await limiter.acquire("x.com")
        assert limiter._hosts["x.com"] is first

    async def test_context_manager_returns_self(self):
        limiter = RateLimiter(rate=1000.0)
        async with limiter as ctx:
            assert ctx is limiter
