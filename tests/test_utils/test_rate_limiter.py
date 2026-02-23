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

    async def test_lru_eviction(self):
        """Per-host limiters are evicted when max_hosts exceeded."""
        limiter = RateLimiter(rate=1000.0, max_hosts=3)
        await limiter.acquire("a.com")
        await limiter.acquire("b.com")
        await limiter.acquire("c.com")
        assert len(limiter._hosts) == 3

        # Adding 4th host should evict "a.com" (LRU)
        await limiter.acquire("d.com")
        assert len(limiter._hosts) == 3
        assert "a.com" not in limiter._hosts
        assert "d.com" in limiter._hosts

    async def test_lru_access_refreshes(self):
        """Accessing a host moves it to end, preventing eviction."""
        limiter = RateLimiter(rate=1000.0, max_hosts=3)
        await limiter.acquire("a.com")
        await limiter.acquire("b.com")
        await limiter.acquire("c.com")

        # Re-access "a.com" to refresh it
        await limiter.acquire("a.com")

        # Now "b.com" is LRU, should be evicted
        await limiter.acquire("d.com")
        assert "a.com" in limiter._hosts
        assert "b.com" not in limiter._hosts
