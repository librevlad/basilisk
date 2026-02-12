"""Batch URL checking — concurrent HEAD requests with deadline support."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


async def batch_head_check(
    http_client: Any,
    urls: list[str],
    rate_limiter: Any,
    concurrency: int = 10,
    timeout: float = 5.0,
    deadline: float = 0.0,
    valid_statuses: set[int] | None = None,
) -> list[tuple[str, int, int]]:
    """Concurrent URL existence check via HEAD requests.

    Returns list of (url, status_code, content_length) for matching responses.

    By default (valid_statuses=None) returns only status 200 with content_length > 0.
    When valid_statuses is provided, returns all URLs matching those status codes.

    Args:
        http_client: AsyncHttpClient instance.
        urls: URLs to check.
        rate_limiter: RateLimiter (supports ``async with``).
        concurrency: Max parallel requests.
        timeout: Per-request timeout in seconds.
        deadline: Monotonic deadline; stop early when reached (0 = no limit).
        valid_statuses: If set, accept these status codes (skip size filter).
    """
    sem = asyncio.Semaphore(concurrency)
    results: list[tuple[str, int, int]] = []
    lock = asyncio.Lock()

    async def _check_one(url: str) -> None:
        if deadline and time.monotonic() >= deadline - 1.0:
            return
        async with sem:
            try:
                async with rate_limiter:
                    resp = await http_client.head(url, timeout=timeout)
                    status = resp.status
                    cl = resp.headers.get("content-length", "0")
                    size = int(cl) if cl.isdigit() else 0
                    if valid_statuses is not None:
                        if status in valid_statuses:
                            async with lock:
                                results.append((url, status, size))
                    elif status == 200 and size > 0:
                        async with lock:
                            results.append((url, status, size))
            except Exception:
                pass

    tasks = [asyncio.create_task(_check_one(u)) for u in urls]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results
