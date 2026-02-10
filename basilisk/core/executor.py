"""Async executor + PluginContext (DI container)."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from basilisk.models.result import Finding, PluginResult

if TYPE_CHECKING:
    from basilisk.config import Settings
    from basilisk.core.plugin import BasePlugin
    from basilisk.core.providers import ProviderPool
    from basilisk.models.target import Target
    from basilisk.storage.repo import ResultRepository


logger = logging.getLogger(__name__)


def _noop_emit(_finding: Finding, _target: str = "") -> None:
    pass


@dataclass
class PluginContext:
    """Dependency injection container passed to every plugin.

    Like Laravel's Service Container — shared resources, no globals.
    """

    config: Settings
    http: Any = None         # AsyncHttpClient (set after utils phase)
    dns: Any = None          # DnsClient
    net: Any = None          # NetUtils
    rate: Any = None         # RateLimiter
    db: ResultRepository | None = None
    wordlists: Any = None    # WordlistManager
    providers: ProviderPool | None = None
    log: logging.Logger = field(default_factory=lambda: logging.getLogger("basilisk"))
    pipeline: dict[str, PluginResult] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)
    emit: Callable[[Finding, str], None] = _noop_emit


class AsyncExecutor:
    """Runs plugins concurrently across targets with controlled parallelism."""

    def __init__(self, max_concurrency: int = 50):
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def run_one(
        self,
        plugin: BasePlugin,
        target: Target,
        ctx: PluginContext,
    ) -> PluginResult:
        """Run a single plugin against a single target, with timeout."""
        async with self.semaphore:
            start = time.monotonic()
            try:
                result = await asyncio.wait_for(
                    plugin.run(target, ctx),
                    timeout=plugin.meta.timeout,
                )
                result.duration = time.monotonic() - start
                return result
            except TimeoutError:
                return PluginResult(
                    plugin=plugin.meta.name,
                    target=target.host,
                    status="timeout",
                    duration=time.monotonic() - start,
                    error=f"Timed out after {plugin.meta.timeout}s",
                )
            except Exception as e:
                logger.exception("Plugin %s failed on %s", plugin.meta.name, target.host)
                return PluginResult(
                    plugin=plugin.meta.name,
                    target=target.host,
                    status="error",
                    duration=time.monotonic() - start,
                    error=str(e),
                )

    async def run_batch(
        self,
        plugin: BasePlugin,
        targets: list[Target],
        ctx: PluginContext,
    ) -> list[PluginResult]:
        """Run a plugin across multiple targets concurrently."""
        eligible = [t for t in targets if plugin.accepts(t)]
        if not eligible:
            return []

        tasks = [self.run_one(plugin, t, ctx) for t in eligible]
        results = await asyncio.gather(*tasks)

        # Emit findings to TUI as they arrive
        for result in results:
            for finding in result.findings:
                ctx.emit(finding, result.target)

        return list(results)
