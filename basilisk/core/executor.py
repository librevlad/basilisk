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
    from basilisk.core.auth import AuthManager
    from basilisk.core.callback import CallbackServer
    from basilisk.core.exploit_chain import ExploitChainEngine
    from basilisk.core.plugin import BasePlugin
    from basilisk.core.providers import ProviderPool
    from basilisk.models.target import Target
    from basilisk.storage.repo import ResultRepository
    from basilisk.utils.browser import BrowserManager
    from basilisk.utils.diff import ResponseDiffer
    from basilisk.utils.dynamic_wordlist import DynamicWordlistGenerator
    from basilisk.utils.oob_verifier import NoopOobVerifier, OobVerifier
    from basilisk.utils.payloads import PayloadEngine
    from basilisk.utils.waf_bypass import WafBypassEngine


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
    auth: AuthManager | None = None
    browser: BrowserManager | None = None
    callback: CallbackServer | None = None
    differ: ResponseDiffer | None = None
    payloads: PayloadEngine | None = None
    waf_bypass: WafBypassEngine | None = None
    exploit_chain: ExploitChainEngine | None = None
    dynamic_wordlist: DynamicWordlistGenerator | None = None
    oob: OobVerifier | NoopOobVerifier | None = None
    log: logging.Logger = field(default_factory=lambda: logging.getLogger("basilisk"))
    pipeline: dict[str, PluginResult] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)
    emit: Callable[[Finding, str], None] = _noop_emit
    _deadline: float = 0.0
    _partial_result: PluginResult | None = None

    @property
    def time_remaining(self) -> float:
        """Seconds left before the plugin timeout deadline."""
        if self._deadline == 0.0:
            return float("inf")
        return max(0.0, self._deadline - time.monotonic())

    @property
    def should_stop(self) -> bool:
        """True when less than 2 s remain — plugins should return partial results."""
        return self._deadline > 0 and time.monotonic() >= self._deadline - 2.0


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
            ctx._deadline = start + plugin.meta.timeout
            ctx._partial_result = None
            try:
                result = await asyncio.wait_for(
                    plugin.run(target, ctx),
                    timeout=plugin.meta.timeout,
                )
                result.duration = time.monotonic() - start
                return result
            except TimeoutError:
                if ctx._partial_result is not None:
                    result = ctx._partial_result
                    result.status = "partial"
                    result.duration = time.monotonic() - start
                    result.error = f"Partial result (timed out after {plugin.meta.timeout}s)"
                    return result
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

    # Plugins that don't need HTTP — never skip for reachability
    _NON_HTTP_PLUGINS = frozenset({
        "dns_enum", "dns_zone_transfer", "whois", "port_scan", "ftp_anon",
        "dnssec_check", "email_spoofing", "asn_lookup", "service_detect",
        "service_brute", "ipv6_scan", "subdomain_bruteforce",
        "subdomain_crtsh", "subdomain_hackertarget", "subdomain_rapiddns",
        "subdomain_dnsdumpster", "subdomain_virustotal", "subdomain_alienvault",
        "subdomain_wayback", "reverse_ip",
    })

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

        # Skip unreachable HTTP hosts for HTTP-dependent plugins
        skipped_results: list[PluginResult] = []
        scheme_map = ctx.state.get("http_scheme", {})
        if scheme_map and plugin.meta.name not in self._NON_HTTP_PLUGINS:
            reachable = []
            for t in eligible:
                if t.host in scheme_map and scheme_map[t.host] is None:
                    skipped_results.append(PluginResult(
                        plugin=plugin.meta.name,
                        target=t.host,
                        status="skipped",
                        findings=[],
                        data={},
                    ))
                else:
                    reachable.append(t)
            eligible = reachable

        if not eligible:
            return skipped_results

        tasks = [self.run_one(plugin, t, ctx) for t in eligible]
        results = await asyncio.gather(*tasks)

        # Emit findings to TUI as they arrive + quality metrics
        all_results = skipped_results + list(results)
        for result in results:
            for finding in result.findings:
                ctx.emit(finding, result.target)

            # Quality metric: log warning if >50% of non-INFO findings lack evidence
            non_info = [f for f in result.findings if f.severity >= 2]
            if non_info:
                no_evidence = sum(1 for f in non_info if not f.evidence)
                if no_evidence > len(non_info) * 0.5:
                    logger.warning(
                        "Plugin %s on %s: %d/%d findings (MEDIUM+) lack evidence",
                        plugin.meta.name, result.target,
                        no_evidence, len(non_info),
                    )

        return all_results
