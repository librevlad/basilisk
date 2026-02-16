"""Pipeline — orchestration of plugin execution in phases."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from basilisk.core.executor import AsyncExecutor, PluginContext
from basilisk.core.plugin import BasePlugin
from basilisk.core.registry import PluginRegistry
from basilisk.models.result import PluginResult
from basilisk.models.target import Target, TargetScope

if TYPE_CHECKING:
    from basilisk.storage.cache import ResultCache

logger = logging.getLogger(__name__)

DEFAULT_PHASES = ["recon", "scanning", "analysis", "pentesting"]

OFFENSIVE_PHASES = [
    "recon", "scanning", "analysis", "pentesting",
    "exploitation", "post_exploit", "privesc", "lateral",
]


@dataclass
class PhaseProgress:
    """Progress tracking for a single phase."""

    phase: str
    total: int = 0
    completed: int = 0
    status: str = "waiting"  # waiting, running, done
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def elapsed(self) -> float:
        if self.started_at == 0:
            return 0.0
        end = self.finished_at if self.finished_at else time.monotonic()
        return end - self.started_at

    @property
    def progress_pct(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.completed / self.total) * 100.0


@dataclass
class PipelineState:
    """Full pipeline state — for TUI dashboard."""

    phases: dict[str, PhaseProgress] = field(default_factory=dict)
    results: list[PluginResult] = field(default_factory=list)
    total_findings: int = 0
    status: str = "idle"  # idle, running, completed, failed

    def init_phases(self, categories: list[str]) -> None:
        for cat in categories:
            self.phases[cat] = PhaseProgress(phase=cat)


OnProgressCallback = Callable[[PipelineState], None]


def _noop_progress(_state: PipelineState) -> None:
    pass


class Pipeline:
    """Orchestrates plugin execution in topologically sorted order.

    The pipeline flows: recon → scanning → analysis → pentesting.
    Recon plugins expand the target scope (new subdomains).
    Supports resume via completed_pairs — already-done (plugin, host) combos.
    """

    def __init__(
        self,
        registry: PluginRegistry,
        executor: AsyncExecutor,
        ctx: PluginContext,
        on_progress: OnProgressCallback = _noop_progress,
        completed_pairs: set[tuple[str, str]] | None = None,
        cache: ResultCache | None = None,
        cache_ttl: dict[str, float] | None = None,
        force_phases: set[str] | None = None,
    ):
        self.registry = registry
        self.executor = executor
        self.ctx = ctx
        self.on_progress = on_progress
        self.state = PipelineState()
        self.completed_pairs = completed_pairs or set()
        self.cache = cache
        self.cache_ttl = cache_ttl or {}
        self.force_phases = force_phases or set()

    async def run(
        self,
        scope: TargetScope,
        plugin_names: list[str] | None = None,
        phases: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
    ) -> PipelineState:
        """Run the full audit pipeline."""
        active_phases = phases or DEFAULT_PHASES
        self.state.init_phases(active_phases)
        self.state.status = "running"
        self.on_progress(self.state)

        # Run auth phase if auth manager is configured
        if self.ctx.auth:
            await self._run_auth_phase(scope)

        # Resolve execution order
        ordered = self.registry.resolve_order(plugin_names)

        # Apply exclude patterns (name match or prefix match)
        if exclude_patterns:
            def _excluded(name: str) -> bool:
                return any(
                    name == pat or name.startswith(pat)
                    for pat in exclude_patterns
                )
            before = len(ordered)
            ordered = [p for p in ordered if not _excluded(p.meta.name)]
            logger.info(
                "Excluded %d plugins via patterns: %s",
                before - len(ordered), exclude_patterns,
            )

        # Group by category
        by_phase: dict[str, list[type[BasePlugin]]] = {p: [] for p in active_phases}
        for plugin_cls in ordered:
            cat = plugin_cls.meta.category
            if cat in by_phase:
                by_phase[cat].append(plugin_cls)

        # Execute phases sequentially
        for phase_name in active_phases:
            plugins = by_phase.get(phase_name, [])
            if not plugins:
                self.state.phases[phase_name].status = "done"
                continue

            phase = self.state.phases[phase_name]
            phase.status = "running"
            phase.started_at = time.monotonic()
            phase.total = 0  # computed incrementally per plugin
            self.on_progress(self.state)

            for plugin_cls in plugins:
                scope_size = len(scope)
                phase.total += scope_size

                # Skip plugins with unmet capability requirements
                if self._should_skip_plugin(plugin_cls):
                    phase.completed += scope_size
                    self.on_progress(self.state)
                    continue

                plugin = plugin_cls()
                await plugin.setup(self.ctx)

                all_targets = list(scope)

                # Skip already completed targets (resume support)
                if self.completed_pairs:
                    targets = [
                        t for t in all_targets
                        if (plugin.meta.name, t.host) not in self.completed_pairs
                    ]
                else:
                    targets = all_targets

                # Try cache for remaining targets (unless phase is forced)
                cache_hits: list[PluginResult] = []
                if self.cache and phase_name not in self.force_phases:
                    ttl = self._get_cache_ttl(phase_name)
                    targets, cache_hits = await self._check_cache(
                        plugin.meta.name, targets, ttl,
                    )

                skipped_count = scope_size - len(targets) - len(cache_hits)

                # Inject cache hits into pipeline context
                for cached in cache_hits:
                    key = f"{cached.plugin}:{cached.target}"
                    self.ctx.pipeline[key] = cached
                    self.state.results.append(cached)
                    self.state.total_findings += len(cached.findings)

                    if phase_name == "recon" and cached.ok:
                        new_subs = cached.data.get("subdomains", [])
                        for sub in new_subs:
                            scope.add(
                                Target.subdomain(sub, parent=cached.target)
                            )

                if not targets:
                    phase.completed += scope_size
                    self.on_progress(self.state)
                    await plugin.teardown()
                    continue

                results = await self.executor.run_batch(
                    plugin, targets, self.ctx
                )

                for result in results:
                    # Store in pipeline context for downstream plugins
                    key = f"{result.plugin}:{result.target}"
                    self.ctx.pipeline[key] = result
                    self.state.results.append(result)
                    self.state.total_findings += len(result.findings)

                    # Incremental persist to DB
                    await self._persist_one(result)

                    # Write to cache
                    await self._cache_put(result)

                    # Recon plugins can expand scope
                    if phase_name == "recon" and result.ok:
                        new_subs = result.data.get("subdomains", [])
                        for sub in new_subs:
                            scope.add(
                                Target.subdomain(sub, parent=result.target)
                            )

                phase.completed += len(results) + skipped_count + len(cache_hits)
                self.on_progress(self.state)

                await plugin.teardown()

            phase.finished_at = time.monotonic()
            phase.status = "done"
            self.on_progress(self.state)

            # Quality gate: warn if >50% of non-INFO findings lack evidence
            self._check_quality_gate(phase_name)

            # Pipeline intelligence: inject context for downstream phases
            if phase_name == "recon":
                self._inject_crawl_data(scope)
                await self._check_http_reachability(scope)
            elif phase_name == "analysis":
                self._inject_waf_data(scope)
                self._inject_api_paths(scope)
            elif phase_name == "exploitation":
                self._inject_exploitation_data()
            elif phase_name == "post_exploit":
                self._inject_post_exploit_data()
            elif phase_name == "privesc":
                self._inject_privesc_data()

        self.state.status = "completed"
        self.on_progress(self.state)
        return self.state

    async def _check_http_reachability(self, scope: TargetScope) -> None:
        """Quick HEAD check on all targets to cache HTTP scheme.

        Stores {host: "https"|"http"|None} in ctx.state["http_scheme"].
        Unreachable hosts are skipped by executor in later phases.
        """
        if self.ctx.http is None:
            return

        scheme_map: dict[str, str | None] = {}
        sem = asyncio.Semaphore(30)

        async def check_one(host: str) -> None:
            async with sem:
                for scheme in ("https", "http"):
                    for method in ("head", "get"):
                        try:
                            fn = getattr(self.ctx.http, method)
                            await asyncio.wait_for(
                                fn(f"{scheme}://{host}/"),
                                timeout=7.0,
                            )
                            scheme_map[host] = scheme
                            return
                        except Exception as e:
                            logger.debug(
                                "HTTP check %s://%s (%s) failed: %s",
                                scheme, host, method, e,
                            )
                            continue
                scheme_map[host] = None

        hosts = list({t.host for t in scope})
        await asyncio.gather(*[check_one(h) for h in hosts])
        self.ctx.state["http_scheme"] = scheme_map

        reachable = sum(1 for v in scheme_map.values() if v is not None)
        logger.info(
            "HTTP reachability: %d/%d hosts reachable", reachable, len(scheme_map),
        )

    def _inject_waf_data(self, scope: TargetScope) -> None:
        """After analysis phase, populate waf_map in state for pentesting plugins."""
        waf_map: dict[str, list[str]] = {}
        for t in scope:
            waf_key = f"waf_detect:{t.host}"
            waf_result = self.ctx.pipeline.get(waf_key)
            if waf_result and waf_result.ok:
                waf_list = waf_result.data.get("waf", [])
                if waf_list:
                    waf_map[t.host] = waf_list
        if waf_map:
            self.ctx.state["waf_map"] = waf_map

    def _inject_api_paths(self, scope: TargetScope) -> None:
        """After analysis phase, collect API paths from js_api_extract and api_detect."""
        api_paths: dict[str, list[str]] = {}
        for t in scope:
            paths: list[str] = []
            for key_prefix in ("js_api_extract", "api_detect"):
                key = f"{key_prefix}:{t.host}"
                result = self.ctx.pipeline.get(key)
                if result and result.ok:
                    paths.extend(result.data.get("api_paths", []))
                    paths.extend(result.data.get("interesting_paths", []))
            if paths:
                api_paths[t.host] = list(dict.fromkeys(paths))
        if api_paths:
            self.ctx.state["discovered_api_paths"] = api_paths

    def _inject_crawl_data(self, scope: TargetScope) -> None:
        """After recon phase, populate crawled_urls and forms in state."""
        crawled_urls: dict[str, list[str]] = {}
        discovered_forms: dict[str, list[dict]] = {}
        for t in scope:
            key = f"web_crawler:{t.host}"
            result = self.ctx.pipeline.get(key)
            if result and result.ok:
                crawled_urls[t.host] = result.data.get("crawled_urls", [])
                discovered_forms[t.host] = result.data.get("forms", [])

        # Merge config scan_paths into crawled_urls
        scan_paths = self.ctx.config.scan.scan_paths
        if scan_paths:
            for t in scope:
                scheme_map = self.ctx.state.get("http_scheme", {})
                scheme = scheme_map.get(t.host, "http")
                if scheme is None:
                    continue
                base = f"{scheme}://{t.host}"
                existing = set(crawled_urls.get(t.host, []))
                host_urls = list(crawled_urls.get(t.host, []))
                for sp in scan_paths:
                    if not sp.startswith("/"):
                        sp = f"/{sp}"
                    full = f"{base}{sp}"
                    if full not in existing:
                        host_urls.append(full)
                        existing.add(full)
                crawled_urls[t.host] = host_urls

        if crawled_urls:
            self.ctx.state["crawled_urls"] = crawled_urls
            for host, urls in crawled_urls.items():
                logger.info(
                    "Injected %d crawled URLs for %s (with params: %d)",
                    len(urls), host,
                    sum(1 for u in urls if "?" in u),
                )
        if discovered_forms:
            self.ctx.state["discovered_forms"] = discovered_forms
            for host, forms in discovered_forms.items():
                logger.info("Injected %d forms for %s", len(forms), host)

    def _should_skip_plugin(self, plugin_cls: type[BasePlugin]) -> bool:
        """Check if plugin should be skipped due to unmet requirements."""
        meta = plugin_cls.meta
        if meta.requires_auth and not (
            self.ctx.auth and self.ctx.auth.authenticated_hosts
        ):
            logger.debug("Skipping %s: requires auth", meta.name)
            return True
        if meta.requires_browser and not (
            self.ctx.browser and self.ctx.browser.available
        ):
            logger.debug("Skipping %s: requires browser", meta.name)
            return True
        if meta.requires_callback and self.ctx.callback is None:
            logger.debug("Skipping %s: requires callback server", meta.name)
            return True
        if meta.requires_shell and not self.ctx.state.get("active_shells"):
            logger.debug("Skipping %s: requires shell session", meta.name)
            return True
        if meta.requires_credentials and not self.ctx.state.get("credentials"):
            logger.debug("Skipping %s: requires credentials", meta.name)
            return True
        return False

    async def _run_auth_phase(self, scope: TargetScope) -> None:
        """Authenticate to all targets using the configured auth manager."""
        if not self.ctx.auth:
            return
        logger.info("Running auth phase for %d targets", len(scope))
        for target in scope:
            try:
                session = await self.ctx.auth.login(target.host, self.ctx)
                if session.is_authenticated:
                    logger.info("Authenticated to %s", target.host)
                    # Resolve scheme: use cached value, or probe fresh
                    scheme = self.ctx.state.get("http_scheme", {}).get(
                        target.host
                    )
                    if not scheme:
                        scheme = await self._probe_scheme(target.host)
                        self.ctx.state.setdefault("http_scheme", {})[
                            target.host
                        ] = scheme
                    base = f"{scheme}://{target.host}"
                    # Inject auth cookies into HTTP session so ALL plugins
                    # send them automatically via ctx.http
                    if self.ctx.http and session.cookies:
                        await self.ctx.http.set_cookies(base, session.cookies)
                        logger.info(
                            "Injected %d auth cookies for %s",
                            len(session.cookies), target.host,
                        )
                    # Inject extra_cookies from config (e.g. security=low for DVWA)
                    extra = self.ctx.config.auth.extra_cookies
                    if self.ctx.http and extra:
                        session.cookies.update(extra)
                        await self.ctx.http.set_cookies(base, extra)
                        logger.info(
                            "Injected %d extra cookies for %s",
                            len(extra), target.host,
                        )
                else:
                    logger.warning("Auth failed for %s", target.host)
            except Exception:
                logger.warning("Auth error for %s", target.host, exc_info=True)

    async def _probe_scheme(self, host: str) -> str:
        """Quick probe to determine if host uses HTTPS or HTTP."""
        if self.ctx.http is None:
            return "http"
        for scheme in ("https", "http"):
            try:
                await asyncio.wait_for(
                    self.ctx.http.head(f"{scheme}://{host}/"),
                    timeout=5.0,
                )
                return scheme
            except Exception:
                continue
        return "http"

    def _check_quality_gate(self, phase_name: str) -> None:
        """Warn if too many findings in this phase lack evidence."""
        phase_results = [
            r for r in self.state.results
            if r.plugin in {
                p.meta.name for p in self.registry.all()
                if p.meta.category == phase_name
            }
        ]
        non_info = [
            f for r in phase_results for f in r.findings
            if f.severity.value >= 2
        ]
        if non_info:
            no_evidence = sum(1 for f in non_info if not f.evidence)
            pct = no_evidence / len(non_info)
            if pct > 0.5:
                logger.warning(
                    "Quality gate [%s]: %d/%d (%.0f%%) MEDIUM+ findings lack evidence",
                    phase_name, no_evidence, len(non_info), pct * 100,
                )

    def _inject_exploitation_data(self) -> None:
        """After exploitation phase, collect shells and access into ctx.state."""
        shells: list[dict] = []
        for result in self.state.results:
            if result.ok and result.data.get("shell_session"):
                shells.append(result.data["shell_session"])
            if result.ok and result.data.get("credentials"):
                creds = self.ctx.state.setdefault("credentials", [])
                creds.extend(result.data["credentials"])
        if shells:
            self.ctx.state["active_shells"] = shells
            logger.info("Exploitation yielded %d shell sessions", len(shells))

    def _inject_post_exploit_data(self) -> None:
        """After post_exploit phase, collect harvested creds and enum data."""
        for result in self.state.results:
            if not result.ok:
                continue
            if result.data.get("credentials"):
                creds = self.ctx.state.setdefault("credentials", [])
                creds.extend(result.data["credentials"])
            if result.data.get("users"):
                users = self.ctx.state.setdefault("discovered_users", [])
                users.extend(result.data["users"])
            if result.data.get("network_info"):
                self.ctx.state.setdefault("network_info", {}).update(
                    result.data["network_info"]
                )

    def _inject_privesc_data(self) -> None:
        """After privesc phase, collect elevated shells."""
        elevated: list[dict] = []
        for result in self.state.results:
            if result.ok and result.data.get("elevated_shell"):
                elevated.append(result.data["elevated_shell"])
        if elevated:
            self.ctx.state["elevated_shells"] = elevated
            logger.info("PrivEsc yielded %d elevated shells", len(elevated))

    def _get_cache_ttl(self, phase_name: str) -> float:
        """Get cache TTL for a phase (user override or default)."""
        if phase_name in self.cache_ttl:
            return self.cache_ttl[phase_name]
        from basilisk.storage.cache import DEFAULT_TTL
        return DEFAULT_TTL.get(phase_name, 12.0)

    async def _check_cache(
        self,
        plugin_name: str,
        targets: list[Target],
        ttl_hours: float,
    ) -> tuple[list[Target], list[PluginResult]]:
        """Check cache for each target. Returns (uncached_targets, cached_results)."""
        if not self.cache:
            return targets, []

        uncached: list[Target] = []
        hits: list[PluginResult] = []
        for t in targets:
            try:
                cached = await self.cache.get_cached(plugin_name, t.host, ttl_hours)
            except Exception:
                logger.debug("Cache read error for %s:%s", plugin_name, t.host, exc_info=True)
                cached = None
            if cached:
                hits.append(cached)
                logger.info(
                    "Cache hit: %s:%s (%d findings)",
                    plugin_name, t.host, len(cached.findings),
                )
            else:
                uncached.append(t)
        return uncached, hits

    async def _cache_put(self, result: PluginResult) -> None:
        """Write a result to cache (best-effort)."""
        if not self.cache:
            return
        try:
            run_id = self.ctx.state.get("run_id")
            await self.cache.put(result.target, result, run_id=run_id)
        except Exception:
            logger.debug("Cache write error for %s:%s", result.plugin, result.target, exc_info=True)

    async def _persist_one(self, result: PluginResult) -> None:
        """Save a single plugin result to DB incrementally."""
        repo = self.ctx.db
        project_id = self.ctx.state.get("project_id")
        run_id = self.ctx.state.get("run_id")
        if not repo or not run_id:
            return

        try:
            domain_id = await repo.insert_domain(
                result.target, project_id=project_id
            )
            await repo.save_plugin_result(run_id, domain_id, result)
            if result.findings:
                tuples = [
                    (domain_id, result.plugin, f) for f in result.findings
                ]
                await repo.bulk_insert_findings(run_id, tuples)
        except Exception:
            logger.exception("Failed to persist result for %s", result.target)
