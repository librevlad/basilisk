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
    pass

logger = logging.getLogger(__name__)


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
    ):
        self.registry = registry
        self.executor = executor
        self.ctx = ctx
        self.on_progress = on_progress
        self.state = PipelineState()
        self.completed_pairs = completed_pairs or set()

    async def run(
        self,
        scope: TargetScope,
        plugin_names: list[str] | None = None,
        phases: list[str] | None = None,
    ) -> PipelineState:
        """Run the full audit pipeline."""
        active_phases = phases or ["recon", "scanning", "analysis", "pentesting"]
        self.state.init_phases(active_phases)
        self.state.status = "running"
        self.on_progress(self.state)

        # Run auth phase if auth manager is configured
        if self.ctx.auth:
            await self._run_auth_phase(scope)

        # Resolve execution order
        ordered = self.registry.resolve_order(plugin_names)

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
            phase.total = len(scope) * len(plugins)
            self.on_progress(self.state)

            for plugin_cls in plugins:
                # Skip plugins with unmet capability requirements
                if self._should_skip_plugin(plugin_cls):
                    phase.completed += len(scope)
                    self.on_progress(self.state)
                    continue

                plugin = plugin_cls()
                await plugin.setup(self.ctx)

                targets = list(scope)

                # Skip already completed targets (resume support)
                if self.completed_pairs:
                    targets = [
                        t for t in targets
                        if (plugin.meta.name, t.host) not in self.completed_pairs
                    ]

                if not targets:
                    phase.completed += len(list(scope))
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

                    # Recon plugins can expand scope
                    if phase_name == "recon" and result.ok:
                        new_subs = result.data.get("subdomains", [])
                        for sub in new_subs:
                            scope.add(
                                Target.subdomain(sub, parent=result.target)
                            )

                phase.completed += len(results)
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
                        except Exception:
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
        if crawled_urls:
            self.ctx.state["crawled_urls"] = crawled_urls
        if discovered_forms:
            self.ctx.state["discovered_forms"] = discovered_forms

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
                else:
                    logger.warning("Auth failed for %s", target.host)
            except Exception:
                logger.debug("Auth error for %s", target.host)

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
