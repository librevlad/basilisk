"""Pipeline — orchestration of plugin execution in phases."""

from __future__ import annotations

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
                    phase.completed += phase.total
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

        self.state.status = "completed"
        self.on_progress(self.state)
        return self.state

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
