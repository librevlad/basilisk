"""Basilisk — autonomous security intelligence framework."""

from __future__ import annotations

__version__ = "4.0.0"

# v4 domain types (importable from top-level)
from typing import TYPE_CHECKING, Any

from basilisk.domain.finding import Finding as V4Finding  # noqa: F401
from basilisk.domain.finding import Proof, Severity  # noqa: F401
from basilisk.domain.scenario import Scenario, ScenarioMeta, ScenarioResult  # noqa: F401
from basilisk.domain.surface import Surface  # noqa: F401
from basilisk.domain.target import BaseTarget, LiveTarget, TrainingTarget  # noqa: F401

if TYPE_CHECKING:
    from collections.abc import Callable

    from basilisk.engine.autonomous.runner import RunResult


class Basilisk:
    """One-line security audits. Power under the hood.

    Usage::

        result = await Basilisk("example.com").run()
        result = await Basilisk("example.com", max_steps=50).run()
        result = await Basilisk("10.10.10.1", "10.10.10.2").run()
    """

    def __init__(self, *targets: str, max_steps: int = 100, config: Any = None):
        self._targets = list(targets)
        self._max_steps = max_steps
        self._config = config
        self._campaign_enabled = False
        self._plugin_filter: list[str] = []
        self._exclude_patterns: list[str] = []
        self._on_finding: Callable | None = None
        self._on_step: Callable | None = None

    def campaign(self) -> Basilisk:
        """Enable persistent campaign memory."""
        self._campaign_enabled = True
        return self

    def plugins(self, *names: str) -> Basilisk:
        """Whitelist specific plugins."""
        self._plugin_filter.extend(names)
        return self

    def exclude(self, *patterns: str) -> Basilisk:
        """Exclude plugins by name or prefix."""
        self._exclude_patterns.extend(patterns)
        return self

    def on_finding(self, callback: Callable) -> Basilisk:
        """Register a callback for each finding."""
        self._on_finding = callback
        return self

    def on_step(self, callback: Callable) -> Basilisk:
        """Register a callback for each autonomous step."""
        self._on_step = callback
        return self

    async def run(self) -> RunResult:
        """Execute the autonomous audit."""
        from basilisk.actor.composite import CompositeActor
        from basilisk.engine.autonomous.runner import AutonomousRunner
        from basilisk.engine.target_loader import TargetLoader

        settings = self._resolve_config()
        targets = TargetLoader.load(self._targets, settings)
        actor = CompositeActor.build(settings)
        runner = AutonomousRunner(
            settings=settings,
            actor=actor,
            max_steps=self._max_steps,
            campaign_enabled=self._campaign_enabled,
            plugin_filter=self._plugin_filter or None,
            exclude_patterns=self._exclude_patterns or None,
            on_finding=self._on_finding,
            on_step=self._on_step,
        )
        return await runner.run(targets, settings)

    def _resolve_config(self) -> Any:
        """Resolve config from path, object, or default."""
        from basilisk.config import Settings

        if self._config is None:
            return Settings.load()
        if isinstance(self._config, str):
            return Settings.load(self._config)
        return self._config
