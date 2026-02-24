"""Scenario registry — discovers native scenarios and wraps legacy plugins."""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil

from basilisk.bridge.legacy_scenario import LegacyPluginScenario
from basilisk.core.plugin import BasePlugin
from basilisk.domain.scenario import Scenario, ScenarioMeta

logger = logging.getLogger(__name__)


class ScenarioRegistry:
    """Discovers and manages all scenarios (native + legacy-wrapped)."""

    def __init__(self) -> None:
        self._scenarios: dict[str, Scenario] = {}

    def register(self, scenario: Scenario) -> None:
        """Register a scenario. Native scenarios override legacy wrappers."""
        self._scenarios[scenario.meta.name] = scenario

    def get(self, name: str) -> Scenario | None:
        return self._scenarios.get(name)

    def list_all(self) -> list[ScenarioMeta]:
        return [s.meta for s in self._scenarios.values()]

    def all_scenarios(self) -> list[Scenario]:
        return list(self._scenarios.values())

    def by_category(self, category: str) -> list[Scenario]:
        return [s for s in self._scenarios.values() if s.meta.category == category]

    @property
    def names(self) -> list[str]:
        return list(self._scenarios.keys())

    def discover(self) -> int:
        """Discover native scenarios and legacy plugins, wrap and register all.

        Native scenarios take priority over legacy wrappers with the same name.
        Returns total count registered.
        """
        # 1. Discover native scenarios from basilisk/scenarios/
        native_count = self._discover_native("basilisk.scenarios")

        # 2. Discover legacy plugins and wrap with LegacyPluginScenario
        legacy_count = self._discover_legacy("basilisk.plugins")

        logger.info(
            "ScenarioRegistry: %d native + %d legacy = %d total",
            native_count, legacy_count, len(self._scenarios),
        )
        return len(self._scenarios)

    def _discover_native(self, package_name: str) -> int:
        """Scan for native Scenario subclasses."""
        count = 0
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return 0

        for _importer, modname, ispkg in pkgutil.walk_packages(
            package.__path__, prefix=package.__name__ + ".",
        ):
            if ispkg:
                continue
            try:
                module = importlib.import_module(modname)
            except ImportError:
                continue

            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, Scenario)
                    and obj is not Scenario
                    and not issubclass(obj, LegacyPluginScenario)
                    and hasattr(obj, "meta")
                ):
                    self.register(obj())
                    count += 1

        return count

    def _discover_legacy(self, package_name: str) -> int:
        """Scan for v3 BasePlugin subclasses and wrap them."""
        count = 0
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return 0

        for _importer, modname, ispkg in pkgutil.walk_packages(
            package.__path__, prefix=package.__name__ + ".",
        ):
            if ispkg:
                continue
            try:
                module = importlib.import_module(modname)
            except ImportError:
                continue

            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and hasattr(obj, "meta")
                    and obj.meta.name not in self._scenarios
                ):
                    scenario = LegacyPluginScenario.wrap(obj)
                    self.register(scenario)
                    count += 1

        return count

    def resolve_order(self) -> list[Scenario]:
        """Topological sort on depends_on."""
        # Build adjacency for Kahn's algorithm
        in_degree: dict[str, int] = {s.meta.name: 0 for s in self._scenarios.values()}
        graph: dict[str, list[str]] = {s.meta.name: [] for s in self._scenarios.values()}

        for s in self._scenarios.values():
            for dep in s.meta.depends_on:
                if dep in graph:
                    graph[dep].append(s.meta.name)
                    in_degree[s.meta.name] += 1

        queue = [name for name, deg in in_degree.items() if deg == 0]
        result: list[str] = []

        while queue:
            queue.sort()  # deterministic
            node = queue.pop(0)
            result.append(node)
            for neighbor in graph[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # Append any remaining (cycle or missing deps)
        for name in self._scenarios:
            if name not in result:
                result.append(name)

        return [self._scenarios[name] for name in result]
