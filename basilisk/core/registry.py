"""Plugin registry — auto-discovery, registration, topological ordering."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import TYPE_CHECKING

from basilisk.core.plugin import BasePlugin, PluginCategory

if TYPE_CHECKING:
    pass


class PluginRegistry:
    """Discovers, registers, and resolves execution order for plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, type[BasePlugin]] = {}

    def register(self, plugin_cls: type[BasePlugin]) -> None:
        self._plugins[plugin_cls.meta.name] = plugin_cls

    def get(self, name: str) -> type[BasePlugin] | None:
        return self._plugins.get(name)

    def all(self) -> list[type[BasePlugin]]:
        return list(self._plugins.values())

    def by_category(self, category: PluginCategory) -> list[type[BasePlugin]]:
        return [p for p in self._plugins.values() if p.meta.category == category]

    def by_provides(self, provides: str) -> list[type[BasePlugin]]:
        return [p for p in self._plugins.values() if p.meta.provides == provides]

    @property
    def names(self) -> list[str]:
        return list(self._plugins.keys())

    def discover(self, package_name: str = "basilisk.plugins") -> int:
        """Auto-discover all plugins under a package. Returns count found."""
        count = 0
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return 0

        for _importer, modname, ispkg in pkgutil.walk_packages(
            package.__path__, prefix=package.__name__ + "."
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
                ):
                    self.register(obj)
                    count += 1
        return count

    def resolve_order(
        self, names: list[str] | None = None
    ) -> list[type[BasePlugin]]:
        """Topological sort of plugins by depends_on.

        If names is None, uses all registered plugins.
        """
        if names:
            plugins = {n: self._plugins[n] for n in names if n in self._plugins}
        else:
            plugins = dict(self._plugins)

        # Build adjacency
        graph: dict[str, list[str]] = {name: [] for name in plugins}
        in_degree: dict[str, int] = {name: 0 for name in plugins}

        for name, cls in plugins.items():
            for dep in cls.meta.depends_on:
                if dep in plugins:
                    graph[dep].append(name)
                    in_degree[name] += 1

        # Kahn's algorithm
        queue = [n for n, d in in_degree.items() if d == 0]
        # Stable sort: within same level, order by category priority
        category_order = {
            PluginCategory.RECON: 0,
            PluginCategory.SCANNING: 1,
            PluginCategory.ANALYSIS: 2,
            PluginCategory.PENTESTING: 3,
        }
        queue.sort(key=lambda n: category_order.get(plugins[n].meta.category, 99))

        result: list[type[BasePlugin]] = []
        while queue:
            node = queue.pop(0)
            result.append(plugins[node])
            for neighbor in graph[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
            queue.sort(
                key=lambda n: category_order.get(plugins[n].meta.category, 99)
            )

        if len(result) != len(plugins):
            resolved = {p.meta.name for p in result}
            missing = set(plugins.keys()) - resolved
            msg = f"Circular dependency detected among plugins: {missing}"
            raise ValueError(msg)

        return result
