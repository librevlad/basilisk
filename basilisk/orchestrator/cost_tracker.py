"""Capability cost learning — runtime statistics per plugin."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PluginStats:
    """Accumulated statistics for a single plugin."""

    runs: int = 0
    successes: int = 0
    total_new_entities: int = 0
    total_findings: int = 0
    total_runtime: float = 0.0

    @property
    def success_rate(self) -> float:
        """Fraction of runs that produced new entities or findings."""
        if self.runs == 0:
            return 0.0
        return self.successes / self.runs

    @property
    def avg_new_entities(self) -> float:
        """Average new entities per run."""
        if self.runs == 0:
            return 0.0
        return self.total_new_entities / self.runs

    @property
    def avg_runtime(self) -> float:
        """Average runtime in seconds."""
        if self.runs == 0:
            return 0.0
        return self.total_runtime / self.runs

    @property
    def avg_findings(self) -> float:
        """Average findings per run."""
        if self.runs == 0:
            return 0.0
        return self.total_findings / self.runs


class CostTracker:
    """Tracks plugin execution statistics and provides adjusted cost scores.

    Instead of using static cost_score from capability mapping, this tracker
    learns from actual execution results: plugins that consistently produce
    no results get a higher effective cost, while highly productive plugins
    get a slight discount.
    """

    def __init__(self) -> None:
        self._stats: dict[str, PluginStats] = {}

    def record(
        self,
        plugin_name: str,
        new_entities: int,
        findings: int,
        runtime: float,
    ) -> None:
        """Record the result of a plugin execution."""
        stats = self._stats.setdefault(plugin_name, PluginStats())
        stats.runs += 1
        stats.total_new_entities += new_entities
        stats.total_findings += findings
        stats.total_runtime += runtime
        if new_entities > 0 or findings > 0:
            stats.successes += 1

    def adjusted_cost(self, plugin_name: str, base_cost: float) -> float:
        """Return an adjusted cost score based on observed performance.

        - Plugins with no history: return base_cost unchanged
        - Plugins with 0% success rate: cost * 2.0 (penalize)
        - Plugins with high success rate: cost * 0.7 (discount)
        - Linear interpolation between
        """
        stats = self._stats.get(plugin_name)
        if stats is None or stats.runs < 2:
            return base_cost

        rate = stats.success_rate
        # Linear interpolation: 0% success → 2.0x, 100% success → 0.7x
        multiplier = 2.0 - 1.3 * rate
        return base_cost * max(multiplier, 0.5)

    def get_stats(self, plugin_name: str) -> PluginStats | None:
        """Get stats for a plugin, or None if never tracked."""
        return self._stats.get(plugin_name)

    @property
    def all_stats(self) -> dict[str, PluginStats]:
        """Return all tracked plugin stats."""
        return dict(self._stats)
