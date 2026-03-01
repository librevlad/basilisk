"""DisplayState — accumulates event data for Rich Live rendering."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class PluginActivity:
    """Tracks a single plugin execution."""

    name: str
    target: str
    started_at: float
    finished: bool = False
    duration: float = 0.0
    findings_count: int = 0


@dataclass
class FindingEntry:
    """A finding for display purposes."""

    title: str
    severity: str
    host: str


@dataclass
class DisplayState:
    """Mutable state accumulating event data for the live display.

    Mutated by event handlers (sync), read by Rich Live on refresh.
    """

    # Step progress
    step: int = 0
    max_steps: int = 100
    started_at: float = field(default_factory=time.monotonic)

    # Entity counts by type
    entity_counts: dict[str, int] = field(default_factory=lambda: {
        "host": 0, "service": 0, "endpoint": 0, "technology": 0,
        "credential": 0, "finding": 0, "vulnerability": 0,
        "container": 0, "image": 0,
    })
    total_entities: int = 0
    total_relations: int = 0

    # Gap count
    gap_count: int = 0

    # Plugin activity
    active_plugins: list[PluginActivity] = field(default_factory=list)
    recent_plugins: list[PluginActivity] = field(default_factory=list)

    # Findings
    findings: list[FindingEntry] = field(default_factory=list)

    # Hypothesis stats
    hypotheses_active: int = 0
    hypotheses_confirmed: int = 0
    hypotheses_rejected: int = 0

    # Belief changes
    beliefs_strengthened: int = 0
    beliefs_weakened: int = 0

    # Termination
    finished: bool = False
    termination_reason: str = ""

    @property
    def elapsed(self) -> float:
        """Seconds since display started."""
        return time.monotonic() - self.started_at

    @property
    def step_progress(self) -> float:
        """Progress ratio 0.0 to 1.0."""
        if self.max_steps <= 0:
            return 0.0
        return min(self.step / self.max_steps, 1.0)

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.severity.upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)
