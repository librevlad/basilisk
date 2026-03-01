"""DisplayState — snapshot-driven state for Rich Live rendering."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from basilisk.knowledge.snapshot import KnowledgeSnapshot


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
    """Mutable display state driven by KnowledgeStore snapshots.

    Knowledge data (domains, ports, findings, etc.) comes from KnowledgeSnapshot.
    Activity data (active plugins, recent plugins) comes from events directly.
    Render is gated on snapshot fingerprint change.
    """

    # Step progress
    step: int = 0
    max_steps: int = 100
    started_at: float = field(default_factory=time.monotonic)

    # Entity counts by type (from snapshot or event-driven)
    entity_counts: dict[str, int] = field(default_factory=lambda: {
        "host": 0, "service": 0, "endpoint": 0, "technology": 0,
        "credential": 0, "finding": 0, "vulnerability": 0,
        "container": 0, "image": 0,
    })
    total_entities: int = 0
    total_relations: int = 0

    # Gap count
    gap_count: int = 0

    # Plugin activity (event-driven, not from snapshot)
    active_plugins: list[PluginActivity] = field(default_factory=list)
    recent_plugins: list[PluginActivity] = field(default_factory=list)

    # Findings (from snapshot)
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

    # Snapshot tracking (for diff-based rendering)
    _snapshot: KnowledgeSnapshot | None = field(default=None, repr=False)
    _prev_fingerprint: str = field(default="", repr=False)

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

    @property
    def snapshot(self) -> KnowledgeSnapshot | None:
        """Current knowledge snapshot."""
        return self._snapshot

    def update_from_snapshot(self, snapshot: KnowledgeSnapshot) -> bool:
        """Update state from knowledge snapshot. Returns True if changed."""
        if snapshot.fingerprint == self._prev_fingerprint:
            return False
        self._snapshot = snapshot
        self._prev_fingerprint = snapshot.fingerprint

        # Update totals from snapshot
        self.step = snapshot.step if snapshot.step > 0 else self.step
        self.total_entities = snapshot.entity_count or self.total_entities
        self.total_relations = snapshot.relation_count or self.total_relations

        # Rebuild findings from snapshot
        self.findings = [
            FindingEntry(
                title=f.get("title", ""),
                severity=f.get("severity", "info"),
                host=f.get("host", ""),
            )
            for f in snapshot.findings_verified
        ]

        # Update entity counts from snapshot sets
        self.entity_counts["host"] = len(snapshot.domains)
        self.entity_counts["service"] = len(snapshot.ports)
        self.entity_counts["endpoint"] = len(snapshot.endpoints)
        self.entity_counts["technology"] = len(snapshot.technologies)
        self.entity_counts["finding"] = len(snapshot.findings_verified)

        return True
